// [P0-SEC 2026-09-08] 授权范围（scope）硬约束测试（node:test）
// 渗透作战第一红线：打了没授权的资产是事故，不是 bug。覆盖：
//   1) 主机名 / 通配域 / 裸域 / CIDR / IPv6 前缀 / 带路径前缀 URL 的匹配语义；
//   2) 未配置 scope 时零行为变化（恒放行）；
//   3) 越界目标在 sanitizeStart 层被拒（含 safeUrl / 二阶触发页旁路）；
//   4) 扫描级 scope 登记与回收（HttpClient 逐跳重定向校验取用）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseScope,
  isHostInScope,
  assertInScope,
  filterInScope,
  registerScanScope,
  getScopeForScan,
  releaseScanScope,
} from '../src/core/scopeGuard.js';
import { sanitizeStart } from '../src/api/scanRoutes.js';
import { ErrorCode } from '../src/core/errors.js';

test('scope 未配置 → 恒放行（零行为变化）', () => {
  const s = parseScope(undefined);
  assert.equal(s.enabled, false);
  assert.equal(isHostInScope('anything.example.com', s), true);
  assert.doesNotThrow(() => assertInScope('http://anything.example.com/x', s));
});

test('域名条目默认涵盖子域；=前缀为严格裸域', () => {
  const wide = parseScope('example.com');
  assert.equal(isHostInScope('example.com', wide), true);
  assert.equal(isHostInScope('a.b.example.com', wide), true);
  assert.equal(isHostInScope('notexample.com', wide), false, '后缀匹配必须带点边界');
  assert.equal(isHostInScope('example.com.evil.io', wide), false, '伪后缀必须拒绝');

  const exact = parseScope('=example.com');
  assert.equal(isHostInScope('example.com', exact), true);
  assert.equal(isHostInScope('www.example.com', exact), false);
});

test('CIDR（IPv4/IPv6）与 IP 字面量', () => {
  const s = parseScope(['10.0.0.0/8', '192.168.1.50', '2001:db8::/32']);
  assert.equal(isHostInScope('10.1.2.3', s), true);
  assert.equal(isHostInScope('11.1.2.3', s), false);
  assert.equal(isHostInScope('192.168.1.50', s), true);
  assert.equal(isHostInScope('192.168.1.51', s), false);
  assert.equal(isHostInScope('2001:db8:0:1::5', s), true);
  assert.equal(isHostInScope('2001:db9::1', s), false);
});

test('带路径前缀的条目：host 命中但路径不命中 → 拒绝', () => {
  const s = parseScope('https://app.example.com/portal');
  assert.equal(isHostInScope('app.example.com', s, '/portal/order'), true);
  assert.equal(isHostInScope('app.example.com', s, '/admin'), false);
  assert.equal(isHostInScope('other.example.com', s, '/portal'), false);
});

test('filterInScope 只保留圈内项（二阶触发页剔除语义）', () => {
  const s = parseScope('*.corp.example.com');
  const r = filterInScope(
    ['http://a.corp.example.com/store', 'http://pay.thirdparty.com/notify', 'http://intranet/x'],
    s
  );
  assert.deepEqual(r.allowed, ['http://a.corp.example.com/store']);
  assert.equal(r.rejected.length, 2);
});

test('sanitizeStart：越界目标直接拒绝启动（SCOPE_VIOLATION）', () => {
  assert.throws(
    () =>
      sanitizeStart({
        target: { url: 'http://10.0.0.5/id?1' },
        config: { scope: ['=example.com'] },
      }),
    (e) => e.code === ErrorCode.SCOPE_VIOLATION && /不在授权范围/.test(e.message)
  );
});

test('sanitizeStart：圈内目标放行且 scope 进 config（供逐跳校验复用）', () => {
  const out = sanitizeStart({
    target: { url: 'http://shop.example.com/item?id=1' },
    config: { scope: ['example.com'] },
  });
  assert.deepEqual(out.config.scope, ['example.com']);
});

test('sanitizeStart：safeUrl 旁路也被约束（越界则丢弃该配置而非放行）', () => {
  const out = sanitizeStart({
    target: { url: 'http://shop.example.com/item?id=1' },
    config: { scope: ['example.com'], safeUrl: 'http://health.internal.io/ping', safeFreq: 50 },
  });
  assert.equal(out.config.safeUrl, undefined, '越界 safeUrl 必须被丢弃');
  const ok = sanitizeStart({
    target: { url: 'http://shop.example.com/item?id=1' },
    config: { scope: ['example.com'], safeUrl: 'http://ping.example.com/health', safeFreq: 50 },
  });
  assert.equal(ok.config.safeUrl, 'http://ping.example.com/health');
});

test('sanitizeStart：无 scope 时行为与历史一致（任意目标可启动）', () => {
  const out = sanitizeStart({ target: { url: 'http://127.0.0.1:8123/?id=1' } });
  assert.equal(out.config.scope, undefined);
});

test('扫描级 scope 登记/回收（HttpClient 逐跳校验依赖）', () => {
  const scope = parseScope('example.com');
  registerScanScope('scanA', scope);
  assert.equal(getScopeForScan('scanA'), scope);
  assert.equal(getScopeForScan('unknown'), null);
  releaseScanScope('scanA');
  assert.equal(getScopeForScan('scanA'), null, '回收后不得再命中（防同 id 复用旧范围）');
});

test('登记未启用的 scope 等价于不登记（避免误拦）', () => {
  registerScanScope('scanB', parseScope(''));
  assert.equal(getScopeForScan('scanB'), null);
});
