// scanRoutes.sanitizeStart 新字段收敛/校验（对标 sqlmap 高级检测选项接入）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeStart } from '../src/api/scanRoutes.js';

const base = (cfg) => ({ url: 'http://127.0.0.1/?id=1', config: cfg || {} });

test('默认配置收敛到后端默认值', () => {
  const r = sanitizeStart(base({}));
  assert.equal(r.config.level, 1);
  assert.equal(r.config.risk, 1);
  assert.equal(r.config.timeSec, 2);
  assert.equal(r.config.requestDelayMs, 0);
  assert.equal(r.config.hpp, false);
  assert.equal(r.config.keepAlive, true);
});

test('level 越界 clamp 1-5', () => {
  assert.equal(sanitizeStart(base({ level: 99 })).config.level, 5);
  assert.equal(sanitizeStart(base({ level: -3 })).config.level, 1);
  assert.equal(sanitizeStart(base({ level: 3 })).config.level, 3);
});

test('timeSec 越界 clamp 1-60', () => {
  assert.equal(sanitizeStart(base({ timeSec: 0 })).config.timeSec, 1);
  assert.equal(sanitizeStart(base({ timeSec: 999 })).config.timeSec, 60);
});

test('requestDelayMs 越界 clamp 0-60000', () => {
  assert.equal(sanitizeStart(base({ requestDelayMs: -5 })).config.requestDelayMs, 0);
  assert.equal(sanitizeStart(base({ requestDelayMs: 999999 })).config.requestDelayMs, 60000);
});

test('hpp 布尔化', () => {
  assert.equal(sanitizeStart(base({ hpp: 'yes' })).config.hpp, true);
  assert.equal(sanitizeStart(base({ hpp: 0 })).config.hpp, false);
  assert.equal(sanitizeStart(base({})).config.hpp, false);
});

test('keepAlive 默认 true，仅显式 false 关闭', () => {
  assert.equal(sanitizeStart(base({})).config.keepAlive, true);
  assert.equal(sanitizeStart(base({ keepAlive: true })).config.keepAlive, true);
  assert.equal(sanitizeStart(base({ keepAlive: false })).config.keepAlive, false);
});

test('safeProbe 逗号分隔多 URL 归一化为 urls 数组', () => {
  const r = sanitizeStart(
    base({ safeProbe: { url: 'http://a/, http://b/ ,http://c/', freq: 3 } })
  );
  assert.deepEqual(r.config.safeProbe.urls, ['http://a/', 'http://b/', 'http://c/']);
  assert.equal(r.config.safeProbe.freq, 3);
  assert.equal(r.config.safeProbe.randomize, true);
});

test('safeProbe randomize=false 顺序轮询', () => {
  const r = sanitizeStart(
    base({ safeProbe: { url: 'http://a/', freq: 2, randomize: false } })
  );
  assert.equal(r.config.safeProbe.randomize, false);
});

test('detectMatch 透传有效锚点', () => {
  const r = sanitizeStart(base({ detectMatch: { string: 'ok', code: 200 } }));
  assert.equal(r.config.detectMatch.string, 'ok');
  assert.equal(r.config.detectMatch.code, 200);
});

test('detectMatch 非法正则抛 AppError', () => {
  assert.throws(() => sanitizeStart(base({ detectMatch: { regexp: '(' } })));
});

test('secondOrder.manualStorePoints 纳管：字符串数组去空白过滤', () => {
  const r = sanitizeStart(
    base({ risk: 2, secondOrder: { enabled: true, triggerUrls: ['http://t/u1'], manualStorePoints: [' username ', 'email', '', ' bio '] } }),
  );
  assert.deepEqual(r.config.secondOrder.manualStorePoints, ['username', 'email', 'bio']);
});

test('secondOrder 未传 manualStorePoints → 默认为空数组', () => {
  const r = sanitizeStart(base({ risk: 2, secondOrder: { enabled: true, triggerUrls: ['http://t/u1'] } }));
  assert.deepEqual(r.config.secondOrder.manualStorePoints, []);
});

test('secondOrder.manualStorePoints 非数组 → 安全降级为空数组', () => {
  const r = sanitizeStart(base({ risk: 2, secondOrder: { enabled: true, manualStorePoints: 'username' } }));
  assert.deepEqual(r.config.secondOrder.manualStorePoints, []);
});

// 前后端二阶配置字段对称守卫：防止后端 sanitize 新增/遗漏二阶字段导致前端传参静默丢失。
// 前端契约见 src/shared/types.ts SecondOrderConfig；新增字段必须同步显式纳管到 sanitizeStart，
// 否则前端配置项无法传到引擎而被静默吞掉（复现 round 4/5 的裁剪未声明字段坑）。
const FRONTEND_SECOND_ORDER_FIELDS = ['enabled', 'triggerUrls', 'autoDiscover', 'refreshCsrf', 'negativeControl', 'oobTrigger', 'manualStorePoints'];

test('前后端二阶字段对称守卫：sanitize 后 config.secondOrder 含前端全部字段', () => {
  const r = sanitizeStart(
    base({
      risk: 2,
      secondOrder: {
        enabled: true,
        triggerUrls: ['http://t/u1'],
        autoDiscover: true,
        refreshCsrf: false,
        negativeControl: false,
        oobTrigger: true,
        manualStorePoints: ['email', 'bio'],
      },
    })
  );
  assert.ok(r.config.secondOrder, 'sanitize 应保留 secondOrder 块');
  for (const f of FRONTEND_SECOND_ORDER_FIELDS) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(r.config.secondOrder, f),
      `sanitize 后 secondOrder 缺字段「${f}」（前端已声明，后端 sanitize 未纳管 → 静默丢失）`
    );
  }
  // 不应出现前端契约之外的残留字段（防后端自行扩字段而不更新前端类型）
  const extra = Object.keys(r.config.secondOrder).filter((k) => !FRONTEND_SECOND_ORDER_FIELDS.includes(k));
  assert.deepEqual(extra, [], `sanitize 后 secondOrder 含前端未声明字段：${extra.join(', ')}`);
  // 抽样验证字段值经 sanitize 未被破坏
  assert.equal(r.config.secondOrder.enabled, true);
  assert.deepEqual(r.config.secondOrder.triggerUrls, ['http://t/u1']);
  assert.equal(r.config.secondOrder.autoDiscover, true);
  assert.equal(r.config.secondOrder.refreshCsrf, false);
  assert.equal(r.config.secondOrder.negativeControl, false);
  assert.equal(r.config.secondOrder.oobTrigger, true);
  assert.deepEqual(r.config.secondOrder.manualStorePoints, ['email', 'bio']);
});
