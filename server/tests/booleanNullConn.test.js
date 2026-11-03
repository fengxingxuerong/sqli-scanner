// ============================================================================
// tests/booleanNullConn.test.js —— [D201] --null-connection 快判相位 + 传输形态三旗标
//
// 判据（零网络，mock httpClient）：
//   · 元数据可决：HEAD-only 出结论（request 全程不被调用），证据标注 null-connection；
//   · 元数据不可决（动态页/基线抖动）：落回 body 相位——「不可决 ≠ 不可注入」；
//   · --http2/--http1/--null-connection 进 config；--http1 与 --http2 互斥硬拒；
//   · buildEgressOpts 透传 http2（egress 受治键，注入链路生效的前提）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { buildEgressOpts } from '../src/engine/egressOpts.js';

const { parseArgs } = await import('../bin/cli/args.js');
const { buildConfig } = await import('../bin/cli/config.js');

const URL0 = 'http://127.0.0.1:9/?q=';

function makeCtx({ headByMarker, requestImpl, config }) {
  const headCalls = [];
  const reqCalls = [];
  const httpClient = {
    // buildInjectionRequest 把 payload 拼进 URL query（url 位置注入点）——按标记区分真/假/基线
    async headRequest(url, opts) {
      headCalls.push({ url, opts });
      const res = headByMarker(url);
      return { status: res.status, headers: res.headers ?? {}, data: '' };
    },
    async request(opts) {
      reqCalls.push(opts);
      if (!requestImpl) throw new Error('null-connection 模式不应发全量请求');
      return requestImpl(opts);
    },
  };
  const ctx = {
    httpClient,
    // 形态对齐 boolRegistry.test.js（buildInjectionRequest 消费 target.baseUrl）
    target: { method: 'GET', baseUrl: URL0, headerParams: {}, cookieParams: {}, config: {} },
    point: { id: 'p1', originalValue: '1', param: 'q', location: 'url' },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, blindRobust: { enabled: false }, ...config },
  };
  return { ctx, headCalls, reqCalls };
}

// URL 编码标记：真条件含 1%3D1（1=1），假条件含 1%3D2（1=2），基线两者皆无
test('null-connection：元数据可决 → HEAD-only 出结论（不发全量请求）', async () => {
  const { ctx, headCalls, reqCalls } = makeCtx({
    config: { nullConnection: true },
    headByMarker: (url) => {
      if (/1%3D1/.test(url)) return { status: 500, headers: { 'content-length': '50' } };
      return { status: 200, headers: { 'content-length': '100' } };
    },
  });
  const d = new BooleanBlindDetector();
  const result = await d.detect(ctx);
  assert.equal(result.vulnerable, true, `应命中，实际 ${JSON.stringify(result)}`);
  assert.match(result.evidence, /null-connection/);
  assert.equal(reqCalls.length, 0, '元数据判定全程不应发 GET');
  assert.ok(headCalls.length >= 5, `基线2 + 真假对×N：实际 ${headCalls.length}`);
});

test('null-connection：元数据不可决（全一致）→ 落回 body 相位（request 被调用）', async () => {
  const { ctx, headCalls, reqCalls } = makeCtx({
    config: { nullConnection: true },
    headByMarker: () => ({ status: 200, headers: { 'content-length': '100' } }),
    requestImpl: () => ({ status: 200, headers: {}, data: 'stable page content' }),
  });
  const d = new BooleanBlindDetector();
  const result = await d.detect(ctx);
  assert.equal(result.vulnerable, false, '元数据全一致不该判命中（body 相位对稳定页同样无差异）');
  assert.ok(headCalls.length >= 3, '快判相位应已跑（基线+真假对）');
  assert.ok(reqCalls.length > 0, '元数据不可决必须落回 body 相位（不能把「无差异」读成「无注入」）');
});

test('null-connection：基线自身抖动 → 立即弃用元数据判据（落回 body）', async () => {
  let n = 0;
  const { ctx, reqCalls } = makeCtx({
    config: { nullConnection: true },
    headByMarker: () => ({ status: n++ % 2 === 0 ? 200 : 503, headers: {} }),
    requestImpl: () => ({ status: 200, headers: {}, data: 'stable page content' }),
  });
  const d = new BooleanBlindDetector();
  await d.detect(ctx);
  assert.ok(reqCalls.length > 0, `基线 2 次 HEAD 不一致 ⇒ 元数据判据不可信，必须落回 body 相位（实际 GET ${reqCalls.length} 次）`);
});

test('args/config：--http2/--http1/--null-connection 进 config；--http1 与 --http2 互斥硬拒', () => {
  const c1 = buildConfig(parseArgs(['-u', URL0, '--http2']));
  assert.equal(c1.http2, true);
  const c2 = buildConfig(parseArgs(['-u', URL0, '--http1']));
  assert.equal(c2.http2, false, '--http1 显式压回 HTTP/1.1（可覆盖 --config 档案里的 http2:true）');
  const c3 = buildConfig(parseArgs(['-u', URL0, '--null-connection']));
  assert.equal(c3.nullConnection, true);
  assert.throws(
    () => buildConfig(parseArgs(['-u', URL0, '--http1', '--http2'])),
    /互斥/,
    '双给必须启动即拒（收参数不生效是红线）'
  );
});

test('egress：buildEgressOpts 透传 http2（受治键；注入链路生效的前提）', () => {
  assert.equal(buildEgressOpts({ http2: true }).http2, true);
  assert.equal(buildEgressOpts({}).http2, false, '未配置 = 明确 false（axios HTTP/1.1 默认路径零变化）');
});

test('args 解析：三旗标不落 unknownFlags', () => {
  const a = parseArgs(['-u', URL0, '--http2', '--null-connection']);
  assert.deepEqual(a.unknownFlags, []);
  assert.equal(a.http2, true);
  assert.equal(a.nullConnection, true);
});
