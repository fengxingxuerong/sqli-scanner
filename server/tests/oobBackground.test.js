// OOB 背景哨兵（D108）单元测试：
// ① waitForAnyToken 共享等待器（即时命中/首个胜出/超时/清理/大小写归一）；
// ② runOobSentinel：门控、预算、面选择、命中归因、合成头点入 report.points；
// ③ _runOobBackground 包装层（ScanManager.prototype 挂载）与 startOobIfNeeded 门控。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { waitForAnyTokenIn } from '../src/core/oobWaiters.js';
import { oobReceiver } from '../src/core/oobReceiver.js';
import { oobTunnel } from '../src/core/oobTunnel.js';
import { runOobSentinel } from '../src/engine/scan/oobSentinel.js';
import { _runOobBackground } from '../src/engine/scan/supplementalRuns.js';
import { startOobIfNeeded } from '../src/engine/scan/detect.js';
import { ReportGenerator } from '../src/services/ReportGenerator.js';

const PORT = 19014;
const OOB_CFG = { enabled: true, callbackBase: `127.0.0.1:${PORT}`, httpPort: PORT, timeoutMs: 500 };

function bgCfg(extra = {}) {
  return {
    ...OOB_CFG,
    background: { enabled: true, maxRequests: 24, timeoutMs: 500, headers: [], ...extra },
  };
}

function makeTarget(config, extra = {}) {
  return {
    mode: 'http',
    method: 'GET',
    baseUrl: 'http://mock/item?id=1',
    headerParams: {},
    cookieParams: {},
    config,
    ...extra,
  };
}

function makePoint(over = {}) {
  return {
    id: over.id || 'p1',
    location: 'url',
    param: 'id',
    originalValue: '1',
    confirmed: false,
    technique: null,
    dbms: null,
    ...over,
  };
}

/** 目标模拟：从请求文本提取回调 URL 里的 token 并"回连"（真实环境由 DBMS 执行） */
function makeCallbackClient() {
  const state = { requests: 0 };
  const client = {
    async request(opts) {
      state.requests += 1;
      const text = JSON.stringify(opts);
      // 注入值进 URL query 后 '/' 会被编码（oob%2Ftoken），与 oobDetector.test.js 同口径
      const m = text.match(/oob(?:%2[fF]|\/)([A-Za-z0-9_-]{16,})/);
      if (m) oobReceiver.receive(m[1]);
      return { data: '', status: 200 };
    },
  };
  return { client, state };
}

function makeSilentClient() {
  const state = { requests: 0 };
  return {
    state,
    client: {
      async request() {
        state.requests += 1;
        return { data: '', status: 200 };
      },
    },
  };
}

function deps(client, extra = {}) {
  return {
    httpClient: client,
    guard: { shouldAbort: false },
    report: { summary: {} },
    scanId: 's1',
    eventBus: { emit() {} },
    reportGen: new ReportGenerator(),
    ...extra,
  };
}

// ── ① waitForAnyTokenIn ────────────────────────────────────────────────────

test('waitForAnyToken：已回连的 token 即时命中（零等待）', async () => {
  const received = new Map([['aaa', Date.now()]]);
  const hit = await waitForAnyTokenIn(received, new Map(), ['bbb', 'aaa'], 5000, (t) => t);
  assert.equal(hit, 'aaa');
});

test('waitForAnyToken：首个回连胜出并保留原样大小写，其余等待者被清理', async () => {
  const received = new Map();
  const waiters = new Map();
  const p = waitForAnyTokenIn(received, waiters, ['TokenA', 'TokenB'], 5000, (t) => t.toLowerCase());
  // 模拟 receive：归一化 key 入表并唤醒
  received.set('tokenb', Date.now());
  const ws = waiters.get('tokenb');
  assert.ok(ws && ws.size === 1, '归一化后的 key 必须注册了等待者');
  for (const w of ws) w.resolve(true);
  assert.equal(await p, 'TokenB', '返回值必须是调用方传入的原样 token，而不是小写 key');
  assert.equal(waiters.size, 0, '命中后本组全部等待者必须清理');
});

test('waitForAnyToken：超时返回 null 且不留悬挂 waiter', async () => {
  const received = new Map();
  const waiters = new Map();
  const hit = await waitForAnyTokenIn(received, waiters, ['x1', 'x2'], 60, (t) => t);
  assert.equal(hit, null);
  assert.equal(waiters.size, 0);
});

test('waitForAnyToken：空 token 列表直接返回 null（不注册定时器）', async () => {
  const hit = await waitForAnyTokenIn(new Map(), new Map(), [], 5000, (t) => t);
  assert.equal(hit, null);
});

// ── ② runOobSentinel ──────────────────────────────────────────────────────

test('background 未开启 → 零请求、零漏洞', async () => {
  await oobReceiver.start(OOB_CFG);
  const { client, state } = makeCallbackClient();
  const cfg = { ...OOB_CFG, background: { enabled: false } };
  const points = [makePoint()];
  const out = await runOobSentinel('s1', makeTarget(cfg), points, new Set(), null, cfg, ['union'], deps(client));
  assert.deepEqual(out, []);
  assert.equal(state.requests, 0);
  await oobReceiver.stop();
});

test('隧道未启动 → 直接返回 []（宁可不跑，也不假装测过）', async () => {
  await oobReceiver.stop();
  const { client, state } = makeCallbackClient();
  const cfg = bgCfg();
  const points = [makePoint()];
  const out = await runOobSentinel('s1', makeTarget(cfg), points, new Set(), null, cfg, ['union'], deps(client));
  assert.deepEqual(out, []);
  assert.equal(state.requests, 0);
});

test('命中归因：只有回连的面被标记，其余面不误报', async () => {
  await oobReceiver.start(OOB_CFG);
  const cfg = bgCfg({ timeoutMs: 300 });
  const target = makeTarget(cfg);
  const points = [makePoint({ id: 'p1', param: 'a' }), makePoint({ id: 'p2', param: 'b' })];
  // 只让第二个请求（第二个面）回连：模拟目标只在某个参数上执行了带外原语
  let n = 0;
  const client = {
    async request(opts) {
      n += 1;
      const text = JSON.stringify(opts);
      const m = text.match(/oob(?:%2[fF]|\/)([A-Za-z0-9_-]{16,})/);
      if (m && n >= 5) oobReceiver.receive(m[1]); // 第 5 个请求起（第二面的第一个 DBMS 候选）才回连
      return { data: '', status: 200 };
    },
  };
  const out = await runOobSentinel('s1', target, points, new Set(), null, cfg, ['union'], deps(client));
  assert.ok(out.length >= 1, '回连必须产出漏洞条目');
  assert.equal(points[0].confirmed, false, '未回连的面不得被标记');
  assert.equal(points[1].confirmed, true, '回连的面必须被标记');
  assert.ok(out.every((v) => v.oobBackground === true && v.technique === 'oob'));
  await oobReceiver.stop();
});

test('无回连 → 不产出漏洞（阴性不得写成命中）', async () => {
  await oobReceiver.start(OOB_CFG);
  const cfg = bgCfg({ timeoutMs: 80 });
  const { client } = makeSilentClient();
  const points = [makePoint()];
  const out = await runOobSentinel('s1', makeTarget(cfg), points, new Set(), null, cfg, ['union'], deps(client));
  assert.deepEqual(out, []);
  assert.equal(points[0].confirmed, false);
  await oobReceiver.stop();
});

test('请求预算：播撒请求数不超过 maxRequests', async () => {
  await oobReceiver.start(OOB_CFG);
  const cfg = bgCfg({ timeoutMs: 60, maxRequests: 2 });
  const { client, state } = makeSilentClient();
  const points = [makePoint({ id: 'p1' }), makePoint({ id: 'p2', param: 'q' }), makePoint({ id: 'p3', param: 'r' })];
  await runOobSentinel('s1', makeTarget(cfg), points, new Set(), null, cfg, ['union'], deps(client));
  assert.ok(state.requests <= 2, `预算 2 但发了 ${state.requests} 个请求`);
  await oobReceiver.stop();
});

test('面选择：user-skip / paramName 不播撒；headerParams 合成头点进入 report.points', async () => {
  await oobReceiver.start(OOB_CFG);
  const cfg = bgCfg({ timeoutMs: 60 });
  const target = makeTarget(cfg, { headerParams: { 'X-Api-Key': 'k1' } });
  const points = [
    makePoint({ id: 'skip', param: 'logout', skipReason: 'user-skip' }),
    makePoint({ id: 'name', param: 'orderby', location: 'paramName' }),
    makePoint({ id: 'static', param: 'page', skipReason: 'static' }),
  ];
  const { client } = makeSilentClient();
  await runOobSentinel('s1', target, points, new Set(), null, cfg, ['union'], deps(client));
  const headers = points.filter((p) => p.location === 'header');
  assert.equal(headers.length, 1, '未生成注入点的 headerParams 必须合成一个头点');
  assert.equal(headers[0].param, 'X-Api-Key');
  assert.equal(headers[0].background, true, '合成头点必须带 background 标记');
  assert.ok(points.some((p) => p.id === 'static'), 'static 跳过点应保留在 points 里');
  // user-skip/paramName 绝不合成，也不被标记
  assert.equal(points.find((p) => p.id === 'skip').confirmed, false);
  assert.equal(points.find((p) => p.id === 'name').confirmed, false);
  await oobReceiver.stop();
});

test('oob 技术已选中且点完整跑过 → 不重复播撒（零额外请求）', async () => {
  await oobReceiver.start(OOB_CFG);
  const cfg = bgCfg({ timeoutMs: 60 });
  const { client, state } = makeSilentClient();
  const points = [makePoint({ id: 'p1' })];
  const out = await runOobSentinel(
    's1', makeTarget(cfg), points, new Set(['p1']), null, cfg, ['oob'], deps(client)
  );
  assert.deepEqual(out, []);
  assert.equal(state.requests, 0);
  await oobReceiver.stop();
});

test('零注入点扫描经哨兵命中 → 清掉 noInjectionPoints 误导标记', async () => {
  await oobReceiver.start(OOB_CFG);
  const cfg = bgCfg({ timeoutMs: 500 });
  const target = makeTarget(cfg, { headerParams: { 'X-Trace': '1' } });
  const points = [];
  const report = { summary: { noInjectionPoints: true, noInjectionPointsHint: 'x' } };
  const { client } = makeCallbackClient();
  const out = await runOobSentinel('s1', target, points, new Set(), null, cfg, ['union'], deps(client, { report }));
  assert.ok(out.length >= 1, '头面回连必须检出');
  assert.equal(report.summary.noInjectionPoints, undefined);
  assert.equal(report.summary.noInjectionPointsHint, undefined);
  await oobReceiver.stop();
});

// ── ③ 包装层与启动门控 ────────────────────────────────────────────────────

test('_runOobBackground 包装层：未启用时零请求，且不挂 ScanManager.prototype', async () => {
  const { client, state } = makeSilentClient();
  const self = {
    _wrapWithSignal: (id, c) => c,
    getScanClient: () => client,
    _selectedTechs: () => ['union'],
    reportGen: new ReportGenerator(),
    _maybeClose: async () => {},
  };
  const cfg = { ...OOB_CFG, background: { enabled: false } };
  const out = await _runOobBackground.call(self, 's1', makeTarget(cfg), [makePoint()], null, new Set(), null, { summary: {} });
  assert.deepEqual(out, []);
  assert.equal(state.requests, 0);
  const { ScanManager } = await import('../src/engine/ScanManager.js');
  // 不挂原型：挂载会拉长原型挂载尾部，与 httpClient/Detector/Exploiter 产生克隆窗口
  assert.equal(ScanManager.prototype._runOobBackground, undefined, '不得挂原型（supplemental 直接 .call）');
});

test('startOobIfNeeded：background.enabled 隐含启动（即使 techniques 不含 oob）', async () => {
  const cfg = { enabled: false, callbackBase: `127.0.0.1:${PORT}`, httpPort: PORT, background: { enabled: true } };
  const err = await startOobIfNeeded([], cfg);
  assert.equal(err, null, `隧道应启动，实际：${err}`);
  assert.equal(oobTunnel.isStarted(), true);
  await oobTunnel.stop();
});

test('startOobIfNeeded：未选中 oob 且 background 关闭 → 不启动', async () => {
  const err = await startOobIfNeeded(['union'], { enabled: true, background: { enabled: false } });
  assert.equal(err, null);
  assert.equal(oobTunnel.isStarted(), false);
});
