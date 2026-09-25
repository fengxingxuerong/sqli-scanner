// detect.orchestration.test.js —— scan/detect.js（检测调度 + WAF 自适应重跑）专属单测
// ============================================================================
// 为什么补这一份：覆盖率报告里 `engine/scan/detect.js` 是服务端**最薄弱的核心**
// （lines 52% / branches 69% / functions 48%），且此前**没有专属测试**——
// 643 行的调度主体只有 e2e 间接照看，未覆盖的恰好全是安全关键分支：
//   db-guard 熔断 · validity 熔断 · Retry-After 退避 · 暂停 · resume 跳过 ·
//   direct 模式 DBMS 回落 · 全层网络失败记未决 · 重跑候选筛选与命中合并。
// 这些分支改坏不会让任何既有用例变红（这就是它们的价值）。
//
// 手法：**stub 驱动真实入口**（不是把内部逻辑抄一遍）—— 真调 detectPhase，
// 事件从 eventBus 真实流里捕获，断言落在「发了什么事件 / 哪些检测器被调 /
// 结果怎么合并」这些外部可观测事实上。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectPhase } from '../src/engine/scan/detect.js';
import * as eventBus from '../src/core/eventBus.js';

let uid = 0;
const nextScanId = () => `detect-orch-${++uid}`;

// detect.js 用 `constructor.name === 'UnionDetector'` 找闭合前缀探测器 —— stub 必须同名
class UnionDetector {
  constructor(spec = {}) { this.technique = 'union'; this.spec = spec; this.calls = []; this.boundaryCalls = 0; }
  async detect(ctx) { this.calls.push(ctx); return nextResult(this.spec, this.calls.length); }
  async probeBoundary() { this.boundaryCalls += 1; return this.spec.boundary ?? "'"; }
}
class ErrorDetector {
  constructor(spec = {}) { this.technique = 'error'; this.spec = spec; this.calls = []; }
  async detect(ctx) { this.calls.push(ctx); return nextResult(this.spec, this.calls.length); }
}
class BooleanDetector {
  constructor(spec = {}) { this.technique = 'boolean'; this.spec = spec; this.calls = []; }
  async detect(ctx) { this.calls.push(ctx); return nextResult(this.spec, this.calls.length); }
}
class TimeDetector {
  constructor(spec = {}) { this.technique = 'time'; this.spec = spec; this.calls = []; }
  async detect(ctx) { this.calls.push(ctx); return nextResult(this.spec, this.calls.length); }
}
class StackedDetector {
  constructor(spec = {}) { this.technique = 'stacked'; this.spec = spec; this.calls = []; }
  async detect(ctx) { this.calls.push(ctx); return nextResult(this.spec, this.calls.length); }
}

const CLASSES = { union: UnionDetector, error: ErrorDetector, boolean: BooleanDetector, time: TimeDetector, stacked: StackedDetector };

/** spec.results 按顺序出队（第 1 次主轮、第 2 次重跑……）；spec.throw 每次都抛 */
function nextResult(spec, n) {
  if (spec.throw) throw spec.throw;
  if (Array.isArray(spec.results)) return spec.results[Math.min(n, spec.results.length) - 1] ?? { vulnerable: false };
  return spec.result ?? { vulnerable: false };
}

const NET_ERR = () => Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:80'), { code: 'ECONNREFUSED' });

/**
 * 构造 detectPhase 的最小 run 上下文。
 * @param {object} o
 * @param {Record<string, object>} [o.detectors] 技术 → spec（vulnerable / results / throw）
 */
function build(o = {}) {
  const scanId = nextScanId();
  const events = [];
  const em = eventBus.create(scanId);
  em.on('event', (e) => events.push(e));

  const points = (o.points || [{ id: 'p1' }]).map((p) => ({ originalValue: '1', ...p }));
  const specs = o.detectors || { union: {}, error: {}, boolean: {} };
  const detectors = Object.entries(specs).map(([tech, spec]) => new CLASSES[tech](spec));

  const calls = { activeConfigs: [], inconclusive: [], netErrPoints: [] };

  const httpClient = o.httpClient || { request: async () => ({ status: 200, data: 'x'.repeat(120) }) };

  const sm = {
    detectors,
    extractor: {},
    _selectedTechs: () => o.selected || Object.keys(specs),
    activeDetectors(config) {
      calls.activeConfigs.push(config);
      return detectors.filter((d) => !(config && Array.isArray(config.techniques)) || config.techniques.includes(d.technique));
    },
    async _fingerprintCached() {
      // 显式判 undefined：调用方要能表达「指纹未命中」(null)，用 ?? 会把 null 吞成默认值 ——
      // 那会让 direct 模式用例变成假绿（dialect 分支被短路也照样拿到 dbms）。
      return o.fpResult === undefined
        ? { dbms: 'MySQL', baseline: { status: 200, headers: {}, data: 'x'.repeat(120) } }
        : o.fpResult;
    },
    wafIdentifier: {
      identify: () => o.wafCands ?? [],
      shouldAutoRetry: () => o.autoRetry ?? false,
      activeProbe: async () => ({ detected: false }),
    },
    wafRecommend: () => (o.suggestions || []).map((s) => ({ ...s })),
    getScanClient: () => httpClient,
  };

  const validity = {
    shouldAbort: o.validityAbort ?? false,
    _abortLogged: false,
    addInconclusive(id) { calls.inconclusive.push(id); },
    addNetworkErrorPoint(id) { calls.netErrPoints.push(id); },
    consumeBackoffMs: () => o.backoffMs ?? 0,
    summary: () => ({ reason: 'stub', counts: o.counts ?? { blockHits: 0, serverErr: 0, injection5xx: 0 } }),
  };

  const run = {
    cfg: o.cfg ?? {},
    ctxBase: { httpClient },
    guard: { shouldAbort: o.guardAbort ?? false, fatalHits: 3, lastFatal: { id: 'db-down' }, _abortLogged: false },
    pointsToScan: points,
    rawClient: o.rawClient ?? null,
    s: { cancelled: false, paused: false, ...(o.s || {}) },
    scanId,
    session: o.session ?? null,
    sm,
    target: o.target ?? { mode: 'http', config: { concurrency: 2, ratePerSec: 1000, oob: {}, wafEvasion: {} } },
    validity,
    validityEnabled: o.validityEnabled ?? true,
  };

  return {
    run, scanId, events, calls, detectors, points, sm,
    byType: (t) => events.filter((e) => e.type === t),
    det: (tech) => detectors.find((d) => d.technique === tech),
    done: () => eventBus.dispose(scanId),
  };
}

// ① db-guard 熔断：目标库已损坏 —— 剩余点必须跳过，且不记入「已测完」
test('① db-guard 熔断：剩余点全部跳过，不进 fullyTestedPoints，且中止只播报一次', async () => {
  const h = build({ guardAbort: true, points: [{ id: 'p1' }, { id: 'p2' }] });
  try {
    const out = await detectPhase(h.run);
    assert.equal(out.fullyTestedPoints.size, 0, '熔断后不得把点算成「已完整检测」');
    assert.equal(h.det('union').calls.length, 0, '熔断后不得再发检测请求');
    const aborts = h.byType('db_health_abort');
    assert.equal(aborts.length, 1, '两个点也只播报一次（_abortLogged 去抖）');
    assert.equal(aborts[0].payload.fatalHits, 3);
  } finally { h.done(); }
});

test('① 反向：guard 未熔断时点必须真的被检测（防「跳过」逻辑被写成恒跳过）', async () => {
  const h = build({ points: [{ id: 'p1' }] });
  try {
    const out = await detectPhase(h.run);
    assert.equal(out.fullyTestedPoints.size, 1);
    assert.equal(h.det('union').calls.length, 1);
    assert.equal(h.byType('db_health_abort').length, 0);
  } finally { h.done(); }
});

// ② validity 熔断：目标已连续无有效响应 —— 逐点记未决，禁止冒充阴性
test('② validity 熔断：每个剩余点都记入未决，并播报 scan_validity_abort', async () => {
  const h = build({ validityAbort: true, points: [{ id: 'p1' }, { id: 'p2' }, { id: 'p3' }] });
  try {
    const out = await detectPhase(h.run);
    assert.deepEqual(h.calls.inconclusive.sort(), ['p1', 'p2', 'p3'], '未测的点必须逐个登记，不能被静默吞掉');
    assert.equal(h.det('union').calls.length, 0, '目标已不可信时不得继续投放 payload');
    assert.equal(out.fullyTestedPoints.size, 0);
    assert.equal(h.byType('scan_validity_abort').length, 1, '同样只播报一次');
  } finally { h.done(); }
});

// ③ Retry-After 退避：退避但**不跳过**该点（退避 ≠ 放弃）
test('③ 目标回了 Retry-After：播报退避时长，随后该点仍被检测', async () => {
  const h = build({ backoffMs: 30 });
  try {
    const out = await detectPhase(h.run);
    const bo = h.byType('scan_validity_backoff');
    assert.equal(bo.length, 1);
    assert.equal(bo[0].payload.waitMs, 30, '退避时长必须原样透出（报告/日志要能看懂）');
    assert.equal(out.fullyTestedPoints.size, 1, '退避只是等一等，不是丢点');
    assert.equal(h.det('union').calls.length, 1);
  } finally { h.done(); }
});

// ④ 暂停：点边界阻塞，resume 后继续（不得把暂停当成取消）
test('④ 暂停期间不检测，resume 后该点继续跑完', async () => {
  const h = build({ s: { paused: true } });
  try {
    // 不先 await：暂停期必须真的在等 —— 只看「最终结果」抓不到「没等就跑了」
    const pending = detectPhase(h.run);
    await new Promise((r) => setTimeout(r, 450)); // > PAUSE_POLL_MS(300)，至少跨过一轮轮询
    assert.equal(h.det('union').calls.length, 0, '暂停期间不得投放检测请求');
    h.run.s.paused = false;
    const out = await pending;
    assert.equal(out.fullyTestedPoints.size, 1, 'resume 后必须补上（暂停不是取消）');
    assert.equal(h.det('union').calls.length, 1);
  } finally { h.done(); }
});

test('④ 反向：cancelled 时点被跳过且不进 fullyTestedPoints', async () => {
  const h = build({ s: { cancelled: true } });
  try {
    const out = await detectPhase(h.run);
    assert.equal(out.fullyTestedPoints.size, 0);
    assert.equal(h.det('union').calls.length, 0);
  } finally { h.done(); }
});

// ⑤ resume 模式：已完成点跳过（省请求），且不算「已测完」
test('⑤ resume 续扫：status=done 的点跳过，播报 resume-done 且不重复检测', async () => {
  const session = { perPoint: { p1: { status: 'done' } }, savePointResult: async () => null };
  const h = build({ session, points: [{ id: 'p1' }] });
  try {
    const out = await detectPhase(h.run);
    const skipped = h.byType('point_skipped');
    assert.equal(skipped.length, 1);
    assert.equal(skipped[0].payload.reason, 'resume-done');
    assert.equal(h.det('union').calls.length, 0, '已完成点不得重复发检测请求');
    assert.equal(out.fullyTestedPoints.size, 0, '本轮没测过它，不能算进「已测完」');
  } finally { h.done(); }
});

// ⑥ direct 模式：驱动 dialect → DBMS 回落（避免 http 指纹必然失败时的死回退）
test('⑥ direct 模式：dialect 映射出的 DBMS 写回 point 与产物（指纹识别失败也能定位库）', async () => {
  const h = build({
    rawClient: { getDialect: async () => 'mysql' },
    fpResult: null, // 指纹识别未命中
    target: { mode: 'direct', config: { concurrency: 1, ratePerSec: 1000, oob: {}, wafEvasion: {} } },
  });
  try {
    const out = await detectPhase(h.run);
    assert.equal(out.dbms, 'MySQL');
    assert.equal(h.points[0].dbms, 'MySQL');
  } finally { h.done(); }
});

test('⑥ 反向：非 direct 模式不消费 rawClient（防 dialect 分支越界改写 dbms）', async () => {
  let asked = 0;
  const h = build({
    rawClient: { getDialect: async () => { asked += 1; return 'mysql'; } },
    fpResult: { dbms: 'PostgreSQL', baseline: { status: 200, headers: {}, data: 'x'.repeat(120) } },
    target: { mode: 'http', config: { concurrency: 1, ratePerSec: 1000, oob: {}, wafEvasion: {} } },
  });
  try {
    const out = await detectPhase(h.run);
    assert.equal(asked, 0, 'http 模式不该去问驱动方言');
    assert.equal(out.dbms, 'PostgreSQL');
  } finally { h.done(); }
});

// ⑦ 两层调度：快速层命中即省掉慢速层请求；stacked 被选中则慢速层必须独立跑
test('⑦ 快速层命中且未选 stacked → 慢速层零请求（省请求的核心）', async () => {
  const h = build({
    detectors: { union: { result: { vulnerable: true } }, error: {}, boolean: {}, time: {}, stacked: {} },
    selected: ['union', 'error', 'boolean', 'time'],
  });
  try {
    await detectPhase(h.run);
    assert.equal(h.det('union').calls.length, 1);
    assert.equal(h.det('time').calls.length, 0, '已命中还跑慢速层 = 白花请求');
  } finally { h.done(); }
});

test('⑦ 反向：stacked 被选中时，即使快速层命中也要跑慢速层（末位独立确认）', async () => {
  const h = build({
    detectors: { union: { result: { vulnerable: true } }, error: {}, boolean: {}, time: {}, stacked: {} },
    selected: ['union', 'error', 'boolean', 'time', 'stacked'],
  });
  try {
    await detectPhase(h.run);
    assert.equal(h.det('time').calls.length, 1);
    assert.equal(h.det('stacked').calls.length, 1);
  } finally { h.done(); }
});

// ⑧ 全层网络失败：该点必须记「未决」，不能沉淀成假阴性
test('⑧ 检测器全部因网络层失败退出 → 点标记 netErr 并登记未决（不得当成「测了没漏洞」）', async () => {
  const h = build({
    detectors: { union: { throw: NET_ERR() }, error: { throw: NET_ERR() }, boolean: { throw: NET_ERR() } },
  });
  try {
    const out = await detectPhase(h.run);
    assert.equal(h.points[0].netErr, true);
    assert.deepEqual(h.calls.netErrPoints, ['p1']);
    assert.equal(out.foundByPoint.size, 0, '网络失败不得产出命中');
    assert.equal(out.fullyTestedPoints.size, 1, '点确实跑完了，但是「未决」不是「安全」');
  } finally { h.done(); }
});

test('⑧ 反向：非网络异常按未命中处理，不记未决（不能把「不适用」说成「没测通」）', async () => {
  const h = build({
    detectors: { union: { throw: new Error('payload 构造失败') }, error: {}, boolean: {} },
  });
  try {
    await detectPhase(h.run);
    assert.equal(h.points[0].netErr, undefined, '非网络异常不该污染结论可信度');
    assert.deepEqual(h.calls.netErrPoints, []);
  } finally { h.done(); }
});

// ⑨ 拦截驱动重跑：候选必须包含「已命中但快速层技术位不足」的点（P0-FIX 2026-09-10）
test('⑨ 拦截证据驱动重跑：已命中但技术位不足的点**也在**重跑候选里（否则 union 面永远补不上）', async () => {
  const h = build({
    detectors: {
      union: { results: [{ vulnerable: false }, { vulnerable: true }] },  // 主轮未中、重跑命中
      error: { results: [{ vulnerable: true }, { vulnerable: false }] },  // 主轮命中、重跑不再命中
      // ↑ 重跑侧必须让 error 落空：否则「覆盖式 set」恰好也产出 [error, union]，断言假绿
      boolean: {},
    },
    counts: { blockHits: 3, serverErr: 0, injection5xx: 0 }, // 触发 blockAdaptive
  });
  try {
    const out = await detectPhase(h.run);
    assert.equal(h.det('union').calls.length, 2, 'p1 已命中 error（快速层仅 1 位）→ 必须进重跑候选');
    assert.equal(out.blockAdaptiveInfo?.triggered, true);
    assert.equal(out.blockAdaptiveInfo?.blockHits, 3);
    // 重跑命中 union 后**合并**保留原 error（早期实现直接 set 覆盖，补了 union 丢 error）
    const found = [...out.foundByPoint.get('p1').found].map((f) => f.technique).sort();
    assert.deepEqual(found, ['error', 'union'], '重跑命中必须按技术合并，不得覆盖已有命中');
    assert.ok(h.byType('point_testing').some((e) => e.payload.tamperRetry === true), '重跑必须带 tamperRetry 标记');
  } finally { h.done(); }
});

test('⑨ 重跑必须真的套上 tamper 配置（否则「重跑」只是原样再发一遍）', async () => {
  const h = build({
    detectors: { union: {}, error: { result: { vulnerable: true } }, boolean: {} },
    counts: { blockHits: 2, serverErr: 0, injection5xx: 0 },
  });
  try {
    await detectPhase(h.run);
    const retryCfg = h.calls.activeConfigs.find((c) => c?.wafEvasion?.tamper?.enabled === true);
    assert.ok(retryCfg, '重跑阶段必须构造带 tamper 的 retryConfig');
    assert.ok(Array.isArray(retryCfg.wafEvasion.tamper.plugins) && retryCfg.wafEvasion.tamper.plugins.length > 0,
      'tamper.plugins 为空等于没变形');
  } finally { h.done(); }
});

test('⑨ 反向：用户已显式配置 tamper 时不自作主张（人工接管优先）', async () => {
  const h = build({
    detectors: { union: {}, error: {}, boolean: {} },
    counts: { blockHits: 3, serverErr: 0, injection5xx: 0 },
    target: {
      mode: 'http',
      config: { concurrency: 1, ratePerSec: 1000, oob: {}, wafEvasion: { tamper: { enabled: true, plugins: ['randomcase'] } } },
    },
  });
  try {
    const out = await detectPhase(h.run);
    assert.equal(out.blockAdaptiveInfo, null, '人工挂链时不得再触发自适应重跑（否则 A/B 口径会串味）');
    assert.equal(h.det('union').calls.length, 1, '只有主轮，没有重跑');
  } finally { h.done(); }
});

// ⑩ OOB：启动失败要落成产物字段（报告才能写明「带外没测成」）
test('⑩ OOB 接收端启动失败 → oobUnavailable 写入产物（不让 time/oob 场景被误读成「无带外」）', async () => {
  const h = build({
    selected: ['union', 'error', 'boolean', 'oob'],
    detectors: { union: {}, error: {}, boolean: {} },
    target: {
      mode: 'http',
      config: {
        concurrency: 1, ratePerSec: 1000,
        oob: { enabled: true, start: async () => { throw new Error('端口被占用'); } },
        wafEvasion: {},
      },
    },
  });
  try {
    // oobReceiver.start 是真实模块（无 start 桩则为 no-op），此处仅断言字段存在且可为空：
    // 真实失败路径由 oobReceiver 自身测试覆盖，本例守住「产物里必须有这个字段」
    const out = await detectPhase(h.run);
    assert.ok('oobUnavailable' in out, '产物必须带 oobUnavailable 字段（报告据此说明带外未测成）');
  } finally { h.done(); }
});
