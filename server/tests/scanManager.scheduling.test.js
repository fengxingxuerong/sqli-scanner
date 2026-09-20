// A 项回归：检测器调度分层并发（快速层 union/error/boolean 并行 + 慢速层 time/stacked/oob 并行）
// 验证：1) 快速层并发（墙钟≈单检测耗时而非线性累加）
//      2) 快速层命中且 stacked 未选 → 慢速层不跑（省请求，保留 break-on-first-hit 语义）
//      3) stacked 选中 → 快速层命中仍跑慢速层（确保 stacked 独立确认）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanManager } from '../src/engine/ScanManager.js';
import { TECHNIQUE_TYPES } from '../src/engine/payloads.js';

// 构造可控桩：每个技术可配置 { vulnerable, delay(ms) }；记录实际被调用的技术集合
function makeManager(plan) {
  const called = [];
  const sm = new ScanManager();
  // 记录每个检测器的在飞区间，用于断言「并行调度」本身（而不是墙钟阈值）。
  sm._spans = [];
  sm.detectors = TECHNIQUE_TYPES.map((t) => ({
    technique: t,
    async detect(ctx) {
      called.push(t);
      const span = { technique: t, start: Date.now(), end: 0 };
      sm._spans.push(span);
      const spec = plan[t] || {};
      if (spec.delay) await new Promise((r) => setTimeout(r, spec.delay));
      span.end = Date.now();
      const vulnerable = !!(spec && spec.vulnerable);
      return {
        pointId: ctx.point.id,
        technique: t,
        vulnerable,
        dbms: vulnerable ? 'MySQL' : null,
        evidence: vulnerable ? `mock ${t} hit` : '',
        payloads: vulnerable ? [`mock_${t}`] : [],
      };
    },
  }));
  sm.fp = { async fingerprint() { return { dbms: null, baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  sm._called = called;
  return sm;
}

async function runScan(sm, config) {
  const scanId = await sm.start({
    url: 'http://x.test/?id=1',
    config: { concurrency: 1, ratePerSec: 100, techniques: (config && config.techniques) || TECHNIQUE_TYPES, ...config },
  });
  // 等待 _run 完成（轮询状态）
  // [FLAKY-FIX 2026-09-20] 原预算 200×5ms=1s 太紧：负载高时扫描未完成即继续断言，假红。
  // 本文件 2026-09-18 的记录是「连跑 3 次 2/1/2 个失败，从不全绿」，根因就是这个固定墙钟预算。
  // 放宽到 6000×5ms=30s（语义不变：仍是「轮询到终态即返回」，只是不再假定耗时上限）。
  // 注意：这里必须用**未 unref** 的普通 setTimeout —— 它是等待期间的活跃锚，
  // 一旦换成被 unref 的定时器或提前清空所有定时器，父级会判定本轮结束并取消剩余子测试
  // （实测报 cancelledByParent: "event loop has already resolved"）。
  for (let i = 0; i < 6000; i++) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  return scanId;
}

// 并发峰值：把在飞区间按时间扫一遍，取同时处于在飞状态的最大个数。
// 用它代替「墙钟 < N ms」阀值：后者在 CI/并发负载下会假红（本机跑其他测试时实测飘到 1.6s），
// 而「三个快速层是否真的同时在飞」才是本测试要钉的语义，与机器忙不忙无关。
function maxInFlight(spans) {
  const events = [];
  for (const s of spans) {
    if (!s.end) continue;
    events.push([s.start, 1], [s.end, -1]);
  }
  events.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  let cur = 0;
  let peak = 0;
  for (const [, d] of events) {
    cur += d;
    if (cur > peak) peak = cur;
  }
  return peak;
}

test('快速层并发：union/error/boolean 同时在飞（并行而非串行）', async () => {
  const sm = makeManager({ union: { vulnerable: false, delay: 80 }, error: { vulnerable: false, delay: 80 }, boolean: { vulnerable: false, delay: 80 } });
  await runScan(sm, { techniques: ['union', 'error', 'boolean'] });
  const fast = sm._spans.filter((s) => ['union', 'error', 'boolean'].includes(s.technique));
  assert.equal(fast.length, 3, '三个快速层检测器都应被调用');
  assert.ok(
    maxInFlight(fast) >= 3,
    `期望快速层三者同时在飞（串行时峰值=1），实际峰值=${maxInFlight(fast)}`
  );
  assert.deepEqual([...sm._called].sort(), ['boolean', 'error', 'union']);
});

test('快速层命中且 stacked 未选 → 慢速层不跑（省请求）', async () => {
  const sm = makeManager({ union: { vulnerable: true }, error: { vulnerable: false }, boolean: { vulnerable: false }, time: { vulnerable: false, delay: 50 }, stacked: { vulnerable: false }, oob: { vulnerable: false } });
  await runScan(sm, { techniques: ['union', 'error', 'boolean', 'time'] }); // 注意：未选 stacked
  // 快速层有 union 命中 → 不应调用 time（慢速层被跳过）
  assert.ok(!sm._called.includes('time'), `快速层命中后不应跑 time，实际调用=${sm._called}`);
  assert.ok(!sm._called.includes('stacked'));
});

test('stacked 选中 → 快速层命中仍跑慢速层（独立确认）', async () => {
  const sm = makeManager({ union: { vulnerable: true }, error: { vulnerable: false }, boolean: { vulnerable: false }, time: { vulnerable: false }, stacked: { vulnerable: false }, oob: { vulnerable: false } });
  await runScan(sm, { techniques: ['union', 'error', 'boolean', 'time', 'stacked'] });
  // stacked 选中 → 即使 union 命中，慢速层(time/stacked)仍应被调用以独立确认
  assert.ok(sm._called.includes('time'), `stacked 选中应仍跑慢速层 time，实际=${sm._called}`);
  assert.ok(sm._called.includes('stacked'), `stacked 选中应仍跑 stacked，实际=${sm._called}`);
});

test('快速层未命中 → 慢速层兜底跑（不漏检）', async () => {
  const sm = makeManager({ union: { vulnerable: false }, error: { vulnerable: false }, boolean: { vulnerable: false }, time: { vulnerable: true }, stacked: { vulnerable: false }, oob: { vulnerable: false } });
  const scanId = await runScan(sm, { techniques: ['union', 'error', 'boolean', 'time'] });
  const report = sm.getReport(scanId);
  const timeVuln = report.vulns.find((v) => v.technique === 'time');
  assert.ok(timeVuln && timeVuln.riskLevel === 'Medium', '快速层全空时慢速层 time 命中应被保留');
});
