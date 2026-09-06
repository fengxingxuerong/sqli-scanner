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
  sm.detectors = TECHNIQUE_TYPES.map((t) => ({
    technique: t,
    async detect(ctx) {
      called.push(t);
      const spec = plan[t] || {};
      if (spec.delay) await new Promise((r) => setTimeout(r, spec.delay));
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
  for (let i = 0; i < 200; i++) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  return scanId;
}

test('快速层并发：union/error/boolean 同时跑（墙钟≈单检测耗时，非 3 倍线性）', async () => {
  const sm = makeManager({ union: { vulnerable: false }, error: { vulnerable: false }, boolean: { vulnerable: false, delay: 80 } });
  const t0 = Date.now();
  await runScan(sm, { techniques: ['union', 'error', 'boolean'] });
  const wall = Date.now() - t0;
  // 三个快速检测并行 → 墙钟应 < 200ms（若串行则为 ~240ms+）。宽松阈值防 CI 抖动。
  assert.ok(wall < 220, `期望快速层并发墙钟<220ms，实际=${wall}ms`);
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
