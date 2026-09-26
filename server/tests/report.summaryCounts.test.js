// ============================================================================
// tests/report.summaryCounts.test.js —— 产品报告路径必须算出风险/技术分布
// ============================================================================
// 起因（2026-09-25 实测）：`scripts/one-click-scan.mjs` 的机读清单取
// `report.summary?.byRisk || null` 与 `byTechnique`，而这两个键**只在并行的
// `ReportGenerator.build()` 里算过** —— 产品实际走的 `createReport` → `scan/finalize`
// 那条路从没算过。于是清单里两个键恒 null：
//   现成产物 reports/127.0.0.1-2026-09-17T13-51-34/manifest.json 就是现场 ——
//   findings 三条（High/Medium 齐全），summary.byRisk/byTechnique 却是 null，
//   而同层的 totalPoints/totalVulns 有值（那两个是清单自己现算的）。
//   CI/看板读到 null 会以为"这次扫描没有风险分布可言"。
//
// 为什么必须跑真流水线（不是测 countBy 这个纯函数）：
//   纯函数测一遍只会证明"它能算"，证明不了"有人调它"。本仓已多次栽在
//   "注册成功 ≠ 在干活"上（判据写了、字段声明了、消费方却永远拿到空值）。
//   这里用 ScanManager + 桩检测器走完整流水线，断言的是**落盘报告里的字段**。
// 反向判据：把 finalize 里那两行摘掉 ⇒ 本文件两条断言当场红（keys undefined）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanManager } from '../src/engine/ScanManager.js';
import { TECHNIQUE_TYPES } from '../src/engine/payloads.js';
import { countBy } from '../src/engine/models.js';

// 命中集：union → High、boolean → Medium（风险等级由 reportGen.riskOf 按技术定）
const HIT = new Set(['union', 'boolean']);

function makeManager() {
  const sm = new ScanManager();
  sm.httpClient = { async request() { return { status: 200, headers: {}, data: 'x'.repeat(500) }; } };
  sm.detectors = TECHNIQUE_TYPES.map((t) => ({
    technique: t,
    async detect(ctx) {
      const hit = HIT.has(t);
      return {
        pointId: ctx.point.id,
        technique: t,
        vulnerable: hit,
        dbms: hit ? 'MySQL' : null,
        evidence: hit ? `stub-${t} evidence` : '',
        payloads: hit ? ["1' UNION SELECT 1-- -"] : [],
      };
    },
  }));
  sm.fp = { async fingerprint() { return { dbms: 'MySQL', baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  sm.parser = {
    async discover() {
      return [{ id: 'p1', location: 'url', param: 'v', originalValue: '1' }];
    },
  };
  return sm;
}

async function finishedReport() {
  const sm = makeManager();
  const id = await sm.start({
    url: 'http://mock.test/?v=1',
    config: { concurrency: 1, ratePerSec: 200, prefilter: false, level: 1 },
  });
  for (let i = 0; i < 600; i++) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error' || s.status === 'stopped')) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  return sm.getReport(id);
}

test('真流水线报告：summary.byRisk / byTechnique 有值且与 vulns 逐条一致', async () => {
  const report = await finishedReport();
  assert.ok(report, '报告必须已落盘');
  assert.ok(report.vulns.length >= 2, `桩应命中 ≥2 条漏洞，实际 ${report.vulns.length}`);

  // ① 字段存在（这就是清单那两行读的键；摘掉 finalize 里的赋值 ⇒ 这里 undefined）
  assert.notEqual(report.summary.byRisk, undefined, 'summary.byRisk 缺失 ⇒ manifest 读到 null');
  assert.notEqual(report.summary.byTechnique, undefined, 'summary.byTechnique 缺失 ⇒ manifest 读到 null');

  // ② 与报告本体逐条对账（不采信"看起来有值"）
  assert.deepEqual(report.summary.byRisk, countBy(report.vulns, 'riskLevel'));
  assert.deepEqual(report.summary.byTechnique, countBy(report.vulns, 'technique'));
  const sum = (m) => Object.values(m || {}).reduce((a, b) => a + b, 0);
  assert.equal(sum(report.summary.byRisk), report.vulns.length, 'byRisk 合计必须等于漏洞条数');
  assert.equal(sum(report.summary.byTechnique), report.vulns.length, 'byTechnique 合计必须等于漏洞条数');

  // ③ 具体形态：union→High、boolean→Medium（风险等级来自 reportGen.riskOf，不是本测试假设）
  assert.equal(report.summary.byTechnique.union, 1);
  assert.equal(report.summary.byTechnique.boolean, 1);
  assert.equal(report.summary.byRisk.High, 1);
  assert.equal(report.summary.byRisk.Medium, 1);
});

test('零命中扫描：两个计数是空对象而不是 null/undefined（清单消费方要能区分"没有"与"没算"）', async () => {
  HIT.clear();
  try {
    const report = await finishedReport();
    assert.equal(report.vulns.length, 0);
    assert.deepEqual(report.summary.byRisk, {});
    assert.deepEqual(report.summary.byTechnique, {});
  } finally {
    HIT.add('union');
    HIT.add('boolean');
  }
});
