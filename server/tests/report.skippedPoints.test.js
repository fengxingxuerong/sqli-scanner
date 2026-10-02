// ============================================================================
// report.skippedPoints.test.js — 跳过点统计进交付格式（实战分析 P0-2，2026-10-02）
// ============================================================================
// 存在理由：skippedPoints（有多少点没测、为什么没测）此前只有 JSON 整包与前端逐点
// 标注可见，导出的 md/HTML/SARIF 客户看不到——甲方验收追问「测全了吗」时对外格式
// 答不上，而「prefilter 跳过的点」被误读成「测了且无漏洞」正是交付物级误导（与
// 2026-09-12 verdict 自相矛盾修复同型的问题）。
//
// 夹具纪律（沿 report.sarif.test.js 的规矩）：skippedPoints 由**真实工厂路径**产出——
// 点的 skipReason 用引擎真实原因码（prefilter/static/input_validation），汇总走
// scanHelpers.summarizeSkipped 本体，不许手写 {total, byReason} 字面量。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';
import { createInjectionPoint } from '../src/engine/models.js';
import { summarizeSkipped } from '../src/engine/scanHelpers.js';

const rg = new ReportGenerator();

function makeReport({ withSkips = true, verdict } = {}) {
  const tested = createInjectionPoint('url', 'id', '1');
  const skipPrefilter = createInjectionPoint('url', 'p1', '1');
  const skipStatic = createInjectionPoint('url', 'logo.png', '1');
  const skipValidation = createInjectionPoint('url', 'uid', '1');
  if (withSkips) {
    skipPrefilter.skipReason = 'prefilter';
    skipStatic.skipReason = 'static';
    skipValidation.skipReason = 'input_validation';
  }
  const points = [tested, skipPrefilter, skipStatic, skipValidation];
  const report = {
    scanId: 's1',
    riskLevel: 'High',
    dbms: 'MySQL',
    startedAt: '2026-10-02T00:00:00.000Z',
    finishedAt: '2026-10-02T00:00:10.000Z',
    target: { mode: 'http', baseUrl: 'http://t.local/p', method: 'GET', config: {} },
    points,
    vulns: [],
    data: null,
    summary: {},
  };
  // 走产品真实汇总路径：summary.skippedPoints 由 finalize 里的同一函数产出
  const skipped = summarizeSkipped(points);
  if (skipped) report.summary.skippedPoints = skipped;
  if (verdict) {
    report.summary.verdict = verdict;
    report.summary.verdictNote = '探测层无有效响应信号';
  }
  return report;
}

test('skippedPoints 汇总由 summarizeSkipped 真实产出（3 点 3 原因）', () => {
  const rep = makeReport();
  assert.deepEqual(rep.summary.skippedPoints, {
    total: 3,
    byReason: { prefilter: 1, static: 1, input_validation: 1 },
  });
});

test('toMarkdown：结论节出现跳过统计（总数 + 人话原因标签）', () => {
  const md = rg.toMarkdown(makeReport({ verdict: 'no_vulnerability_detected' }));
  assert.ok(md.includes('跳过的注入点：**3** 个'), '应有总数行');
  assert.ok(md.includes('预筛选（探针无信号） 1'), 'prefilter → 人话标签');
  assert.ok(md.includes('静态资源 1'), 'static → 人话标签');
  assert.ok(md.includes('输入校验（参数在进 SQL 前被拦死） 1'), 'input_validation → 人话标签');
  assert.ok(md.includes('未被测试'), '必须显式声明「未测 ≠ 无漏洞」');
  assert.ok(md.includes('不计入「未检出」结论'));
});

test('toMarkdown：仅有跳过统计、无 verdict/constraints 时结论节仍渲染', () => {
  // 旧逻辑 _conclusion 在 verdict/note/constraints 全空时返回 null → 跳过统计会被吞掉；
  // 纯跳过场景（如全部 input_validation 跳过 + verdict 尚未生成）是真实存在的
  const md = rg.toMarkdown(makeReport());
  assert.ok(md.includes('跳过的注入点'), '纯 skipped 报告也必须渲染结论节');
});

test('toMarkdown：无跳过点时不渲染该行（旧报告向后兼容，零噪声）', () => {
  const md = rg.toMarkdown(makeReport({ withSkips: false, verdict: 'no_vulnerability_detected' }));
  assert.ok(!md.includes('跳过的注入点'), '无跳过不应出现该行');
  assert.ok(md.includes('结论判定'), 'verdict 照常渲染');
});

test('toHTML：跳过统计出现且不带 markdown 加粗标记、经 HTML 转义', () => {
  const html = rg.toHTML(makeReport({ verdict: 'inconclusive' }));
  assert.ok(html.includes('跳过的注入点：3 个'), '总数应在（** 已剥）');
  assert.ok(!html.includes('**'), 'HTML 出口不得残留 markdown 加粗标记');
  assert.ok(html.includes('未被测试，不计入「未检出」结论'));
});

test('toSARIF：run.properties.skippedPoints 挂载（0 结果 ≠ 0 风险的防线）', () => {
  const sarif = JSON.parse(rg.toSARIF(makeReport({ verdict: 'no_vulnerability_detected' })));
  assert.deepEqual(sarif.runs[0].properties.skippedPoints, {
    total: 3,
    byReason: { prefilter: 1, static: 1, input_validation: 1 },
  });
});

test('toSARIF：无跳过点时不挂 properties（不污染 schema，向后兼容）', () => {
  const sarif = JSON.parse(rg.toSARIF(makeReport({ withSkips: false })));
  assert.equal(sarif.runs[0].properties, undefined);
});
