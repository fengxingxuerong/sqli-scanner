// [D195] CLI 收场结果面板单测：renderScanSummaryPanel 只做既有披露的终端呈现，
// 不产生新检测结论。判据：结论行/命中行/覆盖缺口提示/下一步建议按报告事实渲染。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderScanSummaryPanel, batchHitLines, batchNextLine, batchWriteHint, printBatchHitsAndNext } from '../bin/cli.js';

const baseReport = {
  scanId: 's1',
  target: { baseUrl: 'http://127.0.0.1:8099/vuln/?id=1', method: 'GET' },
  startedAt: '2026-10-30T04:02:12.079Z',
  finishedAt: '2026-10-30T04:02:14.498Z',
  riskLevel: 'Low',
  points: [{ id: '283e732d', param: 'id', location: 'url' }],
  vulns: [],
  summary: {
    verdict: 'no_vulnerability_detected',
    verdictNote: '目标在本次扫描窗口内可达、未被拦且会话有效，阴性结论可信度正常',
    uncoveredSurfaces: [
      { surface: 'cookie', label: 'Cookie 注入面', hint: '提高 --level 到 2，或显式 --test-headers' },
      { surface: 'header', label: 'HTTP 请求头注入面', hint: '提高 --level 到 3，或显式 --test-headers' },
      { surface: 'path', label: 'URL 路径段注入面', hint: '显式 --test-path' },
    ],
  },
};

test('面板：阴性结论报告渲染结论/命中/覆盖缺口/耗时，无命中复核建议', () => {
  const out = renderScanSummaryPanel(baseReport);
  assert.ok(out.includes('no_vulnerability_detected'), '结论行应有 verdict');
  assert.ok(out.includes('风险 Low'), '结论行应带风险等级');
  assert.ok(out.includes('0 漏洞'), '命中行应有漏洞数');
  assert.ok(out.includes('id@url'), '已测注入面应带 param@location');
  assert.ok(out.includes('3 类注入面未测'), '覆盖缺口应给数量');
  assert.ok(out.includes('cookie：提高 --level 到 2'), '前 2 个缺口应带提示');
  assert.ok(out.includes('其余 1 项'), '超出 2 条的缺口应折叠指引报告');
  assert.ok(out.includes('2.4s'), '耗时应有可读时长');
  assert.ok(!out.includes('--repro-check'), '无命中不应建议复测');
  assert.ok(out.includes('--level 2+'), '有缺口应建议扩覆盖');
});

test('面板：命中报告给出复测/修复提示词下一步', () => {
  const r = {
    ...baseReport,
    riskLevel: 'High',
    vulns: [{ id: 'v1', technique: 'boolean', riskLevel: 'High' }],
    summary: { verdict: 'vulnerability_detected' },
  };
  const out = renderScanSummaryPanel(r);
  assert.ok(out.includes('1 漏洞'), '命中行应有漏洞数');
  assert.ok(out.includes('--repro-check'), '有命中应建议复测');
  assert.ok(out.includes('--fix-prompt'), '有命中应建议修复提示词');
  assert.ok(!out.includes('覆盖缺口'), '无 uncovered 时不渲染覆盖缺口行');
});

test('面板：inconclusive 给出会话处置指引；未验证面如实披露', () => {
  const r = {
    ...baseReport,
    summary: {
      verdict: 'inconclusive',
      verdictNote: '会话半途失效',
      unverifiedSurfaces: [{ surface: 'header', label: 'HTTP 请求头注入面', tested: 1, total: 2 }],
    },
  };
  const out = renderScanSummaryPanel(r);
  assert.ok(out.includes('inconclusive'), '结论行如实展示');
  assert.ok(out.includes('会话/签名问题'), 'inconclusive 应给处置指引');
  assert.ok(out.includes('未验证面'), '未验证面应披露');
  assert.ok(out.includes('不等于'), '未验证面应带口径提醒');
});

test('面板：注入面 >3 折叠；verdictNote 过长截断；缺 finishedAt 时耗时不崩', () => {
  const r = {
    ...baseReport,
    startedAt: '2026-10-30T04:02:12.079Z',
    finishedAt: undefined,
    points: [1, 2, 3, 4, 5].map((i) => ({ id: `p${i}`, param: `p${i}`, location: 'url' })),
    summary: {
      verdict: 'no_vulnerability_detected',
      verdictNote: '长'.repeat(200),
      uncoveredSurfaces: [],
    },
  };
  const out = renderScanSummaryPanel(r);
  assert.ok(out.includes('等 5 个'), '注入面应折叠');
  assert.ok(!out.includes('长'.repeat(121)), 'verdictNote 应截断');
  assert.ok(out.includes('耗时      -'), '缺 finishedAt 耗时降级为 -');
});

// ── [D196] 批量收场增补 ──
test('批量：命中目标逐个点名（High/Critical + 漏洞数），无命中零行', () => {
  const results = [
    { url: 'http://a/?id=1', riskLevel: 'High', vulns: 3 },
    { url: 'http://b/?id=1', riskLevel: 'Low', vulns: 0 },
    { url: 'http://c/?id=1', riskLevel: 'Critical', vulns: 2 },
  ];
  const lines = batchHitLines(results, (u) => u);
  assert.equal(lines.length, 3, '2 个命中 + 1 行标题');
  assert.ok(lines[0].includes('命中目标  2 个'), '标题带命中数');
  assert.ok(lines[1].includes('http://a/?id=1：High · 3 漏洞'), '逐个点名带风险与漏洞数');
  assert.deepEqual(batchHitLines([{ url: 'x', riskLevel: 'Low', vulns: 0 }], (u) => u), [], '无命中零行');
});

test('批量：下一步按摘要事实推导（高危/需复核/失败三种组合）', () => {
  const full = batchNextLine({ hasHigh: true, needsReview: 1, failed: 2 });
  assert.ok(full.includes('--repro-check') && full.includes('需复核目标') && full.includes('失败目标'), '三种事实齐全时全部出现');
  assert.ok(batchNextLine({ hasHigh: false, needsReview: 0, failed: 0 }) === null, '全干净无建议');
});

test('批量：json-only 落盘指引（非 json 为空串）', () => {
  assert.ok(batchWriteHint('json').includes('--format markdown'));
  assert.equal(batchWriteHint('html'), '');
});

test('批量：printBatchHitsAndNext 走注入的 log（可测、无 console 副作用）', () => {
  const out = [];
  printBatchHitsAndNext({
    results: [{ url: 'http://a/', riskLevel: 'High', vulns: 1 }],
    urlOf: (u) => u,
    summary: { hasHigh: true, needsReview: 0, failed: 0 },
    log: (m) => out.push(m),
  });
  assert.equal(out.length, 3, '命中标题 + 目标行 + 下一步行');
  assert.ok(out[2].startsWith('下一步'), '下一行以标签开头');
});
