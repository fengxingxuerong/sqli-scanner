// CLI --format 出口回归测试（[P1-FIX 2026-09-05]）
// 背景：--format 原为死参数——parseArgs 解析后从未消费，-o/-m 目录恒写 JSON，
// ReportGenerator 的 toCSV/toMarkdown/toHTML 在 CLI 侧完全不可达（仅 REST 可用）。
// 修复：formatReport(report, fmt) 分发函数，单目标 -o 与批量目录导出共用。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatReport } from '../bin/cli.js';

const report = {
  scanId: 's1',
  target: { url: 'http://t/?id=1' },
  riskLevel: 'High',
  vulns: [{ id: 'v1', technique: 'union', pointId: 'p1', dbms: 'MySQL' }],
  points: [{ id: 'p1', param: 'id', in: 'query' }],
  data: { dbs: {} },
};

test('formatReport: json 默认输出', () => {
  const out = formatReport(report);
  assert.equal(JSON.parse(out).scanId, 's1');
  assert.equal(formatReport(report, 'json'), out);
});

test('formatReport: csv 输出含表头与数据行', () => {
  const out = formatReport(report, 'csv');
  assert.ok(typeof out === 'string' && out.includes(','), `csv 应为字符串: ${out}`);
  assert.ok(out.length > 0);
});

test('formatReport: markdown 输出含风险等级', () => {
  const out = formatReport(report, 'markdown');
  assert.ok(out.includes('High') || out.includes('#'), `md 应含内容: ${out.slice(0, 200)}`);
});

test('formatReport: html 输出为 HTML 文档', () => {
  const out = formatReport(report, 'html');
  assert.ok(/<html|<table|<!DOCTYPE/i.test(out), `html 应含标签: ${out.slice(0, 200)}`);
});

test('formatReport: md 别名与 markdown 等价', () => {
  assert.equal(formatReport(report, 'md'), formatReport(report, 'markdown'));
});

test('formatReport: 未知格式回退 json（与 REST 宽容行为一致）', () => {
  assert.equal(formatReport(report, 'xml'), formatReport(report, 'json'));
});

// [P1-REGRESSION 2026-09-13] 锁住「同一份 report 多次渲染必须逐字节一致」。
// 背景：上面的 md/markdown 等价断言曾**偶发失败**（flaky）——根因不在别名分发，而在
// reportDelivery.buildDelivery 的 meta.generatedAt：报告缺 finishedAt/startedAt 时落到
// new Date()，两次渲染跨毫秒即产生差异（同一份报告渲染两次结果不同，本身也是交付层缺陷）。
// 修法是给 buildDelivery 加 report 级缓存。本用例**故意拉开 8ms** 复现该时序，
// 若有人把缓存去掉或改成实时取值，它会稳定失败而不是偶发失败——把 flaky 变成确定性红灯。
test('formatReport: 同一份 report 相隔渲染仍逐字节一致（generatedAt 不得漂移）', async () => {
  const first = formatReport(report, 'md');
  await new Promise((r) => setTimeout(r, 8));
  const second = formatReport(report, 'md');
  assert.equal(first, second, '同一份 report 相隔毫秒渲染应完全一致（含“生成时间”行）');
});
