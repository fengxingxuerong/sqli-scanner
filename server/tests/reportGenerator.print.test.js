import test from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';

const gen = new ReportGenerator();

// 最简报告：无 WAF、无安全间隔告警 → TOC 仅含常驻区块
const baseReport = {
  scanId: 'print-basic',
  riskLevel: 'High',
  dbms: 'MySQL',
  target: { baseUrl: 'http://t/' },
  points: [{ id: 'p1' }],
  vulns: [
    {
      id: 'v1',
      pointId: 'p1',
      technique: 'union',
      dbms: 'MySQL',
      riskLevel: 'High',
      payloads: ["1' UNION SELECT 1-- -"],
      description: '联合注入确认',
    },
  ],
  summary: { safeProbeAlerts: [], byTechnique: { union: 1 }, byRisk: { High: 1 } },
};

// 含 WAF + 安全间隔告警的报告 → TOC 额外含 sec-waf / sec-alerts
const richReport = {
  ...baseReport,
  scanId: 'print-rich',
  summary: {
    safeProbeAlerts: [
      {
        url: 'http://t/safe.php',
        reason: 'status drift',
        baselineStatus: 200,
        baselineLen: 1200,
        actualStatus: 403,
        actualLen: 512,
        ts: '2026-08-05T00:00:00Z',
      },
    ],
    byTechnique: { union: 1 },
    byRisk: { High: 1 },
    wafEvasion: { tamper: { enabled: true, plugins: ['space2comment'], intensity: 'medium' } },
    wafDetected: [{ vendor: 'Cloudflare', confidence: 0.9 }],
  },
};

test('toHTML 注入打印样式与打印按钮（@media print + .print-btn）', () => {
  const html = gen.toHTML(baseReport);
  // 打印媒体查询
  assert.match(html, /@media print/);
  // 打印时隐藏打印按钮
  assert.match(html, /\.print-btn\{display:none\}/);
  // 打印按钮存在且触发 window.print()
  assert.match(html, /class="print-btn"[^>]*onclick="window\.print\(\)"/);
  assert.match(html, /打印此报告 \/ 导出 PDF/);
});

test('toHTML 渲染目录（TOC）含常驻区块锚点', () => {
  const html = gen.toHTML(baseReport);
  // TOC 容器
  assert.match(html, /<nav class="toc" aria-label="目录">/);
  // 常驻区块锚点齐备
  assert.match(html, /href="#sec-stats"/);
  assert.match(html, /href="#sec-vulns"/);
  assert.match(html, /href="#sec-payloads"/);
  // 对应 h2 有匹配 id
  assert.match(html, /<h2 id="sec-stats">扫描统计<\/h2>/);
  assert.match(html, /<h2 id="sec-vulns">漏洞清单<\/h2>/);
  assert.match(html, /<h2 id="sec-payloads">Payload 示例<\/h2>/);
});

test('toHTML 无 WAF / 无告警时 TOC 不含 sec-waf / sec-alerts', () => {
  const html = gen.toHTML(baseReport);
  assert.doesNotMatch(html, /href="#sec-waf"/);
  assert.doesNotMatch(html, /href="#sec-alerts"/);
  assert.doesNotMatch(html, /<h2 id="sec-waf">/);
  assert.doesNotMatch(html, /<h2 id="sec-alerts">/);
});

test('toHTML 含 WAF / 告警时 TOC 自动纳入对应区块', () => {
  const html = gen.toHTML(richReport);
  assert.match(html, /href="#sec-waf"/);
  assert.match(html, /href="#sec-alerts"/);
  assert.match(html, /<h2 id="sec-waf">WAF 规避与指纹<\/h2>/);
  assert.match(html, /<h2 id="sec-alerts">安全间隔探测告警（1 条）<\/h2>/);
});

test('toHTML 渲染风险等级配色图例（四档色块）', () => {
  const html = gen.toHTML(baseReport);
  assert.match(html, /<div class="legend" aria-label="风险等级图例">/);
  // 四档风险均出现，且带对应配色 class
  for (const lv of ['critical', 'high', 'medium', 'low']) {
    assert.match(html, new RegExp(`<span class="lg ${lv}">${lv[0].toUpperCase() + lv.slice(1)}</span>`));
  }
});

test('toHTML 渲染页脚（生成时间 + 引擎版本）', () => {
  const html = gen.toHTML({ ...baseReport, finishedAt: '2026-08-05T14:00:00.000Z' });
  assert.match(html, /<footer class="rp-footer">/);
  assert.match(html, /生成时间：/);
  assert.match(html, /引擎版本 v\d+\.\d+\.\d+/);
  assert.match(html, /本报告由 SQL 注入检测引擎自动生成/);
});
