// ============================================================================
// findingTriage.test.js —— [D125 2026-10-22] 人工裁决的存储与报告透传
//
// 契约：
//   ① 默认 open；confirmed/false_positive/accepted_risk 持久化后读取可见；
//   ② 指纹跨复扫稳定（pointId / vuln.id 每次重生成，不能拿来当键）；
//   ③ 裁决不改 verdict/风险等级；open + 空备注 = 删除；
//   ④ CSV/Markdown/HTML/SARIF 都带裁决；SARIF 把误报映射为 external suppression。
// ============================================================================
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { attachTriage, setFindingTriage, findingKeyOf, triageStatusText } from '../src/services/findingTriage.js';
import { ReportGenerator } from '../src/services/ReportGenerator.js';
import { createInjectionPoint, createVulnerability } from '../src/engine/models.js';
import { attachVulnContext } from '../src/engine/vulnEnrich.js';

const DIR = mkdtempSync(join(tmpdir(), 'sqli-triage-'));
process.env.SQLI_TRIAGE_FILE = join(DIR, 'triage.json');
after(() => rmSync(DIR, { recursive: true, force: true }));

const URL1 = 'http://shop.example.com/item?id=1';

/** 真实工厂产出报告（与 report.sarif.test.js 同一纪律：不手写 severity/target.url）。 */
function makeReport({ scanId = 's1', url = URL1, param = 'id' } = {}) {
  const point = createInjectionPoint('url', param, '1', { actionUrl: url });
  const vuln = Object.assign(
    createVulnerability(point.id, 'boolean', 'High', ['1 AND 1=1'], '真/假响应差异'),
    { dbms: 'MySQL' }
  );
  return attachVulnContext({
    scanId,
    target: { mode: 'http', method: 'GET', baseUrl: url },
    points: [point],
    vulns: [vuln],
    data: {},
    summary: { verdict: 'vulnerability_detected' },
  });
}

test('默认无裁决 ⇒ open，summary.triage 计数完整', () => {
  const rep = attachTriage(makeReport());
  assert.equal(rep.vulns[0].triage.status, 'open');
  assert.equal(rep.vulns[0].triage.note, '');
  assert.deepEqual(rep.summary.triage, { total: 1, open: 1, confirmed: 0, falsePositive: 0, acceptedRisk: 0 });
});

test('写入 false_positive 后读取可见；复扫（新 pointId/vuln.id/原值）仍命中同一指纹', () => {
  const first = attachTriage(makeReport());
  const out = setFindingTriage({
    report: first,
    scanId: 's1',
    findingId: first.vulns[0].id,
    status: 'false_positive',
    note: '人工复现为页面差异，非注入',
  });
  assert.match(out.findingKey, /^GET http:\/\/shop\.example\.com\/item\|url\|id\|boolean$/);
  assert.equal(out.triage.status, 'false_positive');

  const readBack = attachTriage(makeReport());
  assert.equal(readBack.vulns[0].triage.status, 'false_positive');
  assert.equal(readBack.vulns[0].triage.note, '人工复现为页面差异，非注入');
  assert.deepEqual(readBack.summary.triage, { total: 1, open: 0, confirmed: 0, falsePositive: 1, acceptedRisk: 0 });
  // 裁决是标注：verdict 与风险等级不得被改写
  assert.equal(readBack.summary.verdict, 'vulnerability_detected');
  assert.equal(readBack.vulns[0].riskLevel, 'High');

  // 复扫：新 URL 原值（query 不参与指纹）+ 新 pointId/vuln.id
  const rescan = attachTriage(makeReport({ scanId: 's2', url: 'http://shop.example.com/item?id=999' }));
  assert.equal(rescan.vulns[0].findingKey, readBack.vulns[0].findingKey);
  assert.equal(rescan.vulns[0].triage.status, 'false_positive');
});

test('不同参数不串味：同站另一参数保持 open', () => {
  const rep = attachTriage(makeReport({ scanId: 's3', url: 'http://shop.example.com/item?name=x', param: 'name' }));
  assert.equal(rep.vulns[0].triage.status, 'open');
});

test('open + 空备注 = 删除裁决；非法状态/超长备注/未知 finding 明确报错', () => {
  const rep = attachTriage(makeReport());
  setFindingTriage({ report: rep, scanId: 's1', findingId: rep.vulns[0].id, status: 'confirmed', note: 'ok' });
  assert.equal(attachTriage(rep).vulns[0].triage.status, 'confirmed');
  setFindingTriage({ report: attachTriage(rep), scanId: 's1', findingId: rep.vulns[0].id, status: 'open', note: '' });
  assert.equal(attachTriage(rep).vulns[0].triage.status, 'open');

  assert.throws(
    () => setFindingTriage({ report: rep, scanId: 's1', findingId: rep.vulns[0].id, status: 'nope', note: '' }),
    /无效的裁决状态/
  );
  assert.throws(
    () => setFindingTriage({ report: rep, scanId: 's1', findingId: rep.vulns[0].id, status: 'confirmed', note: 'x'.repeat(2001) }),
    /备注过长/
  );
  assert.throws(
    () => setFindingTriage({ report: rep, scanId: 's1', findingId: 'missing', status: 'confirmed' }),
    /未找到该漏洞/
  );
});

test('findingKey 不依赖每次重生成的 id；triageStatusText 给中文展示名', () => {
  const a = makeReport({ scanId: 'a' });
  const b = makeReport({ scanId: 'b', url: 'http://shop.example.com/item?id=2' });
  assert.notEqual(a.points[0].id, b.points[0].id);
  assert.equal(findingKeyOf(a, a.vulns[0]), findingKeyOf(b, b.vulns[0]));
  assert.equal(triageStatusText('false_positive'), '误报');
  assert.equal(triageStatusText('unknown'), '待确认');
});

test('导出格式透传裁决：CSV/Markdown/HTML/SARIF（误报→external suppression）', () => {
  const rep = attachTriage(makeReport({ scanId: 'export' }));
  setFindingTriage({ report: rep, scanId: 'export', findingId: rep.vulns[0].id, status: 'false_positive', note: '页面差异' });
  const triaged = attachTriage(rep);
  const g = new ReportGenerator();

  const csv = g.toCSV(triaged);
  assert.match(csv, /裁决,裁决备注/);
  assert.match(csv, /误报/);
  assert.match(csv, /页面差异/);

  const md = g.toMarkdown(triaged);
  assert.match(md, /裁决 \| 裁决备注/);
  assert.match(md, /误报/);
  assert.match(md, /人工裁决：已确认 0 \/ 误报 1/);

  const html = g.toHTML(triaged);
  assert.match(html, /<th>裁决<\/th><th>裁决备注<\/th>/);
  assert.match(html, /页面差异/);

  const sarif = JSON.parse(g.toSARIF(triaged));
  const result = sarif.runs[0].results[0];
  assert.deepEqual(result.properties.triage, { status: 'false_positive', note: '页面差异' });
  assert.equal(result.suppressions[0].kind, 'external');
  assert.match(result.suppressions[0].justification, /页面差异/);
  assert.equal(result.partialFingerprints.findingKey, triaged.vulns[0].findingKey);
});
