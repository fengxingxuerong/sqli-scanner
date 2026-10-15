// ============================================================================
// vulnEnrich.cvss.test.js —— [D82] 引擎原始报告必须自带 CVSS（README 交付契约）
// ============================================================================
// 实测缺陷（一次真扫交付物核查）：report.json 的三条 vulns 全无 cvss 字段，
// 而 report.md / report.html 有（union 8.2 / boolean 7.5）——CVSS 只活在渲染链路
// （reportDelivery.buildDelivery），引擎回填链路（vulnEnrich）漏了。
// README 的口径是「每条漏洞必含 风险等级 + CVSS v3.1，**全部格式**」⇒ 属契约违反。
// 修法：在 enrichVuln 回填 affectedParam 的同一处补 cvssFor(vuln)（单一真源复用）。
// 本文件钉三件事：三件套齐全 / 幂等不覆盖 / 不写回输入（poc.evidence 既有契约）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { enrichVuln, attachVulnContext } from '../src/engine/vulnEnrich.js';

test('D82：无 cvss 的条目被回填 score/severity/vector 三件套（union=8.2/High）', () => {
  const v = enrichVuln(
    { technique: 'union', pointId: 'p1' },
    { id: 'p1', param: 'cat', location: 'query' },
    { url: 'http://t/' },
  );
  assert.ok(v.cvss, 'cvss 字段必须存在');
  assert.equal(v.cvss.score, 8.2);
  assert.equal(v.cvss.severity, 'High');
  assert.match(v.cvss.vector, /^AV:N/);
});

test('D82：外部显式给定的 cvss 不被覆盖（幂等）；未知技术落保守默认 5.3', () => {
  const given = { score: 10, vector: 'custom' };
  const v = enrichVuln({ technique: 'union', cvss: given }, null, null);
  assert.deepEqual(v.cvss, given);

  const unknown = enrichVuln({ technique: 'mystery-channel' }, null, null);
  assert.equal(unknown.cvss.score, 5.3);
  assert.equal(unknown.cvss.severity, 'Medium');
});

test('D82：不写回输入对象（poc.evidence「导出不得给输入 vuln 挂字段」契约不破）', () => {
  const input = { technique: 'union' };
  const out = enrichVuln(input, null, null);
  assert.ok(!('cvss' in input), '输入对象不得被挂字段');
  assert.ok(out.cvss, '返回的浅拷贝带 cvss');
});

test('D82：attachVulnContext 整报告路径同样回填（引擎 report.json 消费方）', () => {
  const report = attachVulnContext({
    vulns: [{ technique: 'boolean', pointId: 'p1' }, { technique: 'union', pointId: 'p1' }],
    points: [{ id: 'p1', param: 'cat', location: 'query' }],
    target: { url: 'http://t/' },
  });
  assert.equal(report.vulns[0].cvss.score, 7.5);
  assert.equal(report.vulns[1].cvss.score, 8.2);
});
