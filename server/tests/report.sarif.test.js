// toSARIF 单测：结构合法 / rule 聚合 / severity 映射 / 点关联
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';

function makeReport() {
  return {
    scanId: 'scan1',
    target: { url: 'http://shop.example.com/item?id=1', method: 'GET', mode: 'http' },
    points: [{ id: 'pt1', param: 'id', location: 'url' }],
    vulns: [
      { pointId: 'pt1', technique: 'union', dbms: 'MySQL', severity: 'critical', evidence: 'echo marker', payloads: ["1 UNION SELECT"] },
      { pointId: 'pt1', technique: 'error', dbms: 'MySQL', severity: 'medium', evidence: 'SQL syntax', payloads: ["'"] },
    ],
    data: {},
  };
}

test('toSARIF：SARIF 2.1.0 结构 + rules 按 technique 聚合', () => {
  const g = new ReportGenerator();
  const sarif = JSON.parse(g.toSARIF(makeReport()));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].tool.driver.name, 'sqli-scanner');
  assert.equal(sarif.runs[0].results.length, 2);
  // 两个 technique → 两条 rule
  assert.equal(sarif.runs[0].tool.driver.rules.length, 2);
  const ids = sarif.runs[0].tool.driver.rules.map((r) => r.id);
  assert.ok(ids.includes('SQLI-UNION') && ids.includes('SQLI-ERROR'));
});

test('toSARIF：severity 映射 critical→error / medium→warning', () => {
  const g = new ReportGenerator();
  const sarif = JSON.parse(g.toSARIF(makeReport()));
  const levels = sarif.runs[0].results.map((r) => r.level);
  assert.deepEqual(levels, ['error', 'warning']);
});

test('toSARIF：result 关联 point（uri/param 指纹）', () => {
  const g = new ReportGenerator();
  const sarif = JSON.parse(g.toSARIF(makeReport()));
  const r0 = sarif.runs[0].results[0];
  assert.ok(r0.locations[0].physicalLocation.artifactLocation.uri.includes('/item'));
  assert.equal(r0.partialFingerprints.scanPointId, 'pt1');
  assert.equal(r0.properties.dbms, 'MySQL');
});

test('toSARIF：空漏洞列表也输出合法 SARIF', () => {
  const g = new ReportGenerator();
  const rep = makeReport();
  rep.vulns = [];
  const sarif = JSON.parse(g.toSARIF(rep));
  assert.equal(sarif.runs[0].results.length, 0);
  assert.equal(sarif.runs[0].tool.driver.rules.length, 0);
});
