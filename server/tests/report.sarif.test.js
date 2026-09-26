// toSARIF 单测：结构合法 / rule 聚合 / 严重级映射 / 点关联
// ============================================================================
// ⚠ 夹具必须由**真实工厂 + 真实富化路径**产出（createInjectionPoint / createVulnerability /
//   attachVulnContext），不许再手写字面量。
//
// 为什么专门写这条规矩：上一版夹具手写的是 `severity` 和 `target.url` —— **引擎从不产出这两个
// 字段**（漏洞模型写 `riskLevel`，models.js:215-227；target 上是 `baseUrl`，point 上是
// `actionUrl`）。于是「severity 映射 critical→error / medium→warning」这条断言一直是绿的，
// 而真实导出物里每条 finding 都是 error、uri 全是 "/"：
//   reports/127.0.0.1-2026-09-17T13-51-34/report.sarif —— 3 条 vuln，riskLevel 为
//   High/High/Medium，导出的 level 却全是 error；同一份 report.json 里 vuln.url 是
//   http://127.0.0.1:8130/items?cat=1，导出的 uri 却是 "/"。
// **测试全绿 + 生产产物全错**，根因是夹具替产品发明了一套字段名。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';
import { createInjectionPoint, createVulnerability } from '../src/engine/models.js';
import { attachVulnContext } from '../src/engine/vulnEnrich.js';

const ITEM_URL = 'http://shop.example.com/item?id=1';

function makeReport() {
  const point = createInjectionPoint('url', 'id', '1', { actionUrl: ITEM_URL });
  const vulns = [
    // riskLevel 用**生产里真实的大小写**（产物里就是 'High'/'Medium' 首字母大写），
    // 顺带把 toLowerCase 那条归一也踩到
    Object.assign(createVulnerability(point.id, 'union', 'Critical', ['1 UNION SELECT'], 'echo marker'), { dbms: 'MySQL' }),
    Object.assign(createVulnerability(point.id, 'error', 'Medium', ["'"], 'SQL syntax'), { dbms: 'MySQL' }),
  ];
  const report = {
    scanId: 'scan1',
    target: { mode: 'http', method: 'GET', baseUrl: ITEM_URL },
    points: [point],
    vulns,
    data: {},
  };
  // 走产品真实的富化路径：vuln.url 是这里填进去的（vulnEnrich.js:80-82）。
  // ⚠ 它**返回新报告**（`touched ? {...report, vulns: out}`），不是就地改 —— 丢返回值就等于
  // 没富化，vuln.url 会静默为空（我自己在这行上踩了一次，症状是"地址断言红"）。
  return attachVulnContext(report);
}

test('夹具钉住模型契约：漏洞对象带 riskLevel、不带 severity', () => {
  const rep = makeReport();
  assert.ok(rep.vulns.every((v) => typeof v.riskLevel === 'string' && v.riskLevel),
    '夹具里的 vuln 没有 riskLevel —— 那就是又在发明字段');
  assert.ok(rep.vulns.every((v) => !('severity' in v)),
    '引擎不产出 severity；夹具一旦带上它，SARIF 映射测试就会变成假绿');
  assert.ok(rep.vulns.every((v) => typeof v.url === 'string' && v.url.includes('/item')),
    'attachVulnContext 应把受影响地址填进 vuln.url（SARIF/CSV 都读这个）');
});

test('toSARIF：SARIF 2.1.0 结构 + rules 按 technique 聚合', () => {
  const g = new ReportGenerator();
  const sarif = JSON.parse(g.toSARIF(makeReport()));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs.length, 1);
  assert.equal(sarif.runs[0].tool.driver.name, 'sqli-scanner');
  assert.equal(sarif.runs[0].results.length, 2);
  const ids = sarif.runs[0].tool.driver.rules.map((r) => r.id);
  assert.ok(ids.includes('SQLI-UNION') && ids.includes('SQLI-ERROR'));
});

test('toSARIF：严重级按 riskLevel 映射 Critical→error / Medium→warning', () => {
  const g = new ReportGenerator();
  const sarif = JSON.parse(g.toSARIF(makeReport()));
  const levels = sarif.runs[0].results.map((r) => r.level);
  assert.deepEqual(levels, ['error', 'warning'],
    '全 error = 映射读错了字段（历史实况：消费方会把 Medium 当严重项分诊）');
});

test('toSARIF：result 关联 point（uri/param 指纹）', () => {
  const g = new ReportGenerator();
  const sarif = JSON.parse(g.toSARIF(makeReport()));
  for (const r of sarif.runs[0].results) {
    const uri = r.locations[0].physicalLocation.artifactLocation.uri;
    assert.ok(uri.includes('/item'), `uri 丢了受影响地址（历史实况：全是 "/"）→ ${uri}`);
  }
  assert.equal(sarif.runs[0].results[0].partialFingerprints.scanPointId, makeReport().points[0].id);
  assert.equal(sarif.runs[0].results[0].properties.dbms, 'MySQL');
});

test('toSARIF：空漏洞列表也输出合法 SARIF', () => {
  const g = new ReportGenerator();
  const rep = makeReport();
  rep.vulns = [];
  const sarif = JSON.parse(g.toSARIF(rep));
  assert.equal(sarif.runs[0].results.length, 0);
  assert.equal(sarif.runs[0].tool.driver.rules.length, 0);
});
