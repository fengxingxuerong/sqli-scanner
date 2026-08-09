// ReportGenerator 单元测试：风险定级规则 + build/toJSON/toHTML
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';

const rg = new ReportGenerator();

// mk 构造一个最小漏洞对象；riskOf 只看 technique，不看 riskLevel 字段
const mk = (technique, riskLevel = 'Medium') => ({
  pointId: 'p',
  technique,
  dbms: 'MySQL',
  riskLevel,
  payloads: [],
  description: '',
});

test('riskOf: 含 union 漏洞 → High', () => {
  assert.equal(rg.riskOf([mk('union')]), 'High');
});

test('riskOf: 含 error 漏洞 → High', () => {
  assert.equal(rg.riskOf([mk('error')]), 'High');
});

test('riskOf: 仅 boolean 漏洞 → Medium', () => {
  assert.equal(rg.riskOf([mk('boolean')]), 'Medium');
});

test('riskOf: 仅 time 漏洞 → Medium', () => {
  assert.equal(rg.riskOf([mk('time')]), 'Medium');
});

test('riskOf: 有可提取数据 → Critical（覆盖一切）', () => {
  const data = { databases: ['a'], tables: {}, columns: {}, rows: {} };
  assert.equal(rg.riskOf([], data), 'Critical');
  assert.equal(rg.riskOf([mk('boolean')], data), 'Critical');
});

test('riskOf: 空漏洞数组 → Low（疑似/无）', () => {
  assert.equal(rg.riskOf([]), 'Low');
});

test('riskOf: 未知技术漏洞 → Low', () => {
  assert.equal(rg.riskOf([mk('suspicious')]), 'Low');
});

test('riskOf: 多技术取最高级', () => {
  // union(High) + boolean(Medium) → High
  assert.equal(rg.riskOf([mk('boolean'), mk('union')]), 'High');
  // error(High) + time(Medium) → High
  assert.equal(rg.riskOf([mk('time'), mk('error')]), 'High');
});

test('build 生成 summary 并按风险汇总', () => {
  const report = rg.build(
    's1',
    { baseUrl: 'http://x' },
    [{ id: 'p1' }],
    [mk('union', 'High'), mk('boolean', 'Medium')],
    null
  );
  assert.equal(report.scanId, 's1');
  assert.equal(report.riskLevel, 'High');
  assert.equal(report.summary.totalPoints, 1);
  assert.equal(report.summary.totalVulns, 2);
  assert.equal(report.summary.byTechnique.union, 1);
  assert.equal(report.summary.byTechnique.boolean, 1);
  assert.equal(report.summary.byRisk.High, 1);
  assert.equal(report.summary.byRisk.Medium, 1);
});

test('build 汇总 dbms 列表', () => {
  const report = rg.build(
    's2',
    { baseUrl: 'http://x' },
    [],
    [mk('union'), mk('error')],
    null
  );
  // 两个漏洞 dbms 都是 'MySQL'
  assert.equal(report.dbms, 'MySQL');
});

test('toJSON 返回可解析 JSON 且含关键字段', () => {
  const json = rg.toJSON(rg.build('s1', { baseUrl: 'http://x' }, [], [mk('error', 'High')], null));
  const obj = JSON.parse(json);
  assert.equal(obj.riskLevel, 'High');
  assert.equal(obj.scanId, 's1');
});

test('toHTML 含风险等级且转义危险字符', () => {
  const html = rg.toHTML(rg.build('s1', { baseUrl: 'http://x<a>' }, [], [mk('error', 'High')], null));
  assert.match(html, /SQL 注入检测报告/);
  assert.match(html, /High/);
  // 尖括号被转义，不应原样出现
  assert.ok(!html.includes('<a>'));
});
