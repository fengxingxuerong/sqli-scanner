// ============================================================================
// tests/poc.redact.test.js —— PoC 凭据脱敏开关回归 [P0-SEC 2026-09-08]
//
// 为什么单独成测：PoC 的默认语义是「复制即跑」，因此 Cookie/Authorization 必须原样带出；
// 但报告文件会随邮件/IM 流通，测试者的会话凭据写进去就是自我泄露。两条诉求冲突，
// 用 config.pocRedactAuth 把选择权交给部署方——本测试锁住「默认不脱敏、开启后三处一致脱敏」。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildPocEvidence } from '../src/engine/pocBuilder.js';
import { ReportGenerator } from '../src/services/ReportGenerator.js';

const rg = new ReportGenerator();

const target = (extra = {}) => ({
  mode: 'http',
  baseUrl: 'http://t.local/item?id=1',
  method: 'GET',
  bodyParams: {},
  cookieParams: { session: 'SECRETSID123' },
  headerParams: { 'X-Api-Key': 'AK-SECRET-9' },
  config: {},
  ...extra,
});
const point = { id: 'p1', location: 'url', param: 'id', originalValue: '1' };
const PAYLOAD = "1' AND 1=1-- -";

test('默认（pocRedactAuth 未开）：PoC 原样带出凭据，保证复制即跑', () => {
  const poc = buildPocEvidence(target(), point, PAYLOAD);
  assert.equal(poc.headers.Cookie, 'session=SECRETSID123');
  assert.ok(poc.curl.includes('session=SECRETSID123'), 'curl 必须可直接执行');
});

test('开启 pocRedactAuth：headers / curl / raw 三处一致脱敏（不能只脱一处）', () => {
  const poc = buildPocEvidence(target(), point, PAYLOAD, { redactAuth: true });
  for (const field of [JSON.stringify(poc.headers), poc.curl, poc.raw]) {
    assert.ok(!field.includes('SECRETSID123'), `会话凭据应被脱敏，实际：${field.slice(0, 160)}`);
    assert.ok(!field.includes('AK-SECRET-9'), `自定义凭据头应被脱敏，实际：${field.slice(0, 160)}`);
  }
  // 结构仍在：脱敏不能把 -H 'Cookie: ...' 整段抹掉，否则复现者不知道该补什么
  assert.match(poc.curl, /-H 'Cookie: <[^>]+>'/);
  assert.match(poc.raw, /^Cookie: <[^>]+>$/m);
  assert.match(poc.note, /脱敏/);
});

test('报告侧接线：report.target.config.pocRedactAuth=true 时导出内容不含凭据', () => {
  const report = {
    scanId: 's1',
    target: { ...target(), url: 'http://t.local/item?id=1', config: { pocRedactAuth: true } },
    points: [point],
    vulns: [{ id: 'v1', pointId: 'p1', technique: 'boolean', riskLevel: 'High', payloads: [PAYLOAD], description: 'x' }],
    data: null,
    summary: {},
  };
  const md = rg.toMarkdown(rg.attachPoc(report));
  assert.ok(!md.includes('SECRETSID123'), '导出报告不得残留会话凭据');
  assert.ok(/curl /.test(md), 'PoC 区块仍应存在');

  const plain = rg.toMarkdown(rg.attachPoc({ ...report, target: { ...report.target, config: {} } }));
  assert.ok(plain.includes('session=SECRETSID123'), '未开启时保持可复现语义（默认不变）');
});
