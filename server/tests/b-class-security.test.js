// B 类安全收尾修复测试（⑧~⑫）
//
// ⑧ DNS OOB qname 不校验 dnsDomain → oobReceiver 校验 qname 归属
// ⑨ requestFileParser 三缺口 → https 推断 + POST body 参数 + 无 HTTP 版本
// ⑩ logger 脱敏三缺口 → private_key/access_key + Token/JWT scheme + x-api-key 头名
// ⑪ AI analyst JSON 未校验 → validateAnalysisJson 校验+降级
// ⑫ sqlmapBridge 仅 SIGTERM 无 SIGKILL → 两阶段终止

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { oobReceiver } from '../src/core/oobReceiver.js';
import { redact, redactHeaders } from '../src/core/logger.js';
import { parseRequestFile } from '../src/core/requestFileParser.js';
import { validateAnalysisJson } from '../src/services/ReportAI.js';
import { SqlmapBridge } from '../src/engine/sqlmapBridge.js';

// ─── 辅助：构造 DNS 查询报文 ───
function buildDnsQuery(qname, qtype = 1) {
  const labels = qname.split('.');
  const parts = [];
  for (const label of labels) {
    parts.push(Buffer.from([label.length]));
    parts.push(Buffer.from(label, 'ascii'));
  }
  parts.push(Buffer.from([0])); // 根标签
  const qnameBuf = Buffer.concat(parts);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0); // ID
  header.writeUInt16BE(0x0100, 2); // Flags: standard query, RD
  header.writeUInt16BE(1, 4); // QDCOUNT
  const typeClass = Buffer.alloc(4);
  typeClass.writeUInt16BE(qtype, 0); // QTYPE
  typeClass.writeUInt16BE(1, 2); // QCLASS = IN
  return Buffer.concat([header, qnameBuf, typeClass]);
}

// ═════════ ⑧ DNS OOB qname 校验 dnsDomain ═════════

test('8-1) 不匹配 dnsDomain 的 DNS 查询不触发 receive', () => {
  oobReceiver._received.clear();
  oobReceiver._ipBuckets.clear();
  oobReceiver._dnsDomain = 'oob.example.com';

  const msg = buildDnsQuery('abc.evil.com', 1);
  const rinfo = { address: '127.0.0.1', port: 12345 };
  oobReceiver._handleDns(msg, rinfo);

  assert.equal(oobReceiver._received.size, 0, '不匹配 dnsDomain 的查询不应注册 token');
});

test('8-2) 匹配 dnsDomain 的 DNS 查询触发 receive', () => {
  oobReceiver._received.clear();
  oobReceiver._ipBuckets.clear();
  oobReceiver._dnsDomain = 'oob.example.com';

  const msg = buildDnsQuery('abc.oob.example.com', 1);
  const rinfo = { address: '127.0.0.1', port: 12345 };
  oobReceiver._handleDns(msg, rinfo);

  assert.equal(oobReceiver._received.size, 1, '匹配 dnsDomain 的查询应注册 token');
  assert.ok(oobReceiver._received.has('abc'), 'token 应为 abc');
});

test('8-3) 未配置 dnsDomain 时仍接受所有查询（向后兼容）', () => {
  oobReceiver._received.clear();
  oobReceiver._ipBuckets.clear();
  oobReceiver._dnsDomain = '';

  const msg = buildDnsQuery('anything.anywhere.com', 1);
  const rinfo = { address: '127.0.0.1', port: 12345 };
  oobReceiver._handleDns(msg, rinfo);

  assert.equal(oobReceiver._received.size, 1, '未配置 dnsDomain 时应接受所有查询');
  oobReceiver._dnsDomain = ''; // 清理
});

// ═════════ ⑨ requestFileParser 三缺口 ═════════

test('9-1) Host:443 -> 推断 https 协议', () => {
  const text = [
    'GET /api?id=1 HTTP/1.1',
    'Host: example.com:443',
    '',
  ].join('\r\n');
  const r = parseRequestFile(text);
  assert.ok(r);
  assert.ok(r.url.startsWith('https://'), '端口 443 应使用 https');
  assert.equal(r.url, 'https://example.com:443/api?id=1');
});

test('9-2) POST body 参数提取到 params', () => {
  const text = [
    'POST /login HTTP/1.1',
    'Host: 127.0.0.1:8123',
    'Content-Type: application/x-www-form-urlencoded',
    '',
    'user=admin&pass=secret',
  ].join('\r\n');
  const r = parseRequestFile(text);
  assert.ok(r);
  assert.equal(r.params.user, 'admin');
  assert.equal(r.params.pass, 'secret');
});

test('9-3) 无 HTTP 版本的请求行也能解析', () => {
  const text = [
    'GET /path?id=1',
    'Host: 127.0.0.1:8123',
    '',
  ].join('\r\n');
  const r = parseRequestFile(text);
  assert.ok(r, '无 HTTP 版本的请求行应可解析');
  assert.equal(r.method, 'GET');
  assert.equal(r.url, 'http://127.0.0.1:8123/path?id=1');
});

// ═════════ ⑩ logger 脱敏三缺口 ═════════

test('10-1) private_key/access_key/client_secret 键值打码', () => {
  assert.ok(redact('private_key=abc123').includes('***'));
  assert.ok(redact('access_key=xyz789').includes('***'));
  assert.ok(redact('client_secret=mypwd').includes('***'));
  assert.ok(redact('secret_key=topsecret').includes('***'));
  assert.ok(redact('client_id=myid123').includes('***'));
});

test('10-2) Authorization: Token/JWT/Negotiate/ApiKey scheme 打码', () => {
  assert.ok(redact('Authorization: Token abc123').includes('***'));
  assert.ok(redact('Authorization: JWT eyJhb.abc').includes('***'));
  assert.ok(redact('Authorization: Negotiate dGlcw==').includes('***'));
  assert.ok(redact('Authorization: ApiKey mykey').includes('***'));
});

test('10-3) x-api-key/x-auth-token 头名整体打码', () => {
  const headers = {
    'X-Api-Key': 'secret-key-123',
    'X-Auth-Token': 'bearer-token-456',
    'Content-Type': 'application/json',
  };
  const redacted = redactHeaders(headers);
  assert.equal(redacted['X-Api-Key'], '***');
  assert.equal(redacted['X-Auth-Token'], '***');
  assert.equal(redacted['Content-Type'], 'application/json', '非敏感头不应打码');
});

// ═════════ ⑪ AI analyst JSON 校验 ═════════

test('11-1) 合法 JSON -> 提取结构化 JSON', () => {
  const input = JSON.stringify({
    vulns: [{ name: 'SQL注入', risk: '高危' }],
    overall_risk: '高危',
    impact_summary: '数据泄露风险',
  });
  const result = validateAnalysisJson(input);
  const parsed = JSON.parse(result);
  assert.ok(Array.isArray(parsed.vulns));
  assert.equal(parsed.overall_risk, '高危');
});

test('11-2) markdown 包裹的 JSON -> 提取', () => {
  const input = '```json\n{"vulns":[],"overall_risk":"中危"}\n```';
  const result = validateAnalysisJson(input);
  const parsed = JSON.parse(result);
  assert.equal(parsed.overall_risk, '中危');
});

test('11-3) 非 JSON -> 降级为带警告标记的原始文本', () => {
  const input = '这不是 JSON，是 LLM 的自由文本回答';
  const result = validateAnalysisJson(input);
  assert.ok(result.includes('注意'), '应包含警告标记');
  assert.ok(result.includes('可能不可信'), '应标注不可信');
  assert.ok(result.includes(input), '应保留原始文本');
});

test('11-4) JSON 结构不完整（缺少 vulns/overall_risk）-> 标注警告', () => {
  const input = JSON.stringify({ foo: 'bar' });
  const result = validateAnalysisJson(input);
  assert.ok(result.includes('注意'), '应包含警告标记');
  assert.ok(result.includes('结构不完整'), '应标注结构不完整');
});

// ═════════ ⑫ sqlmapBridge 两阶段终止 ═════════

test('12-1) _killProcess: 立即发 SIGTERM', () => {
  const calls = [];
  const fakeChild = {
    kill(signal) { calls.push(signal); return true; },
  };
  const bridge = new SqlmapBridge();
  bridge._killProcess(fakeChild);
  assert.equal(calls[0], 'SIGTERM', '应立即发 SIGTERM');
});

test('12-2) _killProcess: 5s 后升级 SIGKILL', async () => {
  const calls = [];
  const fakeChild = {
    kill(signal) { calls.push(signal); return true; },
  };
  const bridge = new SqlmapBridge();
  bridge._killProcess(fakeChild);
  assert.equal(calls[0], 'SIGTERM');
  await new Promise(r => setTimeout(r, 5100));
  assert.ok(calls.includes('SIGKILL'), '5s 后应升级到 SIGKILL');
});
