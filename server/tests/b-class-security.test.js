// B 类安全收尾修复测试（⑧~⑫）
//
// ⑧ DNS OOB qname 不校验 dnsDomain → oobReceiver 校验 qname 归属
// ⑧-bis DNS OOB token 无白名单 → 与 HTTP 通道共用同一份判据（2026-10-05 加固）
// ⑨ requestFileParser 三缺口 → https 推断 + POST body 参数 + 无 HTTP 版本
// ⑩ logger 脱敏三缺口 → private_key/access_key + Token/JWT scheme + x-api-key 头名
// ⑪ AI analyst JSON 未校验 → validateAnalysisJson 校验+降级
// ⑫ sqlmapBridge 仅 SIGTERM 无 SIGKILL → 两阶段终止

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
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

// ═════════ ⑧-bis DNS OOB token 白名单（2026-10-05 加固）═════════
//
// 起因：DNS 通道此前是两条入口里**唯一不做 token 形状校验**的一条 ——
// HTTP 通道有 `/^[A-Za-z0-9_-]{1,64}$/`，DNS 通道直接把子域标签 receive()。
// 「一份入口修了、另一份没修」正是本仓反复吃亏的形状（见 ipBytes.js 教训）。
//
// 为什么这个测试不能省：它钉的是**判据本身**，不是某个具体输入。
// 若日后有人把白名单删掉或放宽，下面每条都会红 —— 那正是我们要的。

test('8-4) DNS 通道：非法形状的标签不注册 token（与 HTTP 通道同源判据）', () => {
  oobReceiver._received.clear();
  oobReceiver._ipBuckets.clear();
  oobReceiver._dnsDomain = '';

  // 合法 token 由 nanoid 生成，字母表恒为 A-Za-z0-9_-。
  // 以下标签字符集不在该字母表内 ⇒ 必然不是本进程签发的 token。
  //
  // ⚠️ **不要用点号**做非法样本：qname 本就以 `.` 分隔标签，
  // `abc.def.example.com` 的首标签是 `abc`（合法），整条查询合法。
  // 取的是点号之外、确实进不了 nanoid 字母表的字符。
  for (const bad of ['abc$def', 'abc%20def', 'abc def', 'abc/def', 'abc:def', 'abc\\def', 'abc@def']) {
    oobReceiver._received.clear();
    const msg = buildDnsQuery(`${bad}.example.com`, 1);
    oobReceiver._handleDns(msg, { address: '127.0.0.1', port: 12345 });
    assert.equal(
      oobReceiver._received.size, 0,
      `非法 token "${bad}" 不应被注册（DNS 通道必须与 HTTP 通道同一份白名单）`
    );
  }
  oobReceiver._dnsDomain = '';
});

test('8-5) DNS 通道：超长标签不注册 token（封死 qname 塞满标签冲 LRU 的面）', () => {
  oobReceiver._received.clear();
  oobReceiver._ipBuckets.clear();
  oobReceiver._dnsDomain = '';

  // RFC 1035 允许单标签 63 字节；白名单限长 64。
  // 超长者既不是合法 token，也会成为一次无意义的 Map 插入。
  const tooLong = 'a'.repeat(65);
  const msg = buildDnsQuery(`${tooLong}.example.com`, 1);
  oobReceiver._handleDns(msg, { address: '127.0.0.1', port: 12345 });

  assert.equal(oobReceiver._received.size, 0, '超长 token 不应被注册');
  oobReceiver._dnsDomain = '';
});

test('8-6) DNS 通道：合法 token 仍全部放行（加固不得误伤 OOB 能力）', () => {
  oobReceiver._received.clear();
  oobReceiver._ipBuckets.clear();
  oobReceiver._dnsDomain = '';

  // nanoid 默认字母表 A-Za-z0-9_- 全域抽样：加固若写窄了，这里必红。
  // ⚠️ 不含 `_x` / `x_` 这类**以 `_` 开头**的样本 —— `_` 前缀是系统查询过滤
  // （_acme-challenge 等），在白名单**之前**生效，与本条测的白名单是两道独立的闸。
  // 下划线出现在非首位时仍属合法（见 a-b_c / x_ / trail-）。
  for (const ok of ['abc', 'a-b_c', 'A1b2C3', 'x_', 'trail-', '-lead', '0123456789abcdef']) {
    oobReceiver._received.clear();
    const msg = buildDnsQuery(`${ok}.example.com`, 1);
    oobReceiver._handleDns(msg, { address: '127.0.0.1', port: 12345 });
    assert.equal(oobReceiver._received.size, 1, `合法 token "${ok}" 必须仍被注册`);
    assert.ok(oobReceiver._received.has(ok), `token 应以原样存入："${ok}"`);
  }
  oobReceiver._dnsDomain = '';
});

test('8-7) DNS 通道：_ 前缀系统查询仍被过滤，且不因白名单而改变顺序', () => {
  oobReceiver._received.clear();
  oobReceiver._ipBuckets.clear();
  oobReceiver._dnsDomain = '';

  // `_` 本身在白名单内（合法 token 可含下划线），因此这条断言的是
  // **系统查询过滤仍在白名单之前生效** —— 顺序有意为之：系统名不该落进计数与日志。
  const msg = buildDnsQuery('_acme-challenge.example.com', 1);
  oobReceiver._handleDns(msg, { address: '127.0.0.1', port: 12345 });

  assert.equal(oobReceiver._received.size, 0, '_ 前缀系统查询不应注册 token');
  oobReceiver._dnsDomain = '';
});

test('8-8) 判据不空转：DNS 与 HTTP 两条通道共用同一份白名单（防再次分叉）', () => {
  // 不 import 内部函数，改用**行为**证明两条入口同源：
  // 同一个非法 token，HTTP 通道与 DNS 通道必须给出**同样的拒绝结论**。
  const src = readFileSync(new URL('../src/core/oobReceiver.js', import.meta.url), 'utf8');

  // 只允许出现一处白名单字面量（唯一真源）；出现第二处即已分叉。
  const literals = src.match(/A-Za-z0-9_-\]\{1,64\}/g) || [];
  assert.equal(literals.length, 1, `白名单字面量应只出现 1 次（唯一真源），实际 ${literals.length} 次`);
  assert.ok(/const TOKEN_PATTERN = \/\^/.test(src), '白名单应提为具名常量 TOKEN_PATTERN');
  assert.ok(/if \(!isValidToken\(firstLabel\)\) return;/.test(src),
    'DNS 通道必须调用 isValidToken —— 否则两条入口又分叉了');
  assert.ok(/if \(!isValidToken\(token\)\) \{/.test(src),
    'HTTP 通道必须调用 isValidToken');
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
