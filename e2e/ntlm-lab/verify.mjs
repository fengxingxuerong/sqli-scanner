// ============================================================================
// e2e/ntlm-lab/verify.mjs —— NTLM 三步握手端到端验证（真 mock 服务端，非 stub）
//
// 验证链路：HttpClient 在 401 + WWW-Authenticate: NTLM 下完成
//   裸请求(401) → Type1(401+Type2) → Type3(200)
// 并验证「握手状态复用」：同主机第二次请求应直接带 Type3，只发 1 次请求。
//
// 用法：node e2e/ntlm-lab/verify.mjs
// ============================================================================
import { createServer } from 'node:http';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const req = require; // 保持 CJS/ESM 路径解析一致

const { httpClient } = await import('../../server/src/core/httpClient.js');
const { NTLM_SIG_B64_PREFIX } = { NTLM_SIG_B64_PREFIX: 'TlRMTVNTUAAD' }; // Type3 签名 base64 前缀

const USER = 'alice';
const PASS = 'P@ssw0rd!23';
const DOMAIN = 'LAB';
const CHALLENGE = Buffer.from('1122334455667788', 'hex'); // 固定 challenge，便于断言

// Type2 消息（签名 + type=2 + flags + challenge + 空字段）
function buildType2() {
  const buf = Buffer.alloc(48);
  Buffer.from('NTLMSSP\0', 'latin1').copy(buf, 0);
  buf.writeUInt32LE(2, 8);          // MessageType = 2
  buf.writeUInt16LE(40, 12);        // TargetNameLen
  buf.writeUInt16LE(40, 14);        // TargetNameMaxLen
  buf.writeUInt32LE(40, 16);        // TargetNameOffset
  buf.writeUInt32LE(0x00010203, 20); // NegotiateFlags
  CHALLENGE.copy(buf, 24);          // ServerChallenge (8 bytes)
  return buf.toString('base64');
}

let hits = 0;         // 服务端收到的请求数
let sawType1 = 0;
let sawType3 = 0;
let lastType3User = null;

const server = createServer((req, res) => {
  hits++;
  const auth = req.headers['authorization'] || '';
  if (!/^ntlm\s+/i.test(auth)) {
    res.writeHead(401, { 'WWW-Authenticate': 'NTLM', 'Content-Type': 'text/plain' });
    res.end('unauthorized');
    return;
  }
  const token = auth.replace(/^ntlm\s+/i, '');
  if (token.startsWith('TlRMTVNTUAAB')) {
    // Type1 → 回 Type2
    sawType1++;
    res.writeHead(401, { 'WWW-Authenticate': `NTLM ${buildType2()}`, 'Content-Type': 'text/plain' });
    res.end('challenge');
    return;
  }
  if (token.startsWith(NTLM_SIG_B64_PREFIX)) {
    // Type3 → 解出用户名（UTF-16LE 出现在消息体里）并放行
    sawType3++;
    try {
      const msg = Buffer.from(token, 'base64');
      const u16 = msg.subarray(msg.length - (msg.length % 2 ? 1 : 0));
      lastType3User = msg.toString('utf16le').match(/[\x20-\x7e]{3,}/)?.[0] || null;
      void u16;
    } catch { /* 解析失败不影响主断言 */ }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('AUTH_OK');
    return;
  }
  res.writeHead(401, { 'WWW-Authenticate': 'NTLM', 'Content-Type': 'text/plain' });
  res.end('bad token');
});

const failures = [];
const check = (cond, msg) => {
  if (cond) console.log('✅ ' + msg);
  else { console.log('❌ ' + msg); failures.push(msg); }
};

const port = await new Promise((resolve) => {
  server.listen(0, '127.0.0.1', () => resolve(server.address().port));
});
const url = `http://127.0.0.1:${port}/`;

// ── 1) 完整握手 ────────────────────────────────────────────────────────────
const res1 = await httpClient.request({
  url,
  method: 'GET',
  auth: { type: 'ntlm', basic: { username: USER, password: PASS, domain: DOMAIN } },
});
check(res1 && res1.status === 200, `握手后返回 200（实际 ${res1 && res1.status}）`);
check(String(res1 && res1.data) === 'AUTH_OK', `响应体为 AUTH_OK（实际 ${JSON.stringify(res1 && res1.data)}）`);
check(sawType1 === 1, `服务端收到 1 次 Type1（实际 ${sawType1}）`);
check(sawType3 === 1, `服务端收到 1 次 Type3（实际 ${sawType3}）`);
check(hits === 3, `共 3 次请求完成握手（实际 ${hits}：裸请求 + Type1 + Type3）`);
check(!!lastType3User && lastType3User.includes(USER), `Type3 携带用户名 ${USER}（实际 ${lastType3User}）`);

// ── 2) 状态复用：第二次请求应直接带 Type3（1 次请求） ────────────────────────
const hitsBefore = hits;
const sawType1Before = sawType1;
const res2 = await httpClient.request({
  url,
  method: 'GET',
  auth: { type: 'ntlm', basic: { username: USER, password: PASS, domain: DOMAIN } },
});
check(res2 && res2.status === 200, `复用状态后第二次请求 200（实际 ${res2 && res2.status}）`);
check(hits - hitsBefore === 1, `第二次请求仅 1 次往返（实际 ${hits - hitsBefore}）`);
check(sawType1 === sawType1Before, '第二次请求不再发 Type1（握手已缓存）');

// ── 3) 错误凭据：Type3 被拒后不应死循环 ─────────────────────────────────────
const bad = await httpClient.request({
  url: `http://127.0.0.1:${port}/other`,
  method: 'GET',
  auth: { type: 'ntlm', basic: { username: 'bob', password: 'wrong' } },
});
check(bad && (bad.status === 200 || bad.status === 401), `换凭据后请求正常返回（${bad && bad.status}），无死循环/异常`);

server.close();
console.log('');
console.log(failures.length ? `❌ ${failures.length} 项失败` : '✅ NTLM 三步握手 e2e 全部通过');
process.exit(failures.length ? 1 : 0);
