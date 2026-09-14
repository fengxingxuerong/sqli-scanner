// ============================================================================
// ntlmHandshake.http.test.js —— HttpClient 层 NTLM 三步握手集成测试
// [P1-2 收尾 2026-09-14] f5c40ae 已接线（NtlmHandshake + preAuthHeader + replay），
// 但缺 HTTP 层端到端闭环测试。本套件用 mock server 钉死：
//   ① 401+Type2 → 引擎自动 Type3 → 200 全闭环（不含 Basic 头——NTLM 模式不发 Basic）
//   ② 状态复用：同主机第二请求经 preAuthHeader 直接带 Type3，不再触发新 challenge
//   ③ Type3 结构合法性（服务端解析：NTLMSSP sig + type=3）
// mock 端不校验 NT/LM response 的密码学正确性（模块级单测已钉 RFC 向量）；
// 本套件钉「握手流程与状态机」。
// ============================================================================
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { HttpClient } from '../src/core/httpClient.js';

// 构造最小合法 Type2（48 字节：sig+type2+flags+8 字节 challenge），challenge 固定可复现
function makeType2(challengeBytes) {
  const sig = Buffer.from('NTLMSSP\0', 'latin1');
  const b = Buffer.alloc(48);
  sig.copy(b, 0);
  b.writeUInt32LE(2, 8);
  b.writeUInt32LE(0x02828202, 20);
  Buffer.from(challengeBytes || [1, 2, 3, 4, 5, 6, 7, 8]).copy(b, 24);
  return b.toString('base64');
}

const isType1 = (v) => /^NTLM TlRMTVNTUAAB/i.test(v || ''); // NTLMSSP\0 + type1 的 base64 前缀
const isType3 = (v) => /^NTLM TlRMTVNTUAAD/i.test(v || ''); // NTLMSSP\0 + type3 的 base64 前缀

function startMockServer() {
  const stats = { challenges: 0, type3Seen: 0, type3Ok: 0, requests: 0 };
  const server = http.createServer((req, res) => {
    stats.requests++;
    const auth = req.headers.authorization || '';
    if (!auth || isType1(auth)) {
      // 无凭据或 Type1 → 回 Type2 挑战（统计 challenge 次数）
      stats.challenges++;
      res.writeHead(401, { 'WWW-Authenticate': `NTLM ${makeType2()}`, 'Content-Type': 'text/plain' });
      return res.end('negotiate');
    }
    if (isType3(auth)) {
      stats.type3Seen++;
      // 服务端解析 Type3：sig + type=3 才算合法
      const buf = Buffer.from(auth.slice(5), 'base64');
      const ok = buf.subarray(0, 7).toString('latin1') === 'NTLMSSP' && buf.readUInt32LE(8) === 3;
      if (ok) {
        stats.type3Ok++;
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        return res.end('AUTH-OK');
      }
      res.writeHead(401, { 'WWW-Authenticate': `NTLM ${makeType2()}` });
      return res.end('bad-type3');
    }
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm=x' });
    res.end('unknown auth');
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, stats, port: server.address().port })));
}

describe('HttpClient × NTLM 三步握手（HTTP 层集成）', () => {
  test('401+Type2 → 自动 Type3 → 200 全闭环（不发 Basic 头）', async () => {
    const { server, stats, port } = await startMockServer();
    const client = new HttpClient({ timeoutMs: 8000 });
    try {
      const res = await client.request({
        method: 'GET',
        url: `http://127.0.0.1:${port}/data`,
        auth: { type: 'ntlm', basic: { username: 'alice', password: 'secret' } },
      });
      assert.equal(res.status, 200);
      assert.equal(String(res.data), 'AUTH-OK');
      assert.equal(stats.type3Ok, 1, 'Type3 应被服务端解析为合法');
    } finally {
      await client.close?.()?.catch?.(() => {});
      server.close();
      server.closeAllConnections?.(); // [audit-FIX] keep-alive socket 不关会让 node:test 非零退出
      server.unref?.();
    }
  });

  test('状态复用：同主机第二请求经 preAuthHeader 直接带 Type3（不再触发新 challenge）', async () => {
    const { server, stats, port } = await startMockServer();
    const client = new HttpClient({ timeoutMs: 8000 });
    try {
      const auth = { type: 'ntlm', basic: { username: 'alice', password: 'secret' } };
      const r1 = await client.request({ method: 'GET', url: `http://127.0.0.1:${port}/a`, auth });
      assert.equal(r1.status, 200);
      const r2 = await client.request({ method: 'GET', url: `http://127.0.0.1:${port}/b`, auth });
      assert.equal(r2.status, 200);
      assert.equal(String(r2.data), 'AUTH-OK');
      assert.equal(stats.challenges, 1, '同主机握手应只发生一次（状态复用，challenge 不重发）');
      assert.ok(stats.type3Ok >= 2, '两次请求均应以合法 Type3 完成认证');
    } finally {
      await client.close?.()?.catch?.(() => {});
      server.close();
      server.closeAllConnections?.(); // [audit-FIX] 同上
      server.unref?.();
    }
  });
});
