// [D242 对标 sqlmap --check-internet] 本机联网自检的判据
//
// 钉三条失效方向：
//   ① 可达 ⇒ ok=true 且 via 指向命中的那个探测点（不是笼统 true）；
//   ② 全部不可达 ⇒ ok=false，且 tried 原样带出（用户要看到"试了哪些"）；
//   ③ 多探测点时**任一通即 ok** —— 单点被墙/被拦不该误报成"本机断网"。
// 口径边界：本探测只回答"本机有没有到 DNS 的 TCP 通路"，不回答"目标是否可达"，
// 所以这里不测任何 HTTP 语义。
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';

import { probeInternet } from '../src/core/netProbe.js';

let srv;
let port;

before(async () => {
  srv = net.createServer(() => { /* 只要 accept 就算通，不发数据 */ });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  port = srv.address().port;
});
after(() => { try { srv.close(); } catch { /* noop */ } });

test('探测点可达 ⇒ ok=true 且 via 指向命中点', async () => {
  const r = await probeInternet({ probes: [`127.0.0.1:${port}`], timeoutMs: 500 });
  assert.equal(r.ok, true);
  assert.equal(r.via, `127.0.0.1:${port}`);
});

test('全部不可达 ⇒ ok=false，tried 原样带出', async () => {
  const r = await probeInternet({ probes: ['127.0.0.1:1'], timeoutMs: 300 });
  assert.equal(r.ok, false);
  assert.equal(r.via, null);
  assert.deepEqual(r.tried, ['127.0.0.1:1']);
});

test('多探测点：前一个不通、后一个通 ⇒ ok=true（单点被拦不误报）', async () => {
  const r = await probeInternet({
    probes: ['127.0.0.1:1', `127.0.0.1:${port}`],
    timeoutMs: 300,
  });
  assert.equal(r.ok, true);
  assert.equal(r.via, `127.0.0.1:${port}`);
});

test('畸形探测点被跳过而不是抛错（配置写错不该让扫描起不来）', async () => {
  const r = await probeInternet({ probes: ['no-port', `127.0.0.1:${port}`], timeoutMs: 300 });
  assert.equal(r.ok, true);
});
