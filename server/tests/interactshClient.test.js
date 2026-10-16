// ============================================================================
// interactshClient.test.js —— [D87] 外部 OOB 隧道（interactsh 协议）单测
//
// 判据来源：全部为本批**整链真机实测**踩到的点（不是推测），每条都写明反例后果：
//   · 首标签长度 < 33 ⇒ 服务端滑窗匹配不到 correlationID ⇒ poll 恒空
//     （实测 20/26/31/32 全失败、33/34/36 成功；本文件用边界断言钉住）
//   · DNS 不区分大小写 ⇒ 服务端存的回连记录恒为小写，而 token 是 nanoid（含大写）
//     ⇒ 不归一化则「隧道通了却恒不命中」（实测靶站回连 14 次、本地 received 恒 0）
//   · 归因必须限定本次会话前缀 ⇒ 否则同协作端其它会话的流量会被误认成自己的命中（误报）
//   · AES-256-CTR + IV 前置 + RSA-OAEP(SHA-256) 解 key：协议形态错则解密失败
//
// 离线：用**本地 mock 协作端**（不访问公网），故可进 CI 常驻门禁。
// 真机侧由 e2e/oob-interactsh-lab/run.mjs 承担（网络门控 + 按设计跳过）。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import {
  InteractshClient,
  decryptInteraction,
  unwrapAesKey,
  MIN_FIRST_LABEL_LENGTH,
  DEFAULT_SERVERS,
} from '../src/core/interactshClient.js';

/** 起一个 mock 协作端：实现 register/poll/deregister，并可按需注入交互记录 */
function startMockServer({ interactions = null } = {}) {
  const reg = { correlationId: '', secret: '', aesKey: null };
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    if (req.method === 'POST' && u.pathname === '/register') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const j = JSON.parse(body);
        reg.correlationId = j['correlation-id'];
        reg.secret = j['secret-key'];
        res.statusCode = 200;
        res.end('{"message":"registration successful"}');
      });
      return;
    }
    if (u.pathname === '/poll') {
      const data = interactions ? interactions(reg) : [];
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ aes_key: reg.aesKey || '', data }));
      return;
    }
    if (u.pathname === '/deregister') {
      res.statusCode = 200;
      res.end('{"message":"deregistration successful"}');
      return;
    }
    res.statusCode = 404;
    res.end('nf');
  });
  return {
    reg,
    listen: () => new Promise((r) => server.listen(0, '127.0.0.1', r)),
    port: () => server.address().port,
    close: () => new Promise((r) => server.close(r)),
  };
}

/** 按 interactsh 协议加密一条交互记录：AES-256-CTR(IV 前置) + RSA-OAEP(SHA-256) 包 key */
function encodeInteraction(publicKeyPem, plaintext) {
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-ctr', aesKey, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  const data = Buffer.concat([iv, ct]).toString('base64');
  const aesKeyB64 = crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    aesKey
  ).toString('base64');
  return { aesKeyB64, data };
}

test('解密：AES-256-CTR IV 前置 + RSA-OAEP(SHA-256) 解 key 往返一致', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const { aesKeyB64, data } = encodeInteraction(publicKey, '{"full-id":"abc.oast.pro"}');
  const key = unwrapAesKey(privateKey, aesKeyB64);
  assert.equal(key.length, 32);
  assert.equal(decryptInteraction(key, data), '{"full-id":"abc.oast.pro"}');
});

test('解密：密文短于一个 IV 块必须报错（不静默返回空串）', () => {
  const key = crypto.randomBytes(32);
  assert.throws(() => decryptInteraction(key, Buffer.alloc(8).toString('base64')));
});

test('域名形态：首标签 = correlationId(20) + nonce(13)，长度 = 33', async () => {
  const mock = startMockServer();
  await mock.listen();
  const c = new InteractshClient();
  await c.start({ server: `http://127.0.0.1:${mock.port()}`, pollIntervalMs: 60000 });
  const domain = c.callbackDomain();
  const label = domain.split('.')[0];
  assert.equal(label.length, MIN_FIRST_LABEL_LENGTH);
  assert.equal(MIN_FIRST_LABEL_LENGTH, 33);
  assert.equal(label, mock.reg.correlationId + c._nonce);
  // token 拼在前缀之后，首标签更长 ⇒ 仍满足阈值
  assert.ok(c.hostForToken('abc').split('.')[0].length > MIN_FIRST_LABEL_LENGTH);
  await c.stop();
  await mock.close();
});

test('归因：回连记录含大写 token 也能命中（DNS 大小写不敏感回归）', async () => {
  const mock = startMockServer();
  await mock.listen();
  const c = new InteractshClient();
  await c.start({ server: `http://127.0.0.1:${mock.port()}`, pollIntervalMs: 60000 });
  // 检测器投放的 token 含大小写混合（nanoid 真实形态）
  const token = 'AbC123xYz';
  const stored = `${c._domainPrefix()}${token.toLowerCase()}`;
  mock.reg.aesKey = '';
  const { aesKeyB64, data } = (() => {
    // 用当前客户端私钥能解的方式构造：直接复用类内私钥
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-ctr', aesKey, iv);
    const ct = Buffer.concat([
      cipher.update(Buffer.from(JSON.stringify({ 'full-id': `${stored}.oast.pro`, protocol: 'dns' }), 'utf8')),
      cipher.final(),
    ]);
    return {
      aesKeyB64: crypto.publicEncrypt(
        { key: c._publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
        aesKey
      ).toString('base64'),
      data: Buffer.concat([iv, ct]).toString('base64'),
    };
  })();
  mock.reg.aesKey = aesKeyB64;
  const row = data;
  // 直接驱动一次 poll 处理（避免依赖定时器）
  const origFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ aes_key: aesKeyB64, data: [row] }), { status: 200 });
  try {
    await c._pollOnce();
  } finally {
    globalThis.fetch = origFetch;
  }
  assert.equal(c._received.has(token.toLowerCase()), true);
  // 检测器用原始大小写等待，也必须命中（归一化两侧一致）
  assert.equal(await c.waitForToken(token, 100), true);
  await c.stop();
  await mock.close();
});

test('归因：非本次会话前缀的回连记录必须丢弃（防把他人流量认成命中）', async () => {
  const mock = startMockServer();
  await mock.listen();
  const c = new InteractshClient();
  await c.start({ server: `http://127.0.0.1:${mock.port()}`, pollIntervalMs: 60000 });
  const alien = JSON.stringify({ 'full-id': 'deadbeefdeadbeefdeadbeefdeadbeef.oast.pro', protocol: 'dns' });
  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-ctr', aesKey, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(alien, 'utf8')), cipher.final()]);
  const aesKeyB64 = crypto.publicEncrypt(
    { key: c._publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    aesKey
  ).toString('base64');
  const row = Buffer.concat([iv, ct]).toString('base64');
  const origFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({ aes_key: aesKeyB64, data: [row] }), { status: 200 });
  try {
    await c._pollOnce();
  } finally {
    globalThis.fetch = origFetch;
  }
  assert.equal(c._received.size, 0);
  await c.stop();
  await mock.close();
});

test('start：逐协作端尝试，首个成功即生效；全失败则抛错', async () => {
  const mock = startMockServer();
  await mock.listen();
  const c = new InteractshClient();
  // 第一个是死端口，第二个可用 ⇒ 应成功并绑定第二个
  await c.start({
    servers: ['http://127.0.0.1:1', `http://127.0.0.1:${mock.port()}`],
    pollIntervalMs: 60000,
  });
  assert.equal(c.isStarted(), true);
  assert.match(c._server, new RegExp(String(mock.port())));
  await c.stop();
  await mock.close();

  const c2 = new InteractshClient();
  await assert.rejects(
    () => c2.start({ servers: ['http://127.0.0.1:1', 'http://127.0.0.1:2'], pollIntervalMs: 60000 }),
    /interactsh 注册失败/
  );
});

test('waitForToken：超时返回 false；receive 后立即返回 true', async () => {
  const mock = startMockServer();
  await mock.listen();
  const c = new InteractshClient();
  await c.start({ server: `http://127.0.0.1:${mock.port()}`, pollIntervalMs: 60000 });
  assert.equal(await c.waitForToken('NOPE', 80), false);
  c.receive('HitToken');
  assert.equal(await c.waitForToken('hittoken', 80), true);
  await c.stop();
  await mock.close();
});

test('stop：注销协作端并清空本地状态', async () => {
  const mock = startMockServer();
  await mock.listen();
  const c = new InteractshClient();
  await c.start({ server: `http://127.0.0.1:${mock.port()}`, pollIntervalMs: 60000 });
  c.receive('abcdef');
  await c.stop();
  assert.equal(c.isStarted(), false);
  assert.equal(c._received.size, 0);
  await mock.close();
});

test('默认协作端列表与上游一致（public 服务子集）', () => {
  assert.deepEqual(DEFAULT_SERVERS, ['oast.pro', 'oast.live', 'oast.online']);
});
