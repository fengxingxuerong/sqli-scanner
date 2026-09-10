import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import { once } from 'node:events';
import { HttpClient } from '../src/core/httpClient.js';
import {
  parseDigestChallenge,
  pickQop,
  buildDigestHeader,
  extractDigestChallenge,
} from '../src/core/digestAuth.js';
function bodyOf(res) {
  if (typeof res.data !== 'string') return res.data;
  // [P1-FIX 2026-09-08] HttpClient 统一 responseType:'text'（响应体恒为原始文本，
  // JSON API 不再被 axios 隐式 parse），测试侧按 JSON 解析取字段；非 JSON 原样返回。
  try {
    return JSON.parse(res.data);
  } catch {
    return res.data;
  }
}


// ============================================================================
// [P2-4] --auth-type=Digest —— RFC 7616 挑战-响应认证
// 单测：解析器/响应头计算（含 MD5/SHA-256、qop/auth、RFC 2069 无 qop 模式）
// 集成：真实本地 HTTP 服务器 401→挑战→验证 Authorization→200 全链路
// ============================================================================

// —— 独立计算 Digest response（服务端视角复核）——
function serverSideResponse({ method, uri, username, password, realm, nonce, nc, cnonce, qop, algorithm }) {
  const H = (algo) => (algo.startsWith('SHA-256') ? crypto.createHash('sha256') : crypto.createHash('md5'));
  let ha1 = H(algorithm).update(`${username}:${realm}:${password}`).digest('hex');
  if (algorithm.endsWith('-sess')) {
    ha1 = H(algorithm).update(`${ha1}:${nonce}:${cnonce}`).digest('hex');
  }
  const ha2 = H(algorithm).update(`${method}:${uri}`).digest('hex');
  if (qop === 'auth') {
    return H(algorithm).update(`${ha1}:${nonce}:${String(nc).padStart(8, '0')}:${cnonce}:auth:${ha2}`).digest('hex');
  }
  return H(algorithm).update(`${ha1}:${nonce}:${ha2}`).digest('hex');
}

function authHeaderToFields(h) {
  const body = h.replace(/^Digest\s+/i, '');
  const fields = {};
  const re = /([a-zA-Z0-9_-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^\s,]+))/g;
  let m;
  while ((m = re.exec(body)) !== null) fields[m[1].toLowerCase()] = m[2] !== undefined ? m[2] : m[3];
  return fields;
}

// ===== 单元：解析挑战 =====
test('digest: parseDigestChallenge 解析完整挑战（qop/algorithm/opaque）', () => {
  const ch = parseDigestChallenge(
    'Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41", algorithm=MD5'
  );
  assert.ok(ch);
  assert.equal(ch.realm, 'testrealm@host.com');
  assert.equal(ch.nonce, 'dcd98b7102dd2f0e8b11d0f600bfb0c093');
  assert.equal(ch.opaque, '5ccc069c403ebaf9f0171e9517f40e41');
  assert.equal(ch.algorithm, 'MD5');
  assert.match(ch.qop, /auth/);
});

test('digest: parseDigestChallenge 拒绝非 Digest scheme / 缺 realm / 缺 nonce', () => {
  assert.equal(parseDigestChallenge('Basic realm="x"'), null);
  assert.equal(parseDigestChallenge('Digest qop="auth", nonce="n"'), null); // 缺 realm
  assert.equal(parseDigestChallenge('Digest realm="r"'), null); // 缺 nonce
  assert.equal(parseDigestChallenge(null), null);
  assert.equal(parseDigestChallenge(''), null);
});

test('digest: parseDigestChallenge 容忍无引号值 / 逗号在引号内', () => {
  const ch = parseDigestChallenge('Digest realm=r1, nonce="a,b", qop="auth", algorithm=SHA-256');
  assert.ok(ch);
  assert.equal(ch.realm, 'r1');
  assert.equal(ch.nonce, 'a,b'); // 引号内逗号不截断
  assert.equal(ch.algorithm, 'SHA-256');
});

test('digest: pickQop 优先 auth，忽略 auth-int；无 qop 返回 null', () => {
  assert.equal(pickQop('auth,auth-int'), 'auth');
  assert.equal(pickQop('auth-int'), null);
  assert.equal(pickQop(undefined), null);
  assert.equal(pickQop(''), null);
});

test('digest: extractDigestChallenge 从响应头提取（含多 scheme 混合）', () => {
  const h = { 'www-authenticate': 'Basic realm="b", Digest realm="r", nonce="n1", qop="auth"' };
  const ch = extractDigestChallenge(h);
  assert.ok(ch);
  assert.equal(ch.realm, 'r');
  assert.equal(ch.nonce, 'n1');
});

// ===== 单元：RFC 7616 已知测试向量（RFC 7616 §3.9.1） =====
test('digest: RFC 7616 官方向量（MD5 + qop=auth）响应头正确', () => {
  const challenge = {
    realm: 'testrealm@host.com',
    nonce: 'dcd98b7102dd2f0e8b11d0f600bfb0c093',
    opaque: '5ccc069c403ebaf9f0171e9517f40e41',
    algorithm: 'MD5',
    qop: 'auth,auth-int',
  };
  const header = buildDigestHeader({
    method: 'GET',
    uri: '/dir/index.html',
    challenge,
    username: 'Mufasa',
    password: 'Circle Of Life',
    nc: '00000001',
    cnonce: '0a4f113b',
  });
  const f = authHeaderToFields(header);
  assert.equal(f.username, 'Mufasa');
  assert.equal(f.realm, 'testrealm@host.com');
  assert.equal(f.nonce, 'dcd98b7102dd2f0e8b11d0f600bfb0c093');
  assert.equal(f.uri, '/dir/index.html');
  assert.equal(f.qop, 'auth');
  assert.equal(f.nc, '00000001');
  assert.equal(f.cnonce, '0a4f113b');
  assert.equal(f.response, '6629fae49393a05397450978507c4ef1'); // RFC 7616 官方预期
});

test('digest: SHA-256 + qop=auth 响应与独立复核一致', () => {
  const challenge = { realm: 'r', nonce: 'n1', algorithm: 'SHA-256', qop: 'auth' };
  const header = buildDigestHeader({
    method: 'POST', uri: '/api/login',
    challenge, username: 'u', password: 'p',
    nc: 1, cnonce: 'cc',
  });
  const f = authHeaderToFields(header);
  const expected = serverSideResponse({
    method: 'POST', uri: '/api/login',
    username: 'u', password: 'p', realm: 'r', nonce: 'n1',
    nc: 1, cnonce: 'cc', qop: 'auth', algorithm: 'SHA-256',
  });
  assert.equal(f.algorithm, 'SHA-256');
  assert.equal(f.response, expected);
});

test('digest: MD5-sess 变体正确（HA1 二次哈希）', () => {
  const challenge = { realm: 'r', nonce: 'n1', algorithm: 'MD5-sess', qop: 'auth' };
  const header = buildDigestHeader({
    method: 'GET', uri: '/',
    challenge, username: 'u', password: 'p',
    nc: 3, cnonce: 'cnc',
  });
  const f = authHeaderToFields(header);
  const expected = serverSideResponse({
    method: 'GET', uri: '/',
    username: 'u', password: 'p', realm: 'r', nonce: 'n1',
    nc: 3, cnonce: 'cnc', qop: 'auth', algorithm: 'MD5-sess',
  });
  assert.equal(f.response, expected);
});

test('digest: 无 qop（RFC 2069 简化模式）响应正确', () => {
  const challenge = { realm: 'r', nonce: 'n1' }; // 无 algorithm → MD5；无 qop
  const header = buildDigestHeader({
    method: 'GET', uri: '/x', challenge, username: 'u', password: 'p', nc: 1, cnonce: 'cc',
  });
  const f = authHeaderToFields(header);
  const expected = serverSideResponse({
    method: 'GET', uri: '/x',
    username: 'u', password: 'p', realm: 'r', nonce: 'n1',
    nc: 1, cnonce: 'cc', qop: null, algorithm: 'MD5',
  });
  assert.equal(f.qop, undefined); // 无 qop 模式不带 qop 字段
  assert.equal(f.nc, undefined); // 也不带 nc/cnonce
  assert.equal(f.response, expected);
});

test('digest: buildDigestHeader 参数缺失返回 null', () => {
  assert.equal(buildDigestHeader(null), null);
  assert.equal(buildDigestHeader({}), null);
  assert.equal(buildDigestHeader({ method: 'GET', uri: '/', challenge: { realm: 'r', nonce: 'n' }, username: null }), null);
});

// ===== 集成：本地 HTTP 服务器做真实 Digest 挑战 =====
function startDigestServer({ realm = 'sqli@test', requireQop = true, algorithm = 'MD5' } = {}) {
  const seen = new Map(); // nonce → { nc, expires }
  const server = http.createServer((req, res) => {
    const authz = req.headers.authorization;
    if (!authz || !authz.startsWith('Digest ')) {
      const qopStr = requireQop ? ', qop="auth"' : '';
      const waNoQop = requireQop ? '' : '';
      const wa = `Digest realm="${realm}", nonce="abc123nonce"${requireQop ? ', qop="auth"' : waNoQop}, algorithm=${algorithm}, opaque="opq123"`;
      res.writeHead(401, { 'WWW-Authenticate': wa });
      res.end('unauthorized');
      return;
    }
    // 解析客户端 Digest 头并复核
    const f = authHeaderToFields(authz);
    const nc = parseInt(f.nc, 16);
    const seenKey = `${f.username}:${f.nonce}`;
    const prev = seen.get(seenKey) || 0;
    if (nc <= prev) {
      res.writeHead(401, { 'WWW-Authenticate': `Digest realm="${realm}", nonce="abc123nonce", qop="auth", algorithm=${algorithm}, opaque="opq123"` });
      res.end('replay detected');
      return;
    }
    seen.set(seenKey, nc);
    const expected = serverSideResponse({
      method: req.method, uri: f.uri,
      username: 'alice', password: 'secret',
      realm: f.realm, nonce: f.nonce,
      nc, cnonce: f.cnonce, qop: 'auth', algorithm: f.algorithm || 'MD5',
    });
    if (f.response !== expected || f.username !== 'alice') {
      res.writeHead(401, { 'WWW-Authenticate': `Digest realm="${realm}", nonce="abc123nonce", qop="auth", algorithm=${algorithm}, opaque="opq123"` });
      res.end('bad creds');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, method: req.method, path: req.url }));
  });
  return server;
}

async function withServer(server, fn) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const port = server.address().port;
  try {
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    server.close();
    await once(server, 'close').catch(() => {});
  }
}

test('digest: httpClient 全链路 401→挑战→带 Authorization 重放→200', async () => {
  const server = startDigestServer({ realm: 'sqli@test', algorithm: 'MD5' });
  const client = new HttpClient();
  await withServer(server, async (base) => {
    const res = await client.request({
      method: 'GET',
      url: `${base}/data?x=1`,
      headers: {},
      auth: { digest: { username: 'alice', password: 'secret' } },
    });
    assert.ok(res);
    assert.equal(res.status, 200);
    const body = bodyOf(res);
    assert.equal(body.ok, true);
    assert.equal(body.path, '/data?x=1');
  });
});

test('digest: 缓存 challenge 跨请求复用且 nc 单调递增（防重放计数）', async () => {
  let reqCount = 0;
  const server = http.createServer((req, res) => {
    reqCount++;
    const authz = req.headers.authorization;
    if (!authz || !authz.startsWith('Digest ')) {
      res.writeHead(401, { 'WWW-Authenticate': 'Digest realm="r", nonce="fixednonce1", qop="auth", algorithm=MD5' });
      res.end('unauthorized');
      return;
    }
    const f = authHeaderToFields(authz);
    const expected = serverSideResponse({
      method: req.method, uri: f.uri,
      username: 'alice', password: 'secret',
      realm: 'r', nonce: 'fixednonce1',
      nc: parseInt(f.nc, 16), cnonce: f.cnonce, qop: 'auth', algorithm: 'MD5',
    });
    if (f.response !== expected || f.username !== 'alice') {
      res.writeHead(401, { 'WWW-Authenticate': 'Digest realm="r", nonce="fixednonce1", qop="auth", algorithm=MD5' });
      res.end('bad creds');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, nc: parseInt(f.nc, 16) }));
  });
  const client = new HttpClient();
  await withServer(server, async (base) => {
    const auth = { digest: { username: 'alice', password: 'secret' } };
    const r1 = await client.request({ method: 'GET', url: `${base}/a`, headers: {}, auth });
    const r2 = await client.request({ method: 'GET', url: `${base}/b`, headers: {}, auth });
    const b1 = bodyOf(r1);
    const b2 = bodyOf(r2);
    assert.equal(b1.nc, 1); // 首次挑战后重放消费 nc=1
    assert.equal(b2.nc, 2); // 第二次请求缓存复用 nc=2（单调递增）
  });
  // 401(裸) + 200(带) + 200(带) = 3 个请求
  assert.equal(reqCount, 3);
});

test('digest: 错误凭据 → 401 返回（不死循环）', async () => {
  let authRequests = 0;
  const server = http.createServer((req, res) => {
    const authz = req.headers.authorization;
    if (!authz || !authz.startsWith('Digest ')) {
      res.writeHead(401, { 'WWW-Authenticate': 'Digest realm="r", nonce="n1", qop="auth", algorithm=MD5' });
      res.end('unauthorized');
      return;
    }
    authRequests++;
    res.writeHead(401, { 'WWW-Authenticate': 'Digest realm="r", nonce="n1", qop="auth", algorithm=MD5' });
    res.end('bad creds');
  });
  const client = new HttpClient();
  await withServer(server, async (base) => {
    const res = await client.request({
      method: 'GET', url: `${base}/x`, headers: {},
      auth: { digest: { username: 'alice', password: 'wrong' } },
    });
    assert.equal(res.status, 401);
  });
  // 裸请求 + 重放 + （无第三次——401 后清 state 且本请求结束）
  assert.equal(authRequests, 1);
});

test('digest: 未配置 digest 的普通请求不受影响（无额外请求）', async () => {
  let reqCount = 0;
  const server = http.createServer((req, res) => {
    reqCount++;
    res.writeHead(200);
    res.end('ok');
  });
  const client = new HttpClient();
  await withServer(server, async (base) => {
    const res = await client.request({ method: 'GET', url: `${base}/plain`, headers: {} });
    assert.equal(res.status, 200);
  });
  assert.equal(reqCount, 1);
});
