// [D44 2026-10-11] WafIdentifier.activeProbe 多向量差分升级单测
// 对标 wafw00f genericdetect 的三条判据：状态码漂移（多向量）/ 连接级阻断 / Server 头漂移，
// 外加 429 补集与「无 WAF 不误报」红线。全部用本地 mock HTTP 服务，零外部依赖。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { WafIdentifier } from '../src/core/waf/WafIdentifier.js';
import { httpClient } from '../src/core/httpClient.js';

const waf = new WafIdentifier();

/** 起 mock：blockPatterns 命中 id 值 → 403（可选改 status/Server 头/设 cookie）；destroyPatterns 命中 → 直接断连 */
async function startMock({ blockPatterns = [], status = 403, serverHeader = null, blockHeader = null, destroyPatterns = [], normalServer = 'nginx' } = {}) {
  const seen = [];
  const server = createServer((rq, rs) => {
    const u = new URL(rq.url, 'http://x');
    const id = u.searchParams.get('id') || '';
    seen.push(id);
    if (destroyPatterns.some((re) => re.test(id))) {
      rs.socket.destroy();
      return;
    }
    if (blockPatterns.some((re) => re.test(id))) {
      const headers = { 'Content-Type': 'text/html' };
      if (serverHeader) headers.Server = serverHeader;
      if (blockHeader) headers['X-Block-Engine'] = blockHeader;
      rs.writeHead(status, headers);
      // 无特征文案：刻意不带任何拦截页关键词 —— 带关键词的页会被通用拦截页签名
      // （blockSignatures，generic_block 层）认走，那样就测不到 behavior 差分路径了。
      rs.end('no');
      return;
    }
    const headers = { 'Content-Type': 'text/html' };
    if (normalServer) headers.Server = normalServer;
    rs.writeHead(200, headers);
    rs.end(`<html><body><h1>Item ${id}</h1><p>page content for probing</p></body></html>`);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return {
    baseUrl: `http://127.0.0.1:${port}/item?id=1`,
    seen,
    close: () => {
      server.close();
      if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    },
  };
}

test('activeProbe：全向量被拦 + 无厂商签名 → source=behavior(0.6)，四向量齐报', async () => {
  const m = await startMock({ blockPatterns: [/union|select|script|passwd|' OR/i] });
  try {
    const r = await waf.activeProbe({ baseUrl: m.baseUrl }, httpClient);
    assert.equal(r.detected, true);
    assert.equal(r.vendor, null);
    assert.equal(r.source, 'behavior');
    assert.equal(r.confidence, 0.6);
    assert.deepEqual([...r.vectorsBlocked].sort(), ['lfi', 'sqli-quote', 'sqli-union', 'xss']);
    assert.ok(r.evidence.includes('status-shift vectors:'));
  } finally {
    m.close();
  }
});

test('activeProbe：仅拦 SQLi、放行 XSS/LFI → 多向量语义区分「专项规则」', async () => {
  const m = await startMock({ blockPatterns: [/union|select|' OR/i] });
  try {
    const r = await waf.activeProbe({ baseUrl: m.baseUrl }, httpClient);
    assert.equal(r.detected, true);
    assert.deepEqual([...r.vectorsBlocked].sort(), ['sqli-quote', 'sqli-union']);
    assert.ok(!r.vectorsBlocked.includes('xss'));
    assert.ok(!r.vectorsBlocked.includes('lfi'));
  } finally {
    m.close();
  }
});

test('activeProbe：连接级阻断（断连重试仍失败）→ hard 证据 + connectionBlocked 标注', async () => {
  const m = await startMock({ destroyPatterns: [/union|select|script|passwd|' OR/i] });
  try {
    const r = await waf.activeProbe({ baseUrl: m.baseUrl }, httpClient);
    assert.equal(r.detected, true);
    assert.equal(r.source, 'behavior');
    assert.equal(r.connectionBlocked, true);
    assert.ok(r.evidence.includes('connection-level:'));
  } finally {
    m.close();
  }
});

test('activeProbe：连接级偶发抖动（首次断连、重试成功）→ 不计为 WAF 证据（防误报）', async () => {
  let flips = 0;
  const server = createServer((rq, rs) => {
    const u = new URL(rq.url, 'http://x');
    const id = u.searchParams.get('id') || '';
    // 每个恶意向量第一次断连、重试放行 —— 旧实现 .catch(()=>null) 会完全看不见，新实现重试后不计
    if (/union|select|script|passwd|' OR/i.test(id) && flips < 4) {
      flips += 1;
      rs.socket.destroy();
      return;
    }
    rs.writeHead(200, { Server: 'nginx' });
    rs.end(`<html><body>Item ${id}</body></html>`);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  try {
    const r = await waf.activeProbe({ baseUrl: `http://127.0.0.1:${port}/item?id=1` }, httpClient);
    assert.equal(r.detected, false, `偶发断连不应判为 WAF：${JSON.stringify(r)}`);
    assert.equal(r.connectionBlocked, false);
  } finally {
    server.close();
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
  }
});

test('activeProbe：429 计入拦截码集；Server 头漂移进 evidence', async () => {
  const m = await startMock({ blockPatterns: [/script/], status: 429, serverHeader: 'xywall/2.0' });
  try {
    const r = await waf.activeProbe({ baseUrl: m.baseUrl }, httpClient);
    assert.equal(r.detected, true);
    assert.deepEqual(r.vectorsBlocked, ['xss']);
    assert.ok(r.evidence.includes('server-header shift: nginx→xywall/2.0'), `evidence 应含 Server 头漂移：${r.evidence}`);
  } finally {
    m.close();
  }
});

test('activeProbe：无 WAF → detected=false（不误报），且证据字段齐全', async () => {
  const m = await startMock({});
  try {
    const r = await waf.activeProbe({ baseUrl: m.baseUrl }, httpClient);
    assert.equal(r.detected, false);
    assert.equal(r.vendor, null);
    assert.deepEqual(r.vectorsBlocked, []);
    assert.equal(r.connectionBlocked, false);
  } finally {
    m.close();
  }
});

test('activeProbe：被拦响应带厂商签名 → 直接命名厂商（xss 拦截页含已知指纹头）', async () => {
  // 用 62 指纹中的真实厂商签名：Cloudflare 的 server 头
  const m = await startMock({ blockPatterns: [/passwd/], serverHeader: 'cloudflare', status: 403 });
  try {
    const r = await waf.activeProbe({ baseUrl: m.baseUrl }, httpClient);
    assert.equal(r.detected, true);
    assert.equal(r.vendor, 'Cloudflare'); // 厂商名以 wafRules.js 登记的规范大小写为准
    assert.ok(r.confidence >= 0.8);
    assert.deepEqual(r.vectorsBlocked, ['lfi']);
  } finally {
    m.close();
  }
});
