// ============================================================================
// tests/httpClient.egressHardening.test.js —— 出口层三项实战加固
// [P0-FIX 2026-09-09]
//
// 1) DNS 钉死必须「稳定钉住 + 失败才换」：多 A 记录目标（K8s/F5/无 sticky LB）上，
//    基线请求与注入请求若落到不同后端，时间盲注的 σ 会被后端负载差异污染 —— 表现为
//    「time 技术在负载均衡目标上整段不可用」。原实现每次请求都前移索引，正是这个坑。
// 2) 出口头清洗必须覆盖调用方传入的 headers（不止 auth.headers）：否则 Transfer-Encoding /
//    Content-Length 可从任何绕过 REST 入口的路径进入请求，对目标前置代理构成请求走私。
// 3) undici/H2 通道必须解压：不解压时 gzip 响应被当文本解码成整页 U+FFFD，
//    `--http2` 与默认通道会对同一目标给出相反结论。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import zlib from 'node:zlib';
import {
  httpClient,
  dnsCache,
  mergeAuthHeaders,
  decompressResponseBody,
  noteEgressIpFailure,
  assertSafeTargetForEgress,
} from '../src/core/httpClient.js';

// disableKeepAlive 是必要的：否则 axios 会复用已有 socket，lookup 根本不会被再次调用，
// 「钉住/切换」就退化成「连接复用」，测不到 DNS 钉死层的行为。
const EgressOpts = { proxy: false, trustProxyEnv: false, retry: 0, disableKeepAlive: true };

function listen(handler) {
  const server = http.createServer(handler);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

// 取一个空闲端口，再把两个 server 绑到「同一端口 + 不同回环 IP」：
// 这样「请求落到哪个后端」完全由 DNS 钉死结果决定，可以直接断言钉住/切换行为。
function freePort() {
  return new Promise((resolve, reject) => {
    const probe = http.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const p = probe.address().port;
      probe.close(() => resolve(p));
    });
  });
}

function bindTag(ip, port, tag) {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(tag);
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, ip, () => resolve(server));
  });
}

// ── 1) DNS 钉死稳定性 ───────────────────────────────────────────────────────
test('多 A 记录目标：请求稳定落在同一个 IP（不再每请求轮换）', async () => {
  const port = await freePort();
  const host = 'pin-stability.test';
  let sa = null;
  let sb = null;
  try {
    sa = await bindTag('127.0.0.1', port, 'A');
    sb = await bindTag('127.0.0.2', port, 'B');
    dnsCache.set(host, { ips: ['127.0.0.1', '127.0.0.2'], ts: Date.now() });
    const seen = [];
    for (let i = 0; i < 4; i++) {
      const res = await httpClient.request({
        url: `http://${host}:${port}/?id=1`,
        method: 'GET',
        ...EgressOpts,
      });
      seen.push(String(res?.data));
    }
    assert.ok(
      seen.every((x) => x === seen[0]),
      `同一目标连续 4 次请求应钉在同一个后端，实际命中序列=${seen.join(',')}（每请求换 IP 会污染盲注基线）`
    );
    assert.equal(seen[0], 'A');
  } finally {
    dnsCache.delete(host);
    sa?.close();
    sb?.close();
  }
});

test('出口 IP 连接层失败后，后续请求换到下一个已校验 IP 并稳定钉住', async () => {
  const port = await freePort();
  const host = 'pin-failover.test';
  let sa = null;
  let sb = null;
  try {
    sa = await bindTag('127.0.0.1', port, 'A');
    sb = await bindTag('127.0.0.2', port, 'B');
    dnsCache.set(host, { ips: ['127.0.0.1', '127.0.0.2'], ts: Date.now() });
    const url = `http://${host}:${port}/?id=1`;
    const r1 = await httpClient.request({ url, method: 'GET', ...EgressOpts });
    assert.equal(String(r1.data), 'A');
    noteEgressIpFailure(url, 'ECONNREFUSED');
    const r2 = await httpClient.request({ url, method: 'GET', ...EgressOpts });
    assert.equal(String(r2.data), 'B', '拉黑后下一次请求应落到下一个 IP');
    const r3 = await httpClient.request({ url, method: 'GET', ...EgressOpts });
    assert.equal(String(r3.data), 'B', '不能又漂回死 IP 形成乒乓');
  } finally {
    dnsCache.delete(host);
    sa?.close();
    sb?.close();
  }
});

// ── 2) 出口头清洗 ──────────────────────────────────────────────────────────
test('mergeAuthHeaders 拦下调用方传入的传输层头（防走私），保留 Host 与业务头', () => {
  const out = mergeAuthHeaders(
    {
      Host: 'target.internal',
      'Content-Length': '5',
      'Transfer-Encoding': 'chunked',
      'proxy-connection': 'keep-alive',
      'X-Custom-Thing': 'keep-me',
    },
    null
  );
  assert.equal(out['Transfer-Encoding'], undefined, 'Transfer-Encoding 必须由传输层决定，不能由调用方设置');
  assert.equal(out['Content-Length'], undefined);
  assert.equal(out['proxy-connection'], undefined);
  assert.equal(out['X-Custom-Thing'], 'keep-me');
  assert.equal(out.Host, 'target.internal', 'Host 保留：按 IP 直连 + 改 Host 打 vhost 是合法需求');
});

test('auth.headers 侧的既有黑名单行为不回退', () => {
  const out = mergeAuthHeaders({}, { headers: { 'Transfer-Encoding': 'chunked', 'X-A': '1' } });
  assert.equal(out['Transfer-Encoding'], undefined);
  assert.equal(out['X-A'], '1');
});

// ── 3) undici 通道解压 ─────────────────────────────────────────────────────
test('decompressResponseBody：gzip / deflate（含 raw）/ br 往返一致', () => {
  const text = '注入点在这里：id=1 AND SLEEP(2) -- 中文也要活着';
  const buf = Buffer.from(text, 'utf8');
  assert.equal(decompressResponseBody(zlib.gzipSync(buf), 'gzip').toString('utf8'), text);
  assert.equal(decompressResponseBody(zlib.gzipSync(buf), 'GZIP').toString('utf8'), text, '头值大小写要容错');
  assert.equal(decompressResponseBody(zlib.deflateSync(buf), 'deflate').toString('utf8'), text);
  assert.equal(decompressResponseBody(zlib.deflateRawSync(buf), 'deflate').toString('utf8'), text, '部分服务端发 raw deflate');
  assert.equal(decompressResponseBody(zlib.brotliCompressSync(buf), 'br').toString('utf8'), text);
  assert.throws(() => decompressResponseBody(buf, 'zstd-custom'), /不支持的编码/);
});

// ── 4) ssrfViaProxy=strict-dns（代理不自动等于边界）─────────────────────────
test('ssrfViaProxy=strict-dns：本地能解析出元数据 IP 时，即使挂了代理也拦', async () => {
  dnsCache.set('meta.corp.test', { ips: ['169.254.169.254'], ts: Date.now() });
  try {
    await assert.rejects(
      () =>
        assertSafeTargetForEgress('http://meta.corp.test/latest/meta-data', {
          viaProxy: true,
          ssrfViaProxy: 'strict-dns',
        }),
      /strict-dns/,
      '内网 DNS 把域名指到元数据地址时，不能因为「反正走代理」就放弃判定'
    );
    // 既有默认语义（auto）不变：解析发生在代理侧，本地不拦（边界转移已写在注释里）
    await assert.doesNotReject(() =>
      assertSafeTargetForEgress('http://meta.corp.test/x', { viaProxy: true, ssrfViaProxy: 'auto' })
    );
  } finally {
    dnsCache.delete('meta.corp.test');
  }
});

test('走 undici 通道（http2:true）遇到 gzip 响应仍能拿到可读文本', async () => {
  const payload = '<html>baseline 中文 with id=1 AND SLEEP(2)</html>';
  const gz = zlib.gzipSync(Buffer.from(payload, 'utf8'));
  const { server, port } = await listen((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Encoding': 'gzip' });
    res.end(gz);
  });
  try {
    const res = await httpClient.request({
      url: `http://127.0.0.1:${port}/?id=1`,
      method: 'GET',
      http2: true,
      ...EgressOpts,
    });
    assert.equal(res.status, 200);
    assert.equal(String(res.data), payload, 'undici 通道必须解压，否则整页是二进制乱码 → 检测器全盲');
  } finally {
    server.close();
  }
});
