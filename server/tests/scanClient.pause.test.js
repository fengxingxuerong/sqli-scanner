// ============================================================================
// scanClient.pause.test.js —— 暂停闸下沉到 getScanClient 视图（F1 2026-10-03）
//
// 背景（TODO 09-28 #4 的验证口径）：暂停此前只挂在 scanRunner 的 ctxBase 包装层，
// detect.js 的两支 ad-hoc 客户端（tamper 链验证 detect.js 的 verifyTamperChains、
// 拦截驱动重跑 retryCtxBase）直接调 sm.getScanClient 拿**裸视图** —— 暂停期间照常发包，
// 「目标报警了先停手」对这两条路径形同虚设。修复 = 闸挂进视图本身（request+headRequest）。
//
// 判据（全部可证伪）：
//   ① paused=true 时 view.request 不发请求，resume 后原样继续（闸真的在挡流量）；
//   ② headRequest 同样过闸（--null-connection 探针不得绕过暂停）；
//   ③ cancelled 放行（stop 语义：不因暂停闸卡死收尾）；
//   ④ 闸在**视图层**而非某个包装层 ⇒ 直接拿裸视图的 ad-hoc 调用方天然被覆盖 ——
//     这是本修复与「在 detect.js 里再包一层」的本质区别（后者会被 fake-sm 契约打回）。
// ============================================================================
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { getConnector, getScanClient } from '../src/engine/scan/scanClient.js';

let server;
let baseUrl;
/** 靶站侧真实收到的请求计数（不采信客户端自报） */
let hits;

beforeEach(async () => {
  hits = 0;
  server = http.createServer((_req, res) => {
    hits += 1;
    res.writeHead(200, { 'content-type': 'text/plain' }).end('ok');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

afterEach(async () => {
  await new Promise((r) => server.close(r));
});

/** 最小 ScanManager 形状：getScanClient 只用到 httpClient / _scanClients / _waitWhilePaused */
function makeSelf({ paused = false, cancelled = false } = {}) {
  const scans = new Map([
    ['scan-1', { paused, cancelled }],
  ]);
  const waitLog = { waits: 0 };
  const self = {
    httpClient: { forScan: (scanId, ratePerSec, rateKey) => {
      // 走真 HttpClient 的 forScan 语义太重（Agent 建 连），这里用一个最小等效视图：
      // forScan 返回 { request, headRequest }，请求直接打 http 模块 —— 行为与本测试的判据无关，
      // 闸包在外面，闸内只要真的发起网络请求即可被靶站计数。
      const raw = async (opts) => {
        const res = await fetch(opts.url, { method: opts.method || 'GET' });
        return { status: res.status, data: await res.text() };
      };
      return {
        request: raw,
        headRequest: async (url, opts = {}) => raw({ ...opts, url, method: 'HEAD' }),
      };
    } },
    _scanClients: new Map(),
    scans,
    _waitWhilePaused: async (scanId) => {
      waitLog.waits += 1;
      for (;;) {
        const s = scans.get(scanId);
        if (!s || !s.paused || s.cancelled) return;
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
    },
  };
  self.getConnector = (target) => getConnector.call(self, target);
  return { self, scans, waitLog };
}

test('① paused 期间 view.request 不发请求，resume 后放行（靶站侧计数为准）', async () => {
  const { self, scans } = makeSelf({ paused: true });
  const view = getScanClient.call(self, 'scan-1', { mode: 'http', config: {} });
  assert.equal(typeof view.request, 'function');

  let settled = false;
  const p = view.request({ url: `${baseUrl}/a`, method: 'GET' }).then((r) => { settled = true; return r; });
  await new Promise((r) => setTimeout(r, 250));
  assert.equal(settled, false, '暂停期间请求必须挂在闸上（未结算）');
  assert.equal(hits, 0, `暂停期间靶站不应收到任何请求，实得 ${hits} 个`);

  scans.get('scan-1').paused = false; // resume
  await p;
  assert.equal(settled, true, 'resume 后请求应完成');
  assert.equal(hits, 1, `resume 后靶站应恰好收到 1 个请求，实得 ${hits}`);
});

test('② headRequest 同样过闸（--null-connection 不得绕过暂停）', async () => {
  const { self, scans } = makeSelf({ paused: true });
  const view = getScanClient.call(self, 'scan-1', { mode: 'http', config: {} });
  let settled = false;
  const p = view.headRequest(`${baseUrl}/b`).then(() => { settled = true; });
  await new Promise((r) => setTimeout(r, 250));
  assert.equal(settled, false, '暂停期间 HEAD 必须挂在闸上');
  assert.equal(hits, 0, `暂停期间靶站不应收到 HEAD，实得 ${hits}`);
  scans.get('scan-1').paused = false;
  await p;
  assert.equal(hits, 1, `resume 后 HEAD 应送达，实得 ${hits}`);
});

test('③ cancelled 放行：stop 语义不被暂停闸卡死', async () => {
  const { self } = makeSelf({ paused: true, cancelled: true });
  const view = getScanClient.call(self, 'scan-1', { mode: 'http', config: {} });
  const t0 = Date.now();
  await view.request({ url: `${baseUrl}/c`, method: 'GET' });
  assert.ok(Date.now() - t0 < 1000, 'cancelled 时闸必须立即放行（stop 收尾不能被暂停卡住）');
  assert.equal(hits, 1);
});

test('④ 闸挂在视图层：直接持裸视图的 ad-hoc 调用方（detect.js 两处）天然被覆盖 —— 源码钉住', async () => {
  const { readFileSync } = await import('node:fs');
  const { fileURLToPath } = await import('node:url');
  const path = await import('node:path');
  const here = path.dirname(fileURLToPath(import.meta.url));
  const detect = readFileSync(path.join(here, '..', 'src', 'engine', 'scan', 'detect.js'), 'utf8');
  const hits2 = detect.match(/sm\.getScanClient\(scanId, target\)/g) || [];
  assert.ok(
    hits2.length >= 2,
    `detect.js 的 ad-hoc 客户端必须经 sm.getScanClient 获取（暂停闸在视图上才盖得住它们），实得 ${hits2.length} 处`,
  );
  const scanClientSrc = readFileSync(path.join(here, '..', 'src', 'engine', 'scan', 'scanClient.js'), 'utf8');
  assert.match(
    scanClientSrc,
    /view\.request = async \(opts\) => \{\s*\n\s*await waitWhilePaused\(scanId\);/,
    '暂停闸必须挂在 getScanClient 的视图 request 上（挂到别的层 = 本测试判定失效）',
  );
});
