// Phase 2 性能优化回归：网络与提取（对标 sqlmap --keep-alive / --predict-output / 多线程拖库 / 时间盲注优化）
// 覆盖：1) 显式 HTTP Agent + keep-alive 开关（T1）
//      2) 盲注常见值缓存 + predictOutput 开关（T2）
//      3) 提取阶段点间并行度受控（T3）
//      4) 时间盲注最小可行 sleep 标定（T4）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { HttpClient } from '../src/core/httpClient.js';
import { Extractor } from '../src/engine/Extractor.js';
import { ScanManager } from '../src/engine/ScanManager.js';

// ===== 通用工具 =====
// 从请求中取出注入值（url query / body / cookie）
function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  return '';
}

// 布尔预言机：已知 secret，注入条件为真时返回非空响应；onRequest 用于统计请求次数
function makeBooleanOracle(secret, onRequest) {
  return {
    async request(opts) {
      if (onRequest) onRequest();
      const q = extractQuery(opts);
      if (q.includes('1=2')) return { data: '', status: 200 };
      const lenM = q.match(/(?:LENGTH|LEN)\(\(.*?\)+\s*>\s*(\d+)/);
      if (lenM) return { data: Number(lenM[1]) < secret.length ? 'OK' : '', status: 200 };
      const charM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
      if (charM) {
        const i = Number(charM[1]);
        const c = Number(charM[2]);
        const code = secret.charCodeAt(i - 1);
        return { data: c < code ? 'OK' : '', status: 200 };
      }
      return { data: '', status: 200 };
    },
  };
}

function buildCtx(httpClient, dbms = 'MySQL', config = {}, target) {
  return {
    httpClient,
    target: target || { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms,
    config: { timeoutMs: 5000, retry: 0, maxColumnsGuess: 10, ...config },
  };
}

// 等待扫描完成（复用 phase1 语义）
async function waitScanDone(sm, scanId, tries = 200) {
  for (let i = 0; i < tries; i++) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) return s;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error(`扫描未在预期时间内结束：${scanId}`);
}

// ===== T1：显式 HTTP Agent + keep-alive 开关 =====
test('T1 HttpClient 默认挂显式 keep-alive Agent（keepAlive=true）', () => {
  const c = new HttpClient();
  assert.ok(c.instance.defaults.httpAgent instanceof http.Agent, 'httpAgent 应为 http.Agent');
  assert.ok(c.instance.defaults.httpsAgent instanceof https.Agent, 'httpsAgent 应为 https.Agent');
  assert.equal(c.instance.defaults.httpAgent.keepAlive, true);
  assert.equal(c.instance.defaults.httpsAgent.keepAlive, true);
});

test('T1 disableKeepAlive=true 时不挂自定义 keep-alive Agent', () => {
  const c = new HttpClient({ disableKeepAlive: true });
  assert.equal(c.instance.defaults.httpAgent, undefined);
  assert.equal(c.instance.defaults.httpsAgent, undefined);
});

test('T1 request 直连关闭 keep-alive 时显式传 httpAgent:false 覆盖实例默认', async () => {
  const c = new HttpClient();
  let captured = null;
  c.instance.request = async (cfg) => {
    captured = cfg;
    return { data: '', status: 200 };
  };
  await c.request({ url: 'http://127.0.0.1/', headers: {}, disableKeepAlive: true });
  assert.equal(captured.httpAgent, false);
  assert.equal(captured.httpsAgent, false);
});

test('T1 request 默认（未关闭）不额外传 agent，沿用实例默认 keep-alive', async () => {
  const c = new HttpClient();
  let captured = null;
  c.instance.request = async (cfg) => {
    captured = cfg;
    return { data: '', status: 200 };
  };
  await c.request({ url: 'http://127.0.0.1/', headers: {} });
  assert.equal(captured.httpAgent, undefined);
  assert.equal(captured.httpsAgent, undefined);
});

// ===== T2：盲注常见值缓存 + predictOutput 开关 =====
test('T2 predictOutput 常见值缓存：同目标跨注入点复用，命中零请求', async () => {
  const ex = new Extractor();
  const target = { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} };
  let requests = 0;
  const oracle = makeBooleanOracle('5.7.40', () => requests++);

  const ctx1 = buildCtx(oracle, 'MySQL', {}, target);
  ctx1.point = { id: 'p1', location: 'url', param: 'q', originalValue: '1' };
  ctx1.scanId = 's1';
  const r1 = await ex.extractBoolean(ctx1, 'version()');
  const afterFirst = requests;

  // 同目标另一注入点（同 scanId，同 dbms）→ 应命中缓存
  const ctx2 = buildCtx(oracle, 'MySQL', {}, target);
  ctx2.point = { id: 'p2', location: 'url', param: 'q', originalValue: '2' };
  ctx2.scanId = 's1';
  const r2 = await ex.extractBoolean(ctx2, 'version()');

  assert.equal(r1, '5.7.40');
  assert.equal(r2, '5.7.40');
  assert.ok(afterFirst > 0, '首次应发出二分请求');
  assert.equal(requests, afterFirst, '第二次应命中缓存零请求');
});

test('T2 predictOutput=false 关闭缓存，同表达式重复二分', async () => {
  const ex = new Extractor();
  const target = { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} };
  let requests = 0;
  const oracle = makeBooleanOracle('5.7.40', () => requests++);

  const ctx = buildCtx(oracle, 'MySQL', { predictOutput: false }, target);
  ctx.scanId = 's1';
  const r1 = await ex.extractBoolean(ctx, 'version()');
  const afterFirst = requests;
  const r2 = await ex.extractBoolean(ctx, 'version()');

  assert.equal(r1, '5.7.40');
  assert.equal(r2, '5.7.40');
  assert.ok(requests > afterFirst, '关闭缓存应重复二分');
});

test('T2 predictOutput 缓存按目标隔离：不同目标不串数据', async () => {
  const ex = new Extractor();
  const ta = { method: 'GET', baseUrl: 'http://a/?q=1', headerParams: {}, cookieParams: {} };
  const tb = { method: 'GET', baseUrl: 'http://b/?q=1', headerParams: {}, cookieParams: {} };
  const ctxA = buildCtx(makeBooleanOracle('5.7.40'), 'MySQL', {}, ta);
  ctxA.scanId = 's1';
  const ctxB = buildCtx(makeBooleanOracle('8.0.33'), 'MySQL', {}, tb);
  ctxB.scanId = 's2';

  const rA = await ex.extractBoolean(ctxA, 'version()');
  const rB = await ex.extractBoolean(ctxB, 'version()');
  assert.equal(rA, '5.7.40');
  assert.equal(rB, '8.0.33');
});

// ===== T3：提取阶段点间并行度受控 =====
test('T3 _mapPool 并发度受控：峰值不超过 concurrency', async () => {
  const sm = new ScanManager();
  let inFlight = 0;
  let peak = 0;
  const items = [1, 2, 3, 4, 5, 6];
  await sm._mapPool(
    items,
    async () => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 10));
      inFlight--;
    },
    2
  );
  assert.equal(peak, 2, '并发峰值应等于 concurrency');
});

test('T3 提取阶段点间并行：多 union 点并发拖库', async () => {
  const sm = new ScanManager({ retireTtlMs: 50 });
  sm.detectors = [
    {
      technique: 'union',
      async detect() {
        return { vulnerable: true, dbms: 'MySQL', payloads: [], evidence: '', trace: null };
      },
    },
  ];
  sm.fp = {
    async fingerprint() {
      return { dbms: 'MySQL', baseline: { status: 200, headers: {}, body: '' } };
    },
  };
  sm.parser = {
    async discover() {
      return [
        { id: 'a', location: 'url', param: 'a', originalValue: '1' },
        { id: 'b', location: 'url', param: 'b', originalValue: '2' },
      ];
    },
  };
  sm.httpClient = { async request() { return { status: 200, headers: {}, data: 'ok' }; } };
  sm.reportGen = { riskOf: () => 'Medium' };
  let inFlight = 0;
  let peak = 0;
  sm._extract = async (scanId, ctx) => {
    inFlight++;
    peak = Math.max(peak, inFlight);
    await new Promise((r) => setTimeout(r, 30));
    inFlight--;
    return { databases: [ctx.point.id], tables: {}, columns: {}, rows: {} };
  };
  sm.extractor = { extractProof: async () => null };

  const id = await sm.start({
    url: 'http://x/?a=1&b=2',
    config: { concurrency: 2, ratePerSec: 100, techniques: ['union'], prefilter: false, extractConcurrency: 2 },
  });
  await waitScanDone(sm, id);
  assert.equal(peak, 2, '两个注入点的提取应并发执行（点间并行）');
});

// ===== T4：时间盲注最小可行 sleep 标定 =====
const MYSQL_COND = (c, s) => `IF((${c}), SLEEP(${s}), 0)`;

function buildTimeCtx(httpClient, config = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?id=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'id', originalValue: '1', confirmed: true },
    dbms: 'MySQL',
    config: { timeoutMs: 10000, retry: 0, timeThresholdMs: 1500, ...config },
  };
}

// 时间预言机：按 URL 中的 SLEEP(n) 延迟对应毫秒；calls 记录请求
function makeTimeMock(delays) {
  const calls = [];
  return {
    calls,
    async request(opts) {
      const raw = typeof opts.url === 'string' ? opts.url : '';
      const q = decodeURIComponent(raw);
      calls.push(q);
      if (/SLEEP\(1\)/.test(q)) await new Promise((r) => setTimeout(r, delays.one ?? 0));
      else if (/SLEEP\(2\)/.test(q)) await new Promise((r) => setTimeout(r, delays.two ?? 0));
      return { data: 'page', status: 200 };
    },
  };
}

test('T4 calibrateTimeSleep：小 sleep 命中即采用最小可行 sleep', async () => {
  const ex = new Extractor();
  const mock = makeTimeMock({ one: 600, two: 800 });
  const ctx = buildTimeCtx(mock, { timeThresholdMs: 500, timeBlindCalibrate: true });
  const sec = await ex.calibrateTimeSleep(ctx, '1', MYSQL_COND);
  assert.equal(sec, 1, 'sleep=1 已可判定，应采用最小 sleep');
});

test('T4 calibrateTimeSleep：小 sleep 未命中逐步加大回退默认', async () => {
  const ex = new Extractor();
  const mock = makeTimeMock({ one: 300, two: 600 });
  const ctx = buildTimeCtx(mock, { timeThresholdMs: 500, timeBlindCalibrate: true });
  const sec = await ex.calibrateTimeSleep(ctx, '1', MYSQL_COND);
  assert.equal(sec, 2, 'sleep=1 不可判定，应回退 sleep=2（默认）');
});

test('T4 calibrateTimeSleep：timeBlindCalibrate=false 直接返回默认且零请求', async () => {
  const ex = new Extractor();
  const mock = makeTimeMock({ one: 0, two: 0 });
  const ctx = buildTimeCtx(mock, { timeBlindCalibrate: false });
  const sec = await ex.calibrateTimeSleep(ctx, '1', MYSQL_COND);
  assert.equal(sec, 2);
  assert.equal(mock.calls.length, 0, '关闭标定不应发请求');
});
