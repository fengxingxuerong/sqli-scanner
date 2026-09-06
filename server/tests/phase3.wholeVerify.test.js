// P2-P7 盲注提取完整值投票复验（整体重测/投票）测试（node --test）
// 验证：1) 提取完成后对「完整值」发 1 次整体等值复验（布尔/时间通道），复验通过不标记低置信；
//       2) 复验失败（mock 不识别整体等值）→ 值仍返回但 ctx.extractConfidence='low'（调用方在结果注明）；
//       3) 仅 1 次额外请求（不是逐字符重测）；extractVerify:false 关闭后零投票请求；
//       4) predictOutput 缓存命中不重复投票（复验仅首次提取）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  return '';
}

// 布尔预言机：支持长度/字符二分 + 逐字节等值 + 完整值整体等值（wholeVerifyProbes 计数）
function makeBooleanOracle(secret, { supportWholeVerify = true } = {}) {
  const stats = { wholeVerifyProbes: 0 };
  return {
    stats,
    async request(opts) {
      const q = extractQuery(opts);
      if (q.includes('1=2')) return { data: '', status: 200 };
      const lenM = q.match(/(?:LENGTH|LEN)\(\(.*?\)+\s*>\s*(\d+)/);
      if (lenM) return { data: Number(lenM[1]) < secret.length ? 'OK' : '', status: 200 };
      const charM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
      if (charM) {
        const i = Number(charM[1]);
        const c = Number(charM[2]);
        return { data: c < secret.charCodeAt(i - 1) ? 'OK' : '', status: 200 };
      }
      const eqM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*=\s*(\d+)/);
      if (eqM) {
        const i = Number(eqM[1]);
        const c = Number(eqM[2]);
        return { data: c === secret.charCodeAt(i - 1) ? 'OK' : '', status: 200 };
      }
      // 完整值整体复验（P2-P7）：(version())='<完整值>'
      const wholeM = q.match(/\(version\(\)\)='([^']*)'/);
      if (wholeM) {
        stats.wholeVerifyProbes++;
        if (supportWholeVerify && wholeM[1] === secret) return { data: 'OK', status: 200 };
        return { data: '', status: 200 };
      }
      return { data: '', status: 200 };
    },
  };
}

// 时间预言机：条件为真时延迟 delayMs（判定用「耗时 ≥ 阈值」），同时计数完整值投票请求
function makeTimeOracle(secret, { supportWholeVerify = true, delayMs = 100 } = {}) {
  const stats = { wholeVerifyProbes: 0 };
  const evalTrue = (q) => {
    const lenM = q.match(/LENGTH\(\(.*?\)\)>\s*(\d+)/);
    if (lenM) return Number(lenM[1]) < secret.length;
    const charM = q.match(/ASCII\(SUBSTRING?\(\(.*?,\s*(\d+),\s*1\)\)>\s*(\d+)/);
    if (charM) {
      const i = Number(charM[1]);
      const c = Number(charM[2]);
      return c < secret.charCodeAt(i - 1);
    }
    const wholeM = q.match(/\(version\(\)\)='([^']*)'/);
    if (wholeM) {
      stats.wholeVerifyProbes++;
      return supportWholeVerify && wholeM[1] === secret;
    }
    return false;
  };
  return {
    stats,
    async request(opts) {
      const q = extractQuery(opts);
      if (evalTrue(q)) await sleep(delayMs);
      return { data: 'page', status: 200, headers: {} };
    },
  };
}

function buildCtx(httpClient, overrides = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: true },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, retry: 0, extractConcurrency: 2 },
    ...overrides,
  };
}

// ===== 布尔通道 =====

test('extractBoolean 完整值投票：整体复验通过（恰 1 次投票请求，不标记低置信）', async () => {
  const secret = '5.7.40';
  const oracle = makeBooleanOracle(secret, { supportWholeVerify: true });
  const ctx = buildCtx(oracle);
  const ex = new Extractor();
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, secret);
  assert.equal(oracle.stats.wholeVerifyProbes, 1, '应恰有 1 次完整值整体复验（非逐字符重测）');
  assert.equal(ctx.extractConfidence, undefined, '复验通过不应标记低置信');
});

test('extractBoolean 完整值投票：整体复验失败 → 值仍返回但标记低置信', async () => {
  const secret = '8.0.33';
  // 不识别完整值整体等值 → 复验判定为 false（模拟偶发误判/抖动目标）
  const oracle = makeBooleanOracle(secret, { supportWholeVerify: false });
  const ctx = buildCtx(oracle);
  const ex = new Extractor();
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, secret, '复验失败不应丢弃提取值');
  assert.equal(oracle.stats.wholeVerifyProbes, 1, '仍应恰有 1 次投票请求');
  assert.equal(ctx.extractConfidence, 'low', '复验失败应标记低置信供结果注明');
});

test('extractBoolean 完整值投票：extractVerify:false 关闭后零投票请求（与旧行为一致）', async () => {
  const secret = '8.0.33';
  const oracle = makeBooleanOracle(secret, { supportWholeVerify: true });
  const ctx = buildCtx(oracle, {
    config: { timeoutMs: 5000, retry: 0, extractConcurrency: 2, blindRobust: { extractVerify: false } },
  });
  const ex = new Extractor();
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, secret);
  assert.equal(oracle.stats.wholeVerifyProbes, 0, '关闭二次确认后不应发完整值投票请求');
});

test('extractBoolean 完整值投票：predictOutput 缓存命中不重复投票（仅首次提取复验一次）', async () => {
  const ex = new Extractor();
  const target = { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} };
  const oracle = makeBooleanOracle('5.7.40');
  const ctx1 = buildCtx(oracle, { target, scanId: 's1' });
  const r1 = await ex.extractBoolean(ctx1, 'version()');
  const probesAfterFirst = oracle.stats.wholeVerifyProbes;
  const ctx2 = buildCtx(oracle, { target, scanId: 's1' });
  ctx2.point = { id: 'p2', location: 'url', param: 'q', originalValue: '2', confirmed: true };
  const r2 = await ex.extractBoolean(ctx2, 'version()');
  assert.equal(r1, '5.7.40');
  assert.equal(r2, '5.7.40');
  assert.equal(probesAfterFirst, 1, '首次提取应恰有 1 次投票');
  assert.equal(oracle.stats.wholeVerifyProbes, probesAfterFirst, '缓存命中不应重复投票复验');
});

// ===== 时间通道 =====

test('extractTime 完整值投票：时间判定整体复验通过（恰 1 次投票请求）', async () => {
  const secret = '5.7.40';
  const oracle = makeTimeOracle(secret, { supportWholeVerify: true });
  const ctx = buildCtx(oracle, { config: { timeoutMs: 5000, retry: 0, timeThresholdMs: 50, extractConcurrency: 1 } });
  const ex = new Extractor();
  const out = await ex.extractTime(ctx, 'version()');
  assert.equal(out, secret);
  assert.equal(oracle.stats.wholeVerifyProbes, 1, '时间通道应恰有 1 次完整值投票复验');
  assert.equal(ctx.extractConfidence, undefined, '复验通过不应标记低置信');
});

test('extractTime 完整值投票：整体复验失败 → 值仍返回但标记低置信', async () => {
  const secret = '5.7.40';
  const oracle = makeTimeOracle(secret, { supportWholeVerify: false });
  const ctx = buildCtx(oracle, { config: { timeoutMs: 5000, retry: 0, timeThresholdMs: 50, extractConcurrency: 1 } });
  const ex = new Extractor();
  const out = await ex.extractTime(ctx, 'version()');
  assert.equal(out, secret, '复验失败不应丢弃提取值');
  assert.equal(oracle.stats.wholeVerifyProbes, 1, '仍应恰有 1 次投票请求');
  assert.equal(ctx.extractConfidence, 'low', '复验失败应标记低置信');
});
