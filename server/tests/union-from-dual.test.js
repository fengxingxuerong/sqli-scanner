// UNION 探测 FROM dual 兜底测试（修复 P0 硬伤）
//
// 背景：injection.js 的 _markerProbe 构造 UNION SELECT 不带 FROM 子句。
//   Oracle/DM8/DB2 等方言 SELECT 必须带 FROM 伪表，否则直接报错 → 整条 UNION
//   探测系统性失败（漏检）。修复后：
//   - DBMS 已知（如 Oracle）→ 第一轮直接带正确 FROM 子句，一次命中
//   - DBMS 未知（null）→ 第一轮不带 FROM 失败后，追加 FROM dual 兜底探测
//
// 用例：
//   1) DBMS=Oracle：UNION SELECT 带 FROM dual 时正常回显 → 一次探测即命中
//   2) DBMS=null（未知）：第一轮不带 FROM 报错，第二轮带 FROM dual 命中
//   3) DBMS=MySQL：MySQL 支持 FROM dual，但第一轮不带 FROM 就命中，不应发额外请求
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { UnionDetector } from '../src/engine/detectors/UnionDetector.js';
import { discoverEchoColumnsDetailed } from '../src/engine/injection.js';

function extractInjected(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  return '';
}

function buildCtx(httpClient, dbms) {
  return {
    httpClient,
    target: {
      method: 'GET',
      baseUrl: 'http://mock/?q=1',
      headerParams: {},
      cookieParams: {},
      config: {},
    },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', boundary: '', confirmed: false },
    dbms,
    config: { timeoutMs: 5000, timeThresholdMs: 800, maxColumnsGuess: 4, unionSkipGate: true },
  };
}

// Oracle 模拟：SELECT 不带 FROM → 报错页；带 FROM dual → 正常回显标记
function makeOracleMock(calls) {
  return {
    async request(opts) {
      const q = extractInjected(opts);
      if (calls) calls.push(q);
      if (/ORDER BY \d+/.test(q)) {
        const n = Number(q.match(/ORDER BY (\d+)/)[1]);
        return n > 3 ? { data: 'ERR', status: 200 } : { data: 'normal', status: 200 };
      }
      if (/UNION SELECT/.test(q)) {
        // Oracle：不带 FROM dual → 报错
        if (!/FROM dual/i.test(q)) {
          return { data: 'ORA-00923: FROM keyword not found', status: 200 };
        }
        // 带 FROM dual → 正常回显
        return { data: `echo:${q}`, status: 200 };
      }
      return { data: 'normal', status: 200 };
    },
  };
}

// MySQL 模拟：不带 FROM 也正常回显（对照组）
function makeMySQLMock(calls) {
  return {
    async request(opts) {
      const q = extractInjected(opts);
      if (calls) calls.push(q);
      if (/ORDER BY \d+/.test(q)) {
        const n = Number(q.match(/ORDER BY (\d+)/)[1]);
        return n > 3 ? { data: 'ERR', status: 200 } : { data: 'normal', status: 200 };
      }
      if (/UNION SELECT/.test(q)) {
        return { data: `echo:${q}`, status: 200 };
      }
      return { data: 'normal', status: 200 };
    },
  };
}

test('DBMS=Oracle：UNION SELECT 带 FROM dual 一次命中（不再系统性漏检）', async () => {
  const calls = [];
  const ctx = buildCtx(makeOracleMock(calls), 'Oracle');
  const res = await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 3);
  assert.ok(res.cols.length > 0, 'Oracle 应能探测到回显列（带 FROM dual）');
  assert.equal(res.style, 'text');
  // 所有 UNION 探测都应带 FROM dual
  const unionCalls = calls.filter((q) => /UNION SELECT/.test(q));
  assert.ok(unionCalls.length > 0, '应发出 UNION 探测');
  assert.ok(unionCalls.every((q) => /FROM dual/i.test(q)), 'Oracle 探测应带 FROM dual');
  // DBMS 已知时不应发不带 FROM 的探测（第一轮直接带正确 FROM 子句）
  assert.ok(unionCalls.every((q) => /FROM dual/i.test(q)), '所有探测都应带 FROM dual');
});

test('DBMS=null（未知）：第一轮不带 FROM 报错失败 → 第二轮 FROM dual 兜底命中', async () => {
  const calls = [];
  const ctx = buildCtx(makeOracleMock(calls), null);
  const res = await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 3);
  assert.ok(res.cols.length > 0, 'DBMS 未知时 FROM dual 兜底应命中');
  assert.equal(res.style, 'text');
  const unionCalls = calls.filter((q) => /UNION SELECT/.test(q));
  // 第一轮（不带 FROM）+ 第二轮（带 FROM dual）
  const withoutDual = unionCalls.filter((q) => !/FROM dual/i.test(q));
  const withDual = unionCalls.filter((q) => /FROM dual/i.test(q));
  assert.ok(withoutDual.length > 0, '第一轮应发不带 FROM 的探测');
  assert.ok(withDual.length > 0, '第二轮应发带 FROM dual 的兜底探测');
});

test('DBMS=MySQL：不带 FROM 一次命中，不触发额外 FROM dual 兜底请求', async () => {
  const calls = [];
  const ctx = buildCtx(makeMySQLMock(calls), 'MySQL');
  const res = await discoverEchoColumnsDetailed(ctx.httpClient, ctx, 3);
  assert.ok(res.cols.length > 0, 'MySQL 应能探测到回显列');
  const unionCalls = calls.filter((q) => /UNION SELECT/.test(q));
  assert.equal(unionCalls.length, 1, 'MySQL 一次命中，不应发额外 FROM dual 请求');
  assert.ok(!/FROM dual/i.test(unionCalls[0]), 'MySQL 探测不应带 FROM dual');
});

test('UnionDetector 完整链路：DBMS=Oracle → 注入存在性+ORDER BY+回显列定位全通过', async () => {
  const calls = [];
  const ctx = buildCtx(makeOracleMock(calls), 'Oracle');
  const d = new UnionDetector();
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true, 'Oracle UNION 注入应被检测到');
  assert.equal(res.technique, 'union');
  assert.ok(ctx.point.confirmed, '应标记 confirmed');
  assert.ok(ctx.point.echoCols.length > 0, '应定位到回显列');
});
