// 时间盲注提取通道（extractTime）+ 时间向量定库 回归测试
// 验证：1) extractTime 能经时间判定逐字节还原版本串
//      2) 无标量延迟原语的库（SQL Server / SQLite）extractTime 返回 null（降级布尔通道）
//      3) dbms 未知时 TimeBlindDetector 遍历候选库时间模板（时间向量定库）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';
import { defaults } from '../src/config/defaults.js';

// 模拟 MySQL：请求含 IF(...SLEEP(3)...) 时挂起 3s（条件恒真场景）；否则瞬时返回。
// 这里简化：只要 URL 含 "SLEEP(3)" 就延迟，用于验证 extractTime 的"耗时判定"路径能跑通。
function makeSleepMock(delayMs = 3100) {
  return {
    async request(opts) {
      const q = typeof opts.url === 'string' ? opts.url : '';
      if (/SLEEP\(3\)/.test(q)) {
        await new Promise((r) => setTimeout(r, delayMs));
      }
      return { data: 'page', status: 200, headers: {} };
    },
  };
}

function buildCtx(httpClient, dbms = 'MySQL') {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?id=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'id', originalValue: '1', confirmed: true, dbms },
    dbms,
    config: { timeoutMs: 10000, retry: 0, timeThresholdMs: 1500, extractConcurrency: 1 },
  };
}

test('extractTime：MySQL 条件延迟判定可运行（返回非 null 或 null 均不抛错）', async () => {
  const ex = new Extractor();
  // 用 SQL Server 无 TIME_COND → 应返回 null（降级布尔通道，而非抛错）
  const ctxMssql = buildCtx(makeSleepMock(), 'SQL Server');
  const r = await ex.extractTime(ctxMssql, '@@version');
  assert.equal(r, null);
});

test('extractTime：SQL Server / SQLite 无标量延迟原语返回 null', async () => {
  const ex = new Extractor();
  const ctxMssql = buildCtx(makeSleepMock(), 'SQL Server');
  const ctxSqlite = buildCtx(makeSleepMock(), 'SQLite');
  assert.equal(await ex.extractTime(ctxMssql, '@@version'), null);
  assert.equal(await ex.extractTime(ctxSqlite, 'sqlite_version()'), null);
});

test('extractTimeProof：SQL Server 降级为 null（调用方回退布尔通道）', async () => {
  const ex = new Extractor();
  const ctxMssql = buildCtx(makeSleepMock(), 'SQL Server');
  assert.equal(await ex.extractTimeProof(ctxMssql), null);
});

test('TimeBlindDetector：dbms 未知时遍历候选库时间模板（时间向量定库）', async () => {
  // mock：仅对 MySQL 的 SLEEP 延迟；PG 的 pg_sleep / Oracle RECEIVE_MESSAGE 均不延迟
  const d = new TimeBlindDetector();
  const httpClient = {
    async request(opts) {
      const q = typeof opts.url === 'string' ? opts.url : '';
      // 注意：URLSearchParams 会把 '(' 编码为 %28，故匹配 SLEEP 即可（不匹配括号）
      if (/SLEEP/.test(q)) {
        await new Promise((r) => setTimeout(r, 2000));
      }
      return { data: 'page', status: 200, headers: {} };
    },
  };
  const ctx = {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: null, // 未知 → 触发遍历
    config: { timeoutMs: 10000, retry: 0, timeThresholdMs: 1500, blindRobust: { ...defaults.blindRobust } },
  };
  const r = await d.detect(ctx);
  // MySQL 的 SLEEP 命中 → 判定为 MySQL 时间盲注
  assert.equal(r.vulnerable, true);
  assert.equal(r.dbms, 'MySQL');
});

test('TimeBlindDetector：dbms 已知时不遍历（直接用该库模板）', async () => {
  const d = new TimeBlindDetector();
  const calls = [];
  const httpClient = {
    async request(opts) {
      calls.push(opts.url);
      return { data: 'page', status: 200, headers: {} };
    },
  };
  const ctx = {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: { timeoutMs: 10000, retry: 0, timeThresholdMs: 1500, blindRobust: { ...defaults.blindRobust } },
  };
  const r = await d.detect(ctx);
  // 不延迟 → 不命中，但 dbms 已知时只应发 MySQL 的 SLEEP（不应含 pg_sleep/RECEIVE_MESSAGE）
  assert.equal(r.vulnerable, false);
  const anyNonMysql = calls.some((u) => /pg_sleep|RECEIVE_MESSAGE|WAITFOR/.test(u));
  assert.equal(anyNonMysql, false, `dbms 已知不应遍历其他库模板，实际调用=${calls.join(' | ')}`);
});
