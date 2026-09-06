// 时间盲注定库两段式（粗筛+确认）回归测试（[P1-FIX 2026-09-05]）
// 背景：dbms 未知时旧实现串行对 9 个候选库各跑全量采样（基线5+注入5）≈ 90 请求。
// 修复：第一段每库仅 1 条 sleep 粗筛探针（串行防 sleep 互相污染），通过者才进
//       第二段全量 robust 确认。判定语义不变（确认仍走 μ+zσ 统计检验）。
// 验证：
//   1) 正路径：仅 PostgreSQL 真延时 → 命中 PostgreSQL，且 MySQL 只发过 1 条粗筛探针；
//   2) 负路径：无任何库延时 → pg_sleep 仅 1 条粗筛请求（不再对每个候选跑全量）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function buildCtx(httpClient, overrides = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: true },
    dbms: null,
    config: {
      timeoutMs: 10000,
      retry: 0,
      timeThresholdMs: 800,
      timeBlindSleepSec: 1,
      timeBlindSamples: 2,
      blindRobust: { enabled: true, baselineSamples: 2, timeConfidenceZ: 2, minStableRatio: 0.5, concurrency: 2 },
    },
    ...overrides,
  };
}

test('两段式定库：仅 PostgreSQL 延时 → 命中 PG，MySQL 仅 1 条粗筛探针', async () => {
  const captured = [];
  const httpClient = {
    async request(opts) {
      const url = decodeURIComponent(opts.url || '');
      captured.push(url);
      if (/pg_sleep/i.test(url)) await sleep(900); // 仅 PG 执行 sleep
      else await sleep(10);
      return { data: 'page', status: 200, headers: {} };
    },
  };
  const d = new TimeBlindDetector();
  const r = await d.detect(buildCtx(httpClient));
  assert.equal(r.vulnerable, true, '应命中时间盲注');
  assert.equal(r.dbms, 'PostgreSQL', `应定库 PostgreSQL，实际 ${r.dbms}`);
  const mysqlSleep = captured.filter((u) => u.includes('AND+SLEEP(1)'));
  const pgSleep = captured.filter((u) => /pg_sleep/i.test(u));
  assert.equal(mysqlSleep.length, 1, `MySQL 应只有 1 条粗筛探针，实际 ${mysqlSleep.length} 条`);
  assert.ok(pgSleep.length >= 3, `PG 应有粗筛+基线+注入请求，实际 ${pgSleep.length} 条`);
});

test('两段式定库：无库延时 → pg_sleep 仅 1 条粗筛请求，负路径成本 ~1/5', async () => {
  const captured = [];
  const httpClient = {
    async request(opts) {
      const url = decodeURIComponent(opts.url || '');
      captured.push(url);
      await sleep(10); // 无人执行 sleep
      return { data: 'page', status: 200, headers: {} };
    },
  };
  const d = new TimeBlindDetector();
  const r = await d.detect(buildCtx(httpClient));
  assert.equal(r.vulnerable, false, '不应误报');
  const pgSleep = captured.filter((u) => /pg_sleep/i.test(u));
  assert.equal(pgSleep.length, 1, `PG 粗筛失败后不应再跑全量，实际 ${pgSleep.length} 条`);
  // MySQL 兜底全量（基线2+注入2）仍保留历史语义
  const mysqlInject = captured.filter((u) => u.includes('AND+SLEEP(1)'));
  assert.equal(mysqlInject.length, 3, `MySQL 应为 1 粗筛 + 2 注入采样，实际 ${mysqlInject.length} 条`);
});

test('粗筛阈值：延时不足 sleep·0.7 的候选不进入全量确认', async () => {
  const captured = [];
  const httpClient = {
    async request(opts) {
      const url = decodeURIComponent(opts.url || '');
      captured.push(url);
      if (/pg_sleep/i.test(url)) await sleep(200); // 200ms < 700ms 阈值 → 粗筛失败
      else await sleep(10);
      return { data: 'page', status: 200, headers: {} };
    },
  };
  const d = new TimeBlindDetector();
  const r = await d.detect(buildCtx(httpClient));
  assert.equal(r.vulnerable, false, '不足阈值不应确认');
  const pgSleep = captured.filter((u) => /pg_sleep/i.test(u));
  assert.equal(pgSleep.length, 1, `PG 应止步于粗筛，实际 ${pgSleep.length} 条`);
});
