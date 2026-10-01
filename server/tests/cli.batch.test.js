// ============================================================================
// cli.batch.test.js —— 批量编排的故障隔离（对标 sqlmap -m / -l）
// ============================================================================
// 缺陷（本批修）：两处并发池都是「worker 直接 await、错误不外捕」——
// 任一目标抛错 ⇒ Promise.all reject ⇒ 整批中断、已跑完的报告全丢、且看不出是哪个目标坏的。
// 实战后果：100 个目标里第 3 个不通 ⇒ 97 个白等（ghauri 批量同款短板）。
//
// 判据不采信自报：断言的是「其它目标有没有真跑完」「失败有没有被点名」「汇总计数对不对」。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runPool, runBatch, summarizeBatch } from '../bin/cli/batchPool.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ① 单个 worker 抛错：其它项必须照常跑完（故障隔离的核心）
test('batch: 单项失败不中断整批', async () => {
  const seen = [];
  const { errors } = await runPool([1, 2, 3, 4], async (n) => {
    if (n === 2) throw new Error('boom');
    seen.push(n);
  }, 2);
  assert.deepEqual(seen.sort(), [1, 3, 4], `失败项之后的目标必须继续跑，实得 ${JSON.stringify(seen)}`);
  assert.equal(errors.length, 1);
  assert.match(errors[0].message, /boom/);
});

// ② 并发度真的生效（不是退化成串行，也不是无限并发）
test('batch: 并发度上限被遵守', async () => {
  let cur = 0;
  let peak = 0;
  await runPool(Array.from({ length: 12 }, (_, i) => i), async () => {
    cur++;
    peak = Math.max(peak, cur);
    await sleep(5);
    cur--;
  }, 3);
  assert.ok(peak <= 3, `并发峰值不应超过 3，实得 ${peak}`);
  assert.ok(peak >= 2, `应真并发（峰值 ${peak} < 2 说明退化成串行）`);
});

// ③ runBatch：失败计入 failures 且**点名**，成功项结果不丢
test('batch: 失败目标进 failures，成功结果保留', async () => {
  const logs = [];
  const { results, failures, summary } = await runBatch({
    urls: ['http://ok-1', 'http://dead', 'http://ok-2'],
    concurrency: 2,
    log: (m) => logs.push(m),
    scanOne: async (url) => {
      if (url.includes('dead')) throw new Error('ECONNREFUSED');
      return { riskLevel: 'Low', vulns: [] };
    },
  });
  assert.equal(results.length, 2, '两个成功目标的结果必须保留');
  assert.equal(failures.length, 1);
  assert.equal(failures[0].url, 'http://dead');
  assert.match(failures[0].message, /ECONNREFUSED/);
  assert.equal(summary.total, 3);
  assert.equal(summary.failed, 1);
  assert.equal(summary.ok, 2);
  assert.equal(summary.allFailed, false);
  // 失败必须在进度输出里点名（只报数字等于把"哪个没扫"变成悬案）
  assert.ok(logs.some((l) => l.includes('http://dead') && l.includes('失败')), `进度输出未点名失败目标：${JSON.stringify(logs)}`);
});

// ④ 全批失败 → allFailed=true（与「扫了但没高危」区分开，退出码语义靠它）
test('batch: 全批失败时 allFailed 为真', async () => {
  const { results, summary } = await runBatch({
    urls: ['http://dead-1', 'http://dead-2'],
    concurrency: 2,
    scanOne: async () => { throw new Error('unreachable'); },
  });
  assert.equal(results.length, 0);
  assert.equal(summary.allFailed, true);
  assert.equal(summary.hasHigh, false);
});

// ⑤ 高危检出仍要能冒泡（既有退出码 2 的语义不能被隔离逻辑吃掉）
test('batch: 高危目标照常计入 hasHigh', async () => {
  const { summary } = await runBatch({
    urls: ['http://a', 'http://b'],
    concurrency: 1,
    scanOne: async (u) => (u === 'http://a' ? { riskLevel: 'Critical', vulns: [{}] } : { riskLevel: 'Low', vulns: [] }),
  });
  assert.equal(summary.hasHigh, true);
  assert.equal(summary.byRisk.Critical, 1);
});

// ⑦ ★需复核通道★ 「扫完了但什么都没测」（0 注入点，典型=目标不通）必须与真成功区分开。
//   批量里这类目标最会骗人：退出码与成功目标一样，只有点名才能让它浮出水面。
test('batch: 0 注入点的目标进 needsReview 而非默默算成功', async () => {
  const { results, failures, needsReview, summary } = await runBatch({
    urls: ['http://dead-but-no-error', 'http://ok'],
    concurrency: 2,
    // audit 与 cli.js 里同一条判据：points 为空 ⇒ 一个检测请求都没发
    audit: (report) => (report?.points?.length === 0 ? '未发现可测注入点' : null),
    scanOne: async (url) => (url === 'http://ok'
      ? { riskLevel: 'High', vulns: [{}], points: [{ id: 'p1' }] }
      : { riskLevel: 'Low', vulns: [], points: [] }),
  });
  assert.equal(results.length, 2, '报告确实都产出了（不算编排失败）');
  assert.equal(failures.length, 0);
  assert.equal(needsReview.length, 1, '0 注入点目标必须被点名复核');
  assert.equal(needsReview[0].url, 'http://dead-but-no-error');
  assert.equal(summary.needsReview, 1);
  // 高危仍要能冒泡：needsReview 不能把真命中洗掉
  assert.equal(summary.hasHigh, true);
});

// ⑧ 空列表：不抛、汇总为 0（边界形态，批量文件里全是注释时就会走到）
test('batch: 空目标列表不抛且汇总为 0', async () => {
  const { results, failures, summary } = await runBatch({ urls: [], concurrency: 4, scanOne: async () => ({}) });
  assert.deepEqual(results, []);
  assert.deepEqual(failures, []);
  assert.equal(summary.total, 0);
  assert.equal(summarizeBatch([], [], []).allFailed, false);
});
