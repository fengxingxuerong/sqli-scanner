// [B-perf] httpClient 令牌桶速率精度 + Agent 连接池上限对齐测试
// 覆盖：
//   1) 令牌桶并发 acquire 的平均速率 ≈ 设定速率（不高于、也不明显低于）
//   2) 等待期间按速率累积的令牌不被丢弃（醒来后重算并扣除，不清零——旧 bug 已修，测试钉住）
//   3) 突发语义保留：初始满桶（capacity=rate）可立即消耗
//   4) Agent maxSockets 与配置并发对齐（有限上限、≥ 理论在途峰值、公式可推导）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HttpClient, AGENT_MAX_SOCKETS, computeAgentMaxSockets } from '../src/core/httpClient.js';

test('令牌桶速率精度：并发 acquire 平均速率 ≈ 设定速率', async () => {
  const c = new HttpClient();
  const rate = 25; // 容量 25（满桶突发）+ 50 个等待 → 理论 (75-25)/25 = 2.0s
  const b = c.createBucket('tb-precision', rate);
  const total = 75;
  const t0 = Date.now();
  await Promise.all(Array.from({ length: total }, () => b.acquire()));
  const elapsed = Date.now() - t0;
  const expected = ((total - rate) / rate) * 1000;
  assert.ok(
    elapsed >= expected - 60,
    `平均速率不得高于设定（理论 ${expected}ms，实际 ${elapsed}ms）`
  );
  assert.ok(
    elapsed <= expected * 1.6 + 150,
    `平均速率不得明显低于设定（理论 ${expected}ms，实际 ${elapsed}ms；` +
      `旧版等待后清零令牌会持续拉低实际速率）`
  );
  // 扣除初始突发后的有效吞吐 ≥ 设定的 ~60%（CI 定时器抖动余量）
  const steadyRate = (total - rate) / (elapsed / 1000);
  assert.ok(steadyRate >= rate * 0.6, `稳态吞吐 ${steadyRate.toFixed(1)}/s 应 ≥ ${rate * 0.6}/s`);
});

test('令牌桶：等待期间累积的令牌不被丢弃（醒来后重算可用令牌）', async () => {
  const c = new HttpClient();
  const rate = 10;
  const b = c.createBucket('tb-accrual', rate);
  await Promise.all(Array.from({ length: rate }, () => b.acquire())); // 耗尽初始突发
  assert.ok(b.tokens < 1, '初始突发耗尽后令牌应 <1');
  // 第 rate+1 个 acquire 需等待 ~100ms；醒来后按真实经过时长结算再扣 1（不应清零/负超额）
  await b.acquire();
  // 不变量：**结算后令牌恒 ≥0**（产品侧 Math.max(0,…) 保证）。原来写的是 `>= -1e-9`，
  // 容差只是把亚毫秒舍入兜住，实际负载下测到的是 -0.01 —— 那已经穿过容差，门禁随机变红。
  assert.ok(b.tokens >= 0, `等待后令牌结算不应为负，实际 ${b.tokens}`);
  assert.ok(b.tokens <= b.capacity, '令牌不得超过容量');
  // 空闲 0.4s → 应累积 ~4 个令牌，下一个 acquire 立即可用（若等待期令牌被丢弃会再等 ~100ms）
  await new Promise((r) => setTimeout(r, 400));
  const t0 = Date.now();
  await b.acquire();
  assert.ok(Date.now() - t0 < 250, '空闲/等待期间累积的令牌不应被丢弃');
});

test('令牌桶：突发语义保留（初始满桶立即消耗）', async () => {
  const c = new HttpClient();
  const rate = 20;
  const b = c.createBucket('tb-burst', rate);
  const t0 = Date.now();
  await Promise.all(Array.from({ length: rate }, () => b.acquire()));
  assert.ok(Date.now() - t0 < 150, `初始满桶 ${rate} 个应立即可用`);
  assert.ok(b.tokens < 1);
});

test('computeAgentMaxSockets：与配置并发对齐的推导公式', () => {
  // 默认部署：8 个并发扫描 × 单扫描并发 4 = 理论在途峰值 32
  assert.equal(computeAgentMaxSockets(4, 8), 32);
  // 下限：不低于 max(concurrency*2, 16)
  assert.equal(computeAgentMaxSockets(1, 1), 16);
  assert.equal(computeAgentMaxSockets(8, 1), 16);
  // 高并发部署按峰值推导
  assert.equal(computeAgentMaxSockets(16, 8), 128);
  // 非法入参回退 defaults（concurrency=4, MAX_SCAN_API_CONCURRENT=8）
  assert.equal(computeAgentMaxSockets(undefined, undefined), 32);
  assert.equal(computeAgentMaxSockets(-3, 0), 32);
});

test('AGENT_MAX_SOCKETS：有限上限且不低于理论在途峰值', () => {
  assert.ok(Number.isFinite(AGENT_MAX_SOCKETS), 'maxSockets 必须是有限值（不得无限放大连接池）');
  assert.ok(AGENT_MAX_SOCKETS >= 16, '不得低于 max(concurrency*2, 16)');
  assert.ok(
    AGENT_MAX_SOCKETS >= 32,
    '不得低于默认部署理论在途峰值（8 并发扫描 × 4 并发）'
  );
  assert.ok(AGENT_MAX_SOCKETS <= 1000, '连接池上限应保持合理上界');
});
