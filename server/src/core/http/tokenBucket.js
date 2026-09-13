// ============================================================================
// tokenBucket.js —— 令牌桶限速（并发安全）
//
// 从 httpClient.js 抽离，[阶段② 拆上帝对象 2026-09-13]。
// 并发语义（务必保留）：acquire 经 promise 链严格串行化，每个等待者只有在前一个令牌
// 占用者结算完成后才计算 —— 否则 N 个并发等待者会在同一时刻全部放行，
// 实际突发速率 ≈ 并发数 × 设定速率（旧实现的 bug）。
// ============================================================================
import defaults from '../../config/defaults.js';

// ── 令牌桶（MERGED: perf 版——并发突发修复 + 构造参数守卫）─────────────────
// 旧实现每个并发 acquire() 各自用「入口时刻 now」计算 waitMs 并睡到同一时刻，醒来后各自按
// 「入口起经过时长」补令牌再扣 1：N 个并发等待者会在同一时刻全部放行，实际突发速率 ≈ 并发数 × 设定速率。
// 修复：acquire 经 promise 链严格串行化——每个等待者只有在前一个令牌占用者结算完成后才开始计算，
// 醒来时刻的令牌数反映「上一请求之后的真实补充量」，从而保证任意并发下平均速率 ≤ ratePerSec。
// 突发语义保留：初始 tokens = capacity = ratePerSec，满桶时可突发消耗（与旧行为一致，测试不变）。
export class TokenBucket {
  constructor(ratePerSec) {
    this.ratePerSec = Number.isFinite(ratePerSec) && ratePerSec > 0
    ? Math.min(ratePerSec, 10000) // [P0-2] 上限 10000 req/s，防配置错误打爆目标
    : defaults.ratePerSec;
    this.capacity = this.ratePerSec;
    this.tokens = this.ratePerSec;
    this.last = Date.now();
    // 串行化队列：同一桶的 acquire 结算互斥，杜绝「多个等待者同一时刻放行」的突发
    this._chain = Promise.resolve();
  }

  // 获取一个令牌（不足则等待）。返回 promise；串行化保证并发调用下的真实限速。
  acquire() {
    const run = async () => {
      const now = Date.now();
      const elapsed = (now - this.last) / 1000;
      this.tokens = Math.min(this.capacity, this.tokens + elapsed * this.ratePerSec);
      this.last = now;
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const waitMs = ((1 - this.tokens) / this.ratePerSec) * 1000;
      await new Promise((resolve) => setTimeout(resolve, waitMs));
      // 等待期间令牌按速率持续补充：醒来后重新结算并扣除 1 个，不再直接清零
      // （原实现丢掉了等待期间累积的令牌，长等待下实际速率明显低于设定值）。
      const after = Date.now();
      this.tokens = Math.min(this.capacity, this.tokens + ((after - now) / 1000) * this.ratePerSec) - 1;
      this.last = after;
    };
    const p = this._chain.then(run, run);
    // 单个结算失败不阻断后续 acquire（setTimeout/算术不会抛，此为防御）
    this._chain = p.catch(() => {});
    return p;
  }
}
