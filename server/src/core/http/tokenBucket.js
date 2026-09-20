// ============================================================================
// tokenBucket.js —— 令牌桶限速（并发安全）
//
// 从 httpClient.js 抽离，[阶段② 拆上帝对象 2026-09-13]。
// 并发语义（务必保留）：acquire 经 promise 链严格串行化，每个等待者只有在前一个令牌
// 占用者结算完成后才计算 —— 否则 N 个并发等待者会在同一时刻全部放行，
// 实际突发速率 ≈ 并发数 × 设定速率（旧实现的 bug）。
// ============================================================================

// ── 令牌桶（MERGED: perf 版——并发突发修复 + 构造参数守卫）─────────────────
// 旧实现每个并发 acquire() 各自用「入口时刻 now」计算 waitMs 并睡到同一时刻，醒来后各自按
// 「入口起经过时长」补令牌再扣 1：N 个并发等待者会在同一时刻全部放行，实际突发速率 ≈ 并发数 × 设定速率。
// 修复：acquire 经 promise 链严格串行化——每个等待者只有在前一个令牌占用者结算完成后才开始计算，
// 醒来时刻的令牌数反映「上一请求之后的真实补充量」，从而保证任意并发下平均速率 ≤ ratePerSec。
// 突发语义保留：初始 tokens = capacity = ratePerSec，满桶时可突发消耗（与旧行为一致，测试不变）。
export class TokenBucket {
  constructor(ratePerSec) {
    // [P0-FIX 2026-09-14] ratePerSec<=0 语义修正：**不限速**（原实现把 <=0 静默替换成
    // defaults.ratePerSec）。为什么要改：defaults=50 时代「0 意外变 50」掩盖了语义错位；
    // defaults 保守化到 10 后，显式传 0（对标 sqlmap --delay=0 = 不限速）的调用方
    // （如 pentest-lab 本地靶场 baseConfig ratePerSec:0）被暗中压到 10 req/s → 盲注场景
    // 时序断言全崩（实测 0/10 检出）。规则：>0 才建真桶；<=0 = 不限速（acquire 直通）。
    if (Number.isFinite(ratePerSec) && ratePerSec > 0) {
      this.ratePerSec = Math.min(ratePerSec, 10000); // [P0-2] 上限 10000 req/s，防配置错误打爆目标
      this.capacity = this.ratePerSec;
      this.tokens = this.ratePerSec;
      this.last = Date.now();
    } else {
      this.ratePerSec = 0;
      this.capacity = Number.POSITIVE_INFINITY;
      this.tokens = Number.POSITIVE_INFINITY;
      this.last = Date.now();
    }
    // 串行化队列：同一桶的 acquire 结算互斥，杜绝「多个等待者同一时刻放行」的突发
    this._chain = Promise.resolve();
  }

  // 获取一个令牌（不足则等待）。返回 promise；串行化保证并发调用下的真实限速。
  acquire() {
    // [P0-FIX 2026-09-14] 不限速桶直通：ratePerSec=0（容量 ∞）时 tokens 恒 ≥1，
    // 显式短路省掉 promise 链调度开销，也让「0=不限速」语义在代码里可见。
    if (this.ratePerSec === 0) return Promise.resolve();
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
      const settled = Math.min(this.capacity, this.tokens + ((after - now) / 1000) * this.ratePerSec) - 1;
      // [FLAKY-FIX 2026-09-20] 等待窗口由 setTimeout(小数 ms) 决定，定时器可能比所需的 waitMs
      // 早 fires 亚毫秒级 → 结算出 -0.010000…231 这种极小负数。它的含义只是"这一颗令牌还没攒满"，
      // 而我们恰好就是为这一颗等的，所以取 0；留着极小负值会让"令牌不为负"这条不变量
      // 在负载下随机翻脸（本机覆盖率门禁就是这样抖红的，不是阈值也不是逻辑回归）。
      this.tokens = Math.max(0, settled);
      this.last = after;
    };
    const p = this._chain.then(run, run);
    // 单个结算失败不阻断后续 acquire（setTimeout/算术不会抛，此为防御）
    this._chain = p.catch(() => {});
    return p;
  }
}
