// 调度器：并发池 + 失败重试（指数退避）+ 自适应并发控制
// run(items, worker, retry) 以固定并发数执行 worker(item)。
// 速率限制统一由 HttpClient 的令牌桶负责（单一真源），此处不再重复限速。
//
// 自适应并发：根据最近 10 个请求的平均响应时间和错误率动态调整并发数。
// 适用于目标服务器响应不稳定或 WAF 限流时的自适应降级。
//
// —— 重试风暴治理（本版）——
// 旧实现：重试循环无退避，且与 HttpClient.request 内层重试（retry=2，退避 100-400ms）叠加，
// 单个失败 item 最多发出 (retry+1)×(retry+1) = 9 次物理请求。
// 本版：
//   1) 重试间增加指数退避（retryBackoffMs 起，上限 retryBackoffMaxMs）；
//   2) 调用方若已依赖 HttpClient 内层重试，应传 retry=0。
import { logger } from '../core/logger.js';

export class Scheduler {
  /**
   * @param {number} concurrency 初始并发数
   * @param {number} [ratePerSec] @deprecated 此参数不再生效，保留仅为调用点兼容。
   *   实际限速由 HttpClient 令牌桶负责（单一真源）。scanRunner 传入的 ratePerSec
   *   通过 HttpClient 的 opts.ratePerSec 路径生效，不经过 Scheduler。
   * @param {object} [options] { retryBackoffMs, retryBackoffMaxMs, adaptive }
   */
  constructor(concurrency = 4, _ratePerSec = 30, options = {}) {
    this.baseConcurrency = concurrency;
    this.concurrency = concurrency;
    // [⑰] 移除 this.ratePerSec 死参数（限速由 HttpClient 令牌桶负责，此属性误导排障）
    this.retryBackoffMs =
      Number.isFinite(options.retryBackoffMs) && options.retryBackoffMs > 0 ? options.retryBackoffMs : 200;
    this.retryBackoffMaxMs =
      Number.isFinite(options.retryBackoffMaxMs) && options.retryBackoffMaxMs > 0
        ? options.retryBackoffMaxMs
        : 1600;

    // 自适应并发
    this.adaptive = options.adaptive !== false; // 默认开启
    this.latencyWindow = []; // 滑动窗口：最近 N 个请求的耗时（ms）
    this.windowSize = 10;
    this.errorWindow = [];   // 滑动窗口：最近 N 个请求是否错误
    this.minConcurrency = 1;
    this.adjustCooldown = 0; // 冷却时间戳，避免频繁调整
    this.adjustInterval = 3000; // 最小调整间隔 3s
  }

  /** 记录单次请求耗时 + 是否失败 */
  _recordTiming(durationMs, isError) {
    this.latencyWindow.push(durationMs);
    if (this.latencyWindow.length > this.windowSize) this.latencyWindow.shift();
    this.errorWindow.push(isError ? 1 : 0);
    if (this.errorWindow.length > this.windowSize) this.errorWindow.shift();
  }

  /** 自适应调整并发数 */
  _maybeAdjust() {
    if (!this.adaptive) return;
    if (Date.now() < this.adjustCooldown) return;
    if (this.latencyWindow.length < 3) return; // 数据不足

    const avgLatency = this.latencyWindow.reduce((a, b) => a + b, 0) / this.latencyWindow.length;
    const errRate = this.errorWindow.reduce((a, b) => a + b, 0) / this.errorWindow.length;
    let old = this.concurrency;

    if (errRate > 0.2) {
      // 错误率 > 20% → 并发减半（至少 min）
      this.concurrency = Math.max(this.minConcurrency, Math.floor(this.concurrency / 2));
      if (old !== this.concurrency) {
        logger.warn(`[adaptive] concurrency ${old}→${this.concurrency} (error rate ${(errRate * 100).toFixed(0)}%)`);
      }
    } else if (avgLatency > 3000) {
      // 平均耗时 > 3s → 减 25%（至少 min）
      this.concurrency = Math.max(this.minConcurrency, Math.floor(this.concurrency * 0.75));
      if (old !== this.concurrency) {
        logger.warn(`[adaptive] concurrency ${old}→${this.concurrency} (avg latency ${avgLatency.toFixed(0)}ms)`);
      }
    } else if (avgLatency < 800 && this.concurrency < this.baseConcurrency) {
      // 平均耗时 < 800ms 且当前并发低于基准 → 恢复
      this.concurrency = Math.min(this.baseConcurrency, this.concurrency + 1);
      if (old !== this.concurrency) {
        logger.info(`[adaptive] concurrency ${old}→${this.concurrency} (avg latency ${avgLatency.toFixed(0)}ms, recovering)`);
      }
    }

    this.adjustCooldown = Date.now() + this.adjustInterval;
  }

  /**
   * 并发执行任务
   * @param {Array} items 任务列表
   * @param {Function} worker 单任务处理函数 (item) => Promise
   * @param {number} retry 失败重试次数（0=不重试）。[P1-FIX] 默认改为 0：
   *   重试统一收敛到 HttpClient 内层（调用方应依赖 HttpClient 而非本层重试），
   *   避免 (retry+1)×(HttpClient retry+1) 的双重放大（旧默认 2 时最多 9× 物理请求）。
   */
  async run(items, worker, retry = 0) {
    const queue = items.slice();
    if (queue.length <= 0) return;
    let cursor = 0;
    let active = 0; // 当前活跃 worker 数（信号量）
    let _resolvers = []; // 被暂停 worker 的恢复回调（升档时唤醒）

    // 拉取下一 item 前的并发门控：活跃数 < this.concurrency 才继续，否则等待（被升档唤醒）。
    // [P0-FIX] 动态并发真正生效：_maybeAdjust 修改 this.concurrency 后，暂停的 worker 在此被唤醒，
    // 而不是「固定 pool 无法反映降级/升档」。
    const gate = async () => {
      while (active >= this.concurrency) {
        await new Promise((resolve) => _resolvers.push(resolve));
      }
    };
    const wake = () => {
      // 升档时唤醒全部等待者（并发上限可能容纳多个新增 worker）
      const waiters = _resolvers;
      _resolvers = [];
      for (const r of waiters) r();
    };

    const next = async () => {
      while (true) {
        await gate();
        if (cursor >= queue.length) return;
        const item = queue[cursor++];
        active++;
        let lastErr;
        // [P1-FIX] 计时按单次 attempt 采样：原实现 start 在重试循环外，
        // 200+400ms 退避被计入 avgLatency → 自适应误判"响应慢"而降并发。
        // 现每次 attempt 独立计时（成功/失败各记一次），退避不再污染延迟指标。
        for (let i = 0; i <= retry; i++) {
          const attemptStart = Date.now();
          try {
            await worker(item);
            this._recordTiming(Date.now() - attemptStart, false);
            lastErr = null;
            break;
          } catch (e) {
            lastErr = e;
            this._recordTiming(Date.now() - attemptStart, true);
          }
          if (i < retry) {
            const backoffMs = Math.min(this.retryBackoffMs * 2 ** i, this.retryBackoffMaxMs);
            await new Promise((resolve) => setTimeout(resolve, backoffMs));
          }
        }
        if (lastErr) {
          logger.warn(`任务失败（已重试 ${retry} 次）：${lastErr?.message}`);
        }
        active--;
        // 每次任务完成后检查是否需要调整并发；若降级则唤醒可能阻塞的 gate
        this._maybeAdjust();
        wake();
      }
    };

    // 启动初始 pool（按当前 this.concurrency）
    const initialSize = Math.max(1, Math.min(this.concurrency, queue.length));
    const pool = Array.from({ length: initialSize }, () => next());
    await Promise.all(pool);
  }
}

export default Scheduler;