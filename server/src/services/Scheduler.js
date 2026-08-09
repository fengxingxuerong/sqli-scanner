// 调度器：并发池 + 失败重试
// run(items, worker, retry) 以固定并发数执行 worker(item)。
// 速率限制统一由 HttpClient 的令牌桶负责（单一真源），此处不再重复限速，
// 避免「Scheduler + HttpClient 双重令牌桶」把实际速率压到设定值以下。
export class Scheduler {
  /**
   * @param {number} concurrency 并发数
   * @param {number} ratePerSec 每秒请求上限（保留参数以兼容调用点，实际限速在 HttpClient）
   */
  constructor(concurrency = 4, ratePerSec = 3) {
    this.concurrency = concurrency;
    this.ratePerSec = ratePerSec;
  }

  /**
   * 并发执行任务
   * @param {Array} items 任务列表
   * @param {Function} worker 单任务处理函数
   * @param {number} retry 失败重试次数
   */
  async run(items, worker, retry = 2) {
    const queue = items.slice();
    let cursor = 0;

    const next = async () => {
      while (cursor < queue.length) {
        const item = queue[cursor++];
        let lastErr;
        for (let i = 0; i <= retry; i++) {
          try {
            await worker(item);
            lastErr = null;
            break;
          } catch (e) {
            lastErr = e;
          }
        }
        if (lastErr) {
          console.warn(`任务失败（已重试 ${retry} 次）：${lastErr?.message}`);
        }
      }
    };

    const poolSize = Math.min(this.concurrency, items.length);
    const pool = Array.from({ length: poolSize }, () => next());
    await Promise.all(pool);
  }
}

export default Scheduler;
