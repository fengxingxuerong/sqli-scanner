// ============================================================================
// eventLoopWatch.js —— [D236] 事件循环滞后观测（REST 服务端）
//
// 为什么需要它（《卡死风险与优化短板-2026-11-01》§四.3 的「暗区」结论）：
//   死锁型挂死已有成套防线（SSE 清理/停扫取消/并发槽位/前端重连），真正的残余风险是
//   「性能退化型卡顿」——大 body 同步操作把事件循环切成长条时，扫描期间的 REST/SSE
//   全部卡顿，但**没有任何观测点**：出事了既无日志也无指标，只能靠人肉感知。
//   本模块补上这一道：周期采样事件循环滞后直方图，超阈值打节流告警，统计量经
//   /api/health 暴露（只放计数，符合该端点「不放路径/命令行原文」的字段口径）。
//
// 口径（别误读）：
//   · monitorEventLoopDelay 只在**事件循环空闲后恢复时**记录一次延迟——它测的是
//     「本轮同步任务让后续回调等了多久」，不是 CPU 占用率；只对 REST 长驻进程有意义，
//     CLI 一次性进程不接（扫描本身就是唯一消费者）。
//   · 直方图数值是纳秒，对外一律折算成毫秒并保留一位小数。
//   · 未启动（CLI/MCP/测试环境）时 getEventLoopStats() 返回全零——形状恒定，
//     消费方不需要判空。
// ============================================================================
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { ErrorCode, AppError } from './errors.js';
import { logger } from './logger.js';

/** @type {import('node:perf_hooks').IntervalHistogram | null} */
let hist = null;
/** @type {ReturnType<typeof setInterval> | null} */
let sampleTimer = null;
let lastWarnAt = 0;
/** @type {{thresholdMs: number, warnCooldownMs: number}} */
let cfg = { thresholdMs: 100, warnCooldownMs: 30000 };

/** @typedef {{p99Ms: number, maxMs: number, samples: number}} EventLoopStats */
/** @type {EventLoopStats} */
const stats = { p99Ms: 0, maxMs: 0, samples: 0 };

/**
 * 把一个 IntervalHistogram 形状的对象折算成毫秒统计量（纯函数，供测试注入假直方图）。
 * 直方图数值为纳秒；percentile(99) 取 p99，max 取窗口最大值。
 * @param {{max: number, percentile: (p: number) => number}} h
 * @returns {{p99Ms: number, maxMs: number}}
 */
export function summarizeHistogram(h) {
  const nsToMs = (ns) => Math.round(ns / 1e6 * 10) / 10;
  return { p99Ms: nsToMs(h.percentile(99)), maxMs: nsToMs(h.max) };
}

/**
 * 告警决策（纯函数，零墙钟断言可测）：窗口 max 超阈值、且距上次告警超过冷却期才告警。
 * lastAt=0 表示从未告警——**首次超阈值立即告警**，不受冷却期约束（否则进程启动后
 * cooldown 窗口内的首次卡顿会被吞掉，恰好漏掉运维最需要知道的那次）。
 * @param {{maxMs: number}} s 当前窗口统计量
 * @param {number} thresholdMs 告警阈值（毫秒）
 * @param {number} lastAt 上次告警时间戳（epoch ms；0 = 从未告警）
 * @param {number} now 当前时间戳（epoch ms）
 * @param {number} cooldownMs 告警冷却期（毫秒）——同一轮持续卡顿不刷屏
 * @returns {boolean} 是否应当发一条告警
 */
export function shouldWarnLag(s, thresholdMs, lastAt, now, cooldownMs) {
  if (!(s.maxMs > thresholdMs)) return false;
  if (lastAt === 0) return true;
  return now - lastAt >= cooldownMs;
}

/**
 * 启动事件循环滞后观测（REST 服务端 start() 调用；重复启动是调用方 bug，直接抛错）。
 * @param {{thresholdMs?: number, sampleMs?: number, warnCooldownMs?: number}} [opts]
 *   thresholdMs：单窗口最大滞后告警阈值（默认 100ms）；EVENT_LOOP_LAG_WARN_MS 可覆盖。
 *   sampleMs：采样周期（默认 1000ms，直方图每周期读后 reset，统计量是「最近一个窗口」）。
 *   warnCooldownMs：告警冷却期（默认 30000ms）。
 * @returns {void}
 */
export function startEventLoopWatch(opts = {}) {
  if (hist) throw new AppError(ErrorCode.INVALID_PARAM, 'eventLoopWatch 已启动（重复启动是调用方 bug）');
  cfg = {
    thresholdMs: Number(opts.thresholdMs ?? process.env.EVENT_LOOP_LAG_WARN_MS) || 100,
    warnCooldownMs: Number(opts.warnCooldownMs) || 30000,
  };
  const sampleMs = Number(opts.sampleMs) || 1000;
  hist = monitorEventLoopDelay({ resolution: 20 });
  hist.enable();
  // interval 只是 sampleWindow 的周期触发器；窗口语义与告警判定都在 sampleWindow 里
  //（导出供测试确定性驱动——见本文件底部注释与 eventLoopWatch.test.js）
  sampleTimer = setInterval(() => { try { sampleWindow(); } catch { /* stop 竞态，忽略 */ } }, sampleMs);
  sampleTimer.unref?.();
}

/**
 * 采样一个窗口（startEventLoopWatch 的 interval 周期调用；**导出供测试确定性驱动**）：
 * 读直方图 → 更新统计量 → 按阈值/冷却期节流告警 → reset 开新窗口。
 * 已知语义：一次同步长条结束后，monitorEventLoopDelay 的内部观察回调与外部采样
 * 可能同相位竞态——该长条可能落进**下一个**窗口（延迟一个采样周期可见，不影响告警本质）。
 * @param {number} [now] 当前时间戳（测试注入；默认 Date.now()）
 * @returns {EventLoopStats} 采样后的统计量快照
 * @throws {Error} 未启动时调用
 */
export function sampleWindow(now = Date.now()) {
  if (!hist) throw new AppError(ErrorCode.INVALID_PARAM, 'eventLoopWatch 未启动');
  const { p99Ms, maxMs } = summarizeHistogram(hist);
  stats.p99Ms = p99Ms;
  stats.maxMs = maxMs;
  stats.samples += 1;
  if (shouldWarnLag({ maxMs }, cfg.thresholdMs, lastWarnAt, now, cfg.warnCooldownMs)) {
    lastWarnAt = now;
    logger.warn(`事件循环滞后：本窗口最大 ${maxMs}ms（p99 ${p99Ms}ms，阈值 ${cfg.thresholdMs}ms）——存在 >${cfg.thresholdMs}ms 的同步长条任务，REST/SSE 响应会被推迟；复现时用 --cpu-prof 定位来源`);
  }
  hist.reset();
  return getEventLoopStats();
}

/**
 * 停止观测并复位统计量（优雅关闭路径调用；未启动时调用是幂等空操作）。
 * @returns {void}
 */
export function stopEventLoopWatch() {
  if (sampleTimer) { clearInterval(sampleTimer); sampleTimer = null; }
  if (hist) { hist.disable(); hist = null; }
  cfg = { thresholdMs: 100, warnCooldownMs: 30000 };
  stats.p99Ms = 0;
  stats.maxMs = 0;
  stats.samples = 0;
  lastWarnAt = 0;
}

/**
 * 当前统计量（/api/health 消费）。未启动/已停止时返回全零，形状恒定。
 * @returns {EventLoopStats} {p99Ms, maxMs, samples}——只放计数，不含任何路径/环境原文
 */
export function getEventLoopStats() {
  return { ...stats };
}
