// ============================================================================
// detectorSupport/timingBaseline.js —— 目标级动态基线（spec 5.6.1 规则 1 / 模块 6.1）
//
// 解决什么：TimeBlindDetector 此前每次扫描重新采集基线（扫描内 μ/σ），不跨扫描积累。
// 对网络抖动目标，扫描内 5-8 个样本的 σ 估计很不稳定 → 固定 z 阈值产生系统性误判。
// 本模块按 host 维护 EWMA 均值/标准差/样本数，跨扫描积累 → 样本足够时提供更稳的基线。
//
// 降级语义（spec 5.6.1 规则 1）：样本数 < 下限时 getTimingBaseline 返回 null
// → 调用方回退到扫描内基线（零回归）。
//
// 环境变量：
//   TIMING_BASELINE_MIN_SAMPLES（默认 5）—— 返回基线的最少样本数
//   TIMING_BASELINE_MAX_HOSTS（默认 1000）—— LRU 上限
//   TIMING_BASELINE_EWMA_ALPHA（默认 0.3）—— EWMA 平滑因子
//   TIMING_BASELINE_TTL_MS（默认 3600000）—— 基线过期时间（1 小时）
// ============================================================================
const MIN_SAMPLES = Math.max(1, parseInt(process.env.TIMING_BASELINE_MIN_SAMPLES || '5', 10));
const MAX_HOSTS = Math.max(10, parseInt(process.env.TIMING_BASELINE_MAX_HOSTS || '1000', 10));
const ALPHA = Math.min(1, Math.max(0.01, parseFloat(process.env.TIMING_BASELINE_EWMA_ALPHA || '0.3')));
const TTL_MS = Math.max(60000, parseInt(process.env.TIMING_BASELINE_TTL_MS || '3600000', 10));

// host → { mean, m2, count, lastUpdate }
// m2 是 EWMA 方差的辅助量（Welford-style 在线更新的 EWMA 变体）
const store = new Map();

function extractHost(target) {
  if (!target) return null;
  if (typeof target === 'string') {
    try { return new URL(target).hostname; } catch { return target; }
  }
  if (target.hostname) return target.hostname;
  if (target.url) {
    try { return new URL(target.url).hostname; } catch { return null; }
  }
  if (target.host) return String(target.host).split(':')[0];
  return null;
}

/**
 * 获取目标级时间基线。
 * @param {string|URL|object} target 目标（URL 字符串 / URL 对象 / {hostname,url,host}）
 * @returns {{mean:number, std:number, count:number}|null}
 *   样本数 < MIN_SAMPLES 或基线过期时返回 null（调用方回退到扫描内基线）
 * ⚠ 本模块**不返回 z**：μ+z·σ 里的 z 是各检测器自己的判定策略（TimeBlindDetector 与
 *   StackedDetector 取值不同），把它塞进基线就等于让一个没人在读的对象字段决定语义。
 */
export function getTimingBaseline(target) {
  const host = extractHost(target);
  if (!host) return null;
  const entry = store.get(host);
  if (!entry) return null;
  if (Date.now() - entry.lastUpdate > TTL_MS) {
    store.delete(host);
    return null;
  }
  if (entry.count < MIN_SAMPLES) return null;
  const variance = Math.max(0, entry.m2);
  const std = Math.sqrt(variance);
  return { mean: entry.mean, std, count: entry.count };
}

/**
 * 用新样本更新目标级基线（EWMA）。
 * @param {string|URL|object} target 目标
 * @param {number} sampleMs 样本耗时（毫秒）
 */
export function updateTimingBaseline(target, sampleMs) {
  const host = extractHost(target);
  if (!host) return;
  const x = Number(sampleMs);
  if (!Number.isFinite(x) || x < 0) return;

  let entry = store.get(host);
  if (!entry) {
    entry = { mean: x, m2: 0, count: 1, lastUpdate: Date.now() };
    store.set(host, entry);
  } else {
    // EWMA 更新：mean = α·x + (1-α)·mean；方差用同样的平滑
    const delta = x - entry.mean;
    entry.mean = ALPHA * x + (1 - ALPHA) * entry.mean;
    entry.m2 = ALPHA * (delta * delta) + (1 - ALPHA) * entry.m2;
    entry.count = Math.min(entry.count + 1, Number.MAX_SAFE_INTEGER);
    entry.lastUpdate = Date.now();
  }

  // LRU 淘汰：超限时淘汰最旧（lastUpdate 最小）的 host
  if (store.size > MAX_HOSTS) {
    let oldestKey = null;
    let oldestTime = Infinity;
    for (const [k, v] of store) {
      if (v.lastUpdate < oldestTime) { oldestTime = v.lastUpdate; oldestKey = k; }
    }
    if (oldestKey) store.delete(oldestKey);
  }
}

/** 查询当前基线态（供测试/调试） */
export function getTimingBaselineState() {
  return {
    hosts: store.size,
    minSamples: MIN_SAMPLES,
    maxHosts: MAX_HOSTS,
    alpha: ALPHA,
    ttlMs: TTL_MS,
  };
}

/** 重置所有基线（仅测试用） */
export function _resetForTest() {
  store.clear();
}

export { MIN_SAMPLES, MAX_HOSTS, ALPHA, TTL_MS };