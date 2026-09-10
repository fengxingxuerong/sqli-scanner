// 共享列数二分探测：ORDER BY 二分替代线性扫描（请求数 50 → log2(50)≈6）。
// 判据与历史一致：基线长度 baseLen，ORDER BY n 后 status>=500 或 len<baseLen*0.5 视为超出列数。
// probe(n) 由调用方经统一 HttpClient 构造并发送 ORDER BY n 请求，返回 { status, data }（或 null）。
//
// 三处列数探测（UnionDetector / DBFingerprinter / Extractor）统一收敛到此，消除重复实现与判据漂移。
// 支持按注入点缓存（传 cache + cacheKey）：同一注入点的猜列结果跨检测器复用，命中即零请求。
const COL_GUESS_CACHE_MAX = 500;

export async function binaryGuessColumns(probe, { baseLen, maxCols = 50, cache, cacheKey, fixed } = {}) {
  // [P2-5] --union-cols：用户给定列数（sqlmap 语义：已知列数时跳过猜测，零请求）。
  // fixed > 0 时直接返回该列数，不做 ORDER BY 二分（调用方 UnionDetector/Extractor 从
  // config.unionCols 透传）。fixed 非法（非正整数/超 maxCols）时回退自动猜测。
  const fixedN = Number(fixed);
  if (Number.isInteger(fixedN) && fixedN > 0 && fixedN <= maxCols) return fixedN;
  // 缓存命中：直接返回，不再发任何 ORDER BY 探测请求
  if (cache && cacheKey != null && cache.has(cacheKey)) {
    return cache.get(cacheKey);
  }
  const { n: ans, reliable } = await doGuessColumns(probe, baseLen, maxCols);
  // [CRS-FIX 2026-09-09] 不可信结果不写缓存（原实现无条件缓存 = 缓存投毒）：
  // WAF 全量拦截时每个 ORDER BY 都返回 403 短响应 —— 403 既不是 5xx，长度又远小于基线，
  // 于是被判据当成「超出列数」→ 二分收敛到 1。这个 1 一旦写入模块级缓存，后续扫描
  // （含换用有效 tamper 链的重试）会一直复用错误的列数 → UNION 永远走不通。
  // 实测：真实 MySQL + CRS，off 链猜成 1 被缓存，之后 dash2hash/hexliterals 链全部复用该值。
  if (cache && cacheKey != null && reliable) {
    // P1: 淘汰最旧条目防 Map 无界增长（长驻进程跨扫描累积）
    if (cache.size >= COL_GUESS_CACHE_MAX && typeof cache.keys === 'function') {
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) cache.delete(oldest);
    }
    cache.set(cacheKey, ans);
  }
  return ans;
}

// 二分探测核心（无缓存逻辑，供 binaryGuessColumns 调用）
async function doGuessColumns(probe, baseLen, maxCols) {
  let lo = 1;
  let hi = maxCols;
  let ans = 0;
  // reliable：二分过程中是否至少拿到一次正常业务响应（2xx/3xx）。
  // 全为 403/429 等拦截响应说明探测根本没触达 SQL，结果不可信（不可缓存）。
  let reliable = false;
  while (lo <= hi) {
    const mid = Math.floor((lo + hi) / 2);
    const res = await probe(mid);
    const status = Number(res?.status ?? 0);
    const len = String(res?.data ?? '').length;
    if (status >= 200 && status < 400) reliable = true;
    if (status >= 500 || len < baseLen * 0.5) {
      hi = mid - 1;
    } else {
      ans = mid;
      lo = mid + 1;
    }
  }
  return { n: ans <= 0 ? 1 : ans, reliable };
}

// 创建扫描级猜列共享缓存（按注入点 id 作 key）
export function createColumnGuessCache() {
  return new Map();
}

export default binaryGuessColumns;
