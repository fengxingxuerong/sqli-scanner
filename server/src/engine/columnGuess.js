// 共享列数二分探测：ORDER BY 二分替代线性扫描（请求数 50 → log2(50)≈6）。
//
// 判据（2026-09-17 加固 + 收敛到统一 helper）：
//   原两条 —— status>=500 或 len < baseLen*0.5。
//   实测（e2e/blackbox-lab/diag-colguess.mjs）在「SQL 报错也返回 200 + 友好页 + 回显 SQL」
//   的目标上**两条同时失效**：状态码恒 200；错误页因回显 payload 而保持长度
//   （209 vs 224，远超 baseLen*0.5 阈值）→ 二分一路判成功 → 收敛到 maxCols → 提取必败。
//
//   修复分两步走过来的：
//     ① 加「形态判据」（responseSkeleton 剥数字取骨架，与失败端点同形即判超出）；
//     ② 把二进制逻辑整体交给 `binaryProbe`（见 docs/统一探测判据-设计.md）——
//        条件判断交给调用方（本文件只给 judge/shape），
//        「两段式 + 顶到上限才自检 + capped 标记」由 helper 统一实现。
//
// 三处列数探测（UnionDetector / DBFingerprinter / Extractor）统一收敛到此，消除重复实现与判据漂移。
// 支持按注入点缓存（传 cache + cacheKey）：同一注入点的猜列结果跨检测器复用，命中即零请求。
import { binaryProbe } from './binaryProbe.js';
import { responseSkeleton } from './echoStrip.js';

const COL_GUESS_CACHE_MAX = 500;

/**
 * ORDER BY 二分猜列数（三处调用方共用，防判据漂移）。
 * @param {(n: number) => Promise<any>} probe 发送 `ORDER BY n` 并返回 {status,data} 的回调
 * @param {object} [opts]
 * @param {number} [opts.baseLen] 基线响应长度（差异比对用）
 * @param {number} [opts.maxCols] 猜测上限（默认 50）
 * @param {Map<string, number>} [opts.cache] 注入点级缓存
 * @param {string} [opts.cacheKey] 缓存键
 * @param {number} [opts.fixed] 已知列数（--union-cols），>0 时跳过猜测
 * @returns {Promise<number|null>} 列数；**capped（顶到上限且备份判据不可区分）时返回 null** —
 *   调用方约定（binaryProbe.js 头部）：capped 结果不得照用，列数 null = 让 UNION 放弃。
 */
export async function binaryGuessColumns(probe, { baseLen, maxCols = 50, cache, cacheKey, fixed } = {}) {
  // [P2-5] --union-cols：用户给定列数（sqlmap 语义：已知列数时跳过猜测，零请求）。
  const fixedN = Number(fixed);
  if (Number.isInteger(fixedN) && fixedN > 0 && fixedN <= maxCols) return fixedN;
  // 缓存命中：直接返回，不再发任何 ORDER BY 探测请求
  if (cache && cacheKey != null && cache.has(cacheKey)) {
    return /** @type {number} */ (cache.get(cacheKey)); // has() 已判定存在
  }

  const { n: ans, reliable, capped } = await doGuessColumns(probe, baseLen, maxCols);

  // [2026-10-01 落地设计约定] capped = 二分顶到 maxCols 且形态自检不可区分 ⇒ 判据已失效，
  // 数值（通常=maxCols）是垃圾。此前照原样返回并由下游照用 —— UNION 拿 50 列空转、
  // reliable=true 时还会写进模块级缓存跨扫描投毒。现返回 null 让 UNION 放弃，且不写缓存。
  if (capped) return null;

  // [CRS-FIX 2026-09-09] 不可信结果不写缓存（原实现无条件缓存 = 缓存投毒）：
  // WAF 全量拦截时每个 ORDER BY 都返回 403 短响应 —— 403 既不是 5xx，长度又远小于基线，
  // 于是被判据当成「超出列数」→ 二分收敛到 1。这个 1 一旦写入模块级缓存，后续扫描
  // （含换用有效 tamper 链的重试）会一直复用错误的列数 → UNION 永远走不通。
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

// 二分探测核心（判据 + 两段式自检由 binaryProbe 统一实现）
async function doGuessColumns(probe, baseLen, maxCols) {
  const r = await binaryProbe(probe, {
    lo: 1,
    hi: maxCols,
    // 主判据：报错状态码，或响应长度明显缩水（原两条，语义不变）
    judge: (res) => {
      const status = Number(res?.status ?? 0);
      const len = String(res?.data ?? '').length;
      return status >= 500 || len < baseLen * 0.5;
    },
    // 备份判据用的骨架：剥数字与连续空白
    shape: (res) => responseSkeleton(String(res?.data ?? '')),
    trackReliable: true,
  });
  // 列数语义：全假时回落 1（原实现 `ans <= 0 ? 1 : ans`，现由调用方显式表达）。
  return { n: r.n <= 0 ? 1 : r.n, reliable: r.reliable, capped: r.capped };
}

// 创建扫描级猜列共享缓存（按注入点 id 作 key）
export function createColumnGuessCache() {
  return new Map();
}

// 猜列缓存键的「请求形态」维度：同一注入点换 tamper 链 / 混淆开关 / 闭合符后，
// ORDER BY 探针的服务端表现会变（WAF 放行与否直接改变二分真值）——缓存键必须
// 把这些维度揉进去，否则 A 形态下猜出的列数会被 B 形态的扫描复用。
export function colGuessExtra(ctx, boundary = '') {
  const we = ctx?.config?.wafEvasion || {};
  return `${boundary}|${we.obfuscate ? 1 : 0}|${JSON.stringify(we.tamper ?? null)}`;
}

export default binaryGuessColumns;
