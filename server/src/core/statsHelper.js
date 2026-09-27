// 统计辅助工具（纯函数，零依赖）
// 用于盲注判定鲁棒性：基线分布感知（μ + z·σ）+ 一致率统计，抗网络抖动/服务端动态内容误判。

// 均值；空数组返回 0
export function mean(arr) {
  if (!arr || arr.length === 0) return 0;
  let sum = 0;
  for (const v of arr) sum += v;
  return sum / arr.length;
}

// 总体标准差（population std）；长度 < 2 返回 0
export function std(arr) {
  if (!arr || arr.length < 2) return 0;
  const m = mean(arr);
  let acc = 0;
  for (const v of arr) {
    const d = v - m;
    acc += d * d;
  }
  return Math.sqrt(acc / arr.length);
}

// @deprecated 布尔数组为 true 的比例；空数组返回 0。仅测试引用，生产代码改用 similarityRate。
export function ratioTrue(flags) {
  if (!flags || flags.length === 0) return 0;
  let n = 0;
  for (const f of flags) if (f) n++;
  return n / flags.length;
}

// 一致率：对每个 response 计算 match = (similarFn(response) === expected)，返回 match 占比。
// similarFn 由检测器注入（闭包封装其 _similarToBaseline + baselines）。
export function similarityRate(responses, similarFn, expected) {
  if (!responses || responses.length === 0) return 0;
  let hits = 0;
  for (const r of responses) {
    if (similarFn(r) === expected) hits++;
  }
  return hits / responses.length;
}

// 分布感知阈值：σ>0 用 μ+z·σ；σ=0（含基线零抖动/纯 mock）退化为 μ+absFloor（= legacy 固定阈值）
export function effectiveThreshold(mu, sigma, z, absFloor) {
  if (sigma > 0) return mu + z * sigma;
  return mu + absFloor;
}

// 基线自然抖动率（"噪声地板"）：基线响应两两比较，不相似对占比。
// similarFn(a,b) 由检测器注入（封装其相似判定）。样本 < 2 返回 0。
export function baselineNoiseRate(responses, similarFn) {
  if (!responses || responses.length < 2) return 0;
  const n = responses.length;
  const pairs = (n * (n - 1)) / 2;
  let diff = 0;
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      if (!similarFn(responses[i], responses[j])) diff++;
    }
  }
  return pairs ? diff / pairs : 0;
}

// 自适应一致率门槛：要求信号清晰程度超过目标自身噪声 + 余量，再夹在 [floor, cap] 内。
// 稳定目标(noise≈0) → 落回 floor（保持严格，控误报）；抖动目标(noise 大) → 抬高门槛（要求更明确的信号）。
export function adaptiveMinStable(noise, headroom, floor, cap) {
  const raw = (noise || 0) + (headroom || 0);
  return Math.min(cap, Math.max(floor, raw));
}

// 时间盲注自适应绝对下限：在固定阈值基础上，按基线抖动 σ 线性放宽，抑制微抖动误报。
// σ≈0（稳定目标）→ floor=absFloor（与现状一致）；σ 大（抖动目标）→ floor 更宽（更难误报）。
export function adaptiveTimeFloor(absFloor, sigma, scale = 2) {
  return (absFloor || 0) + (scale || 0) * (sigma || 0);
}

// 分块 hash（P1-D4 响应相似度升级）：把字符串切成定长块，逐块 FNV-1a hash。
// 用于「分块比对」替代朴素最长公共前缀——首部动态内容（时间戳/anti-CSRF）不再让整串 LCP 崩塌。
// P2-P3 性能：同一响应会被多次比对（基线两两比较 / 动态块过滤）——每次调用都重算整串 hash 属重复 CPU。
// 这里对 chunkHashes 结果按「字符串值」做轻量 memo 缓存，命中直接复用数组引用，避免重复 hash。
// —— 缓存治理（本版）——
// 旧实现「按条数有界（1024 条）」在字节上无界：键是完整响应体字符串，大响应（100KB+）可滞留
// 100MB+；且动态页面（时间戳每次变化）每次 body 都唯一 → 命中率≈0，每满 1024 条整体 clear
// 造成反复清空重建的抖动，缓存退化为纯开销。
// 本版改为「字节预算（约 4MB）+ 超长串（>8KB）不入缓存」：内存上界确定；大 body 走直算路径
// （分块 hash 约 1-2ns/字符，100KB ≈ 0.2ms，相对网络 RTT 可忽略），不再污染缓存。
// 注：字符串是原始值，无法直接作为 WeakMap 键（WeakMap 键必须是对象），故用「有界 Map」近似
// WeakMap 的弱引用意图；只有默认 blockSize=64 参与缓存，非默认块大小是冷路径，不污染缓存。
const CHUNK_HASH_CACHE_BYTES = 4 * 1024 * 1024; // 缓存字节预算（约 4MB）
const CHUNK_HASH_MAX_STR_LEN = 8192; // 超过该字符数的串不入缓存（防大 body 滞留/抖动）
const chunkHashCache = new Map();
let chunkHashCacheBytes = 0;
function computeChunkHashes(str, blockSize) {
  const out = [];
  for (let i = 0; i < str.length; i += blockSize) {
    const chunk = str.slice(i, i + blockSize);
    let h = 0x811c9dc5;
    for (let j = 0; j < chunk.length; j++) {
      h ^= chunk.charCodeAt(j);
      h = Math.imul(h, 0x01000193);
    }
    out.push(h >>> 0);
  }
  return out;
}
export function chunkHashes(s, blockSize = 64) {
  const str = String(s ?? '');
  if (blockSize !== 64) return computeChunkHashes(str, blockSize);
  // 大串直算不入缓存：避免大 body 逐条滞留内存 + 动态页面导致的缓存抖动
  if (str.length > CHUNK_HASH_MAX_STR_LEN) return computeChunkHashes(str, blockSize);
  const cached = chunkHashCache.get(str);
  if (cached !== undefined) {
    // LRU 触达：重新放入末尾，保持「最近使用优先」淘汰直觉
    chunkHashCache.delete(str);
    chunkHashCache.set(str, cached);
    return cached;
  }
  const out = computeChunkHashes(str, blockSize);
  if (chunkHashCacheBytes + str.length > CHUNK_HASH_CACHE_BYTES) {
    chunkHashCache.clear();
    chunkHashCacheBytes = 0;
  }
  chunkHashCache.set(str, out);
  chunkHashCacheBytes += str.length;
  return out;
}

// 分块相似率：两串分块 hash 后，按「相同 hash 块数 / 总块数」计算相似度。
// 相比 LCP，对「首部有动态内容、其余相同」的响应更鲁棒（首块不同不影响后续块匹配）。
export function chunkSimilarity(a, b, blockSize = 64) {
  // [P0-FIX 2026-09-05] 相同串短路：双空响应是完全相同（相似度 1），
  // 旧实现刻意返回 0 会导致布尔盲注把「真假页同为空 body」判为不同 → 假阳性。
  if (a === b) return 1;
  const ha = chunkHashes(a, blockSize);
  const hb = chunkHashes(b, blockSize);
  const n = Math.max(ha.length, hb.length, 1);
  const map = new Map();
  for (const h of hb) map.set(h, (map.get(h) || 0) + 1);
  let same = 0;
  for (const h of ha) {
    if (map.get(h) > 0) {
      same++;
      map.set(h, map.get(h) - 1);
    }
  }
  return same / n;
}

// 动态内容块排除（P1-D4）：基线两两分块比对，标记「高频差异块下标」为动态块；
// 返回 hasDiff(a, b)：比较 a/b 中非动态块是否仍有实质差异。
// 动态块在基线自比较中反复出现差异 → 视为时间戳/计数器等刷新变化 → 判定时剔除。
export function dynamicBlockFilter(baselines, blockSize = 64) {
  const arr = (baselines || []).map((b) => String(b ?? ''));
  if (arr.length < 2) {
    return { dynamicIdx: new Set(), hasDiff: (a, b) => String(a ?? '') !== String(b ?? '') };
  }
  const n = Math.max(...arr.map((s) => Math.ceil(s.length / blockSize)), 1);
  const diffCount = new Array(n).fill(0);
  let pairs = 0;
  for (let i = 0; i < arr.length; i++) {
    for (let j = i + 1; j < arr.length; j++) {
      pairs++;
      const ha = chunkHashes(arr[i], blockSize);
      const hb = chunkHashes(arr[j], blockSize);
      for (let k = 0; k < n; k++) {
        if ((ha[k] ?? 0) !== (hb[k] ?? 0)) diffCount[k]++;
      }
    }
  }
  const dynamicIdx = new Set();
  if (pairs > 0) {
    for (let k = 0; k < n; k++) {
      if (diffCount[k] / pairs > 0.5) dynamicIdx.add(k);
    }
  }
  const hasDiff = (a, b) => {
    const ha = chunkHashes(a, blockSize);
    const hb = chunkHashes(b, blockSize);
    const nn = Math.max(ha.length, hb.length, 1);
    for (let k = 0; k < nn; k++) {
      if (dynamicIdx.has(k)) continue; // 跳过动态块
      if ((ha[k] ?? 0) !== (hb[k] ?? 0)) return true; // 非动态块存在差异
    }
    return false;
  };
  return { dynamicIdx, hasDiff };
}

// ============================================================================
// [P1-FLAKY 2026-09-27] HTML 动态页的「标签边界 token 袋」相似判定
// （noisy 强动态页布尔漏检根治——登记于 real-mysql-lab verify.mjs [FLAKY 2026-09-23]，
//   定位工具 e2e/real-mysql-lab/load-repro.mjs）
//
// 病根：fixed-offset 分块（dynamicBlockFilter / buildDynamicSimilarFn）对「内容位移」
// 不鲁棒——变长动态段（时间戳/随机 hex/推荐位）一出现，其后所有 64B 块的边界全部错位，
// 静态内容的块 hash 被动态字节污染；块序打乱（推荐位/广告位洗牌）再叠一层。
// 实测两态翻硬币（load-repro 抓到）：过滤器退化成「全动态」时 similar 恒真（检测靠
// 二级判据兜底），落到「半动态」时基线噪声率虚高（0.40）→ 门槛抬高 → 真样本对齐
// 运气为 0 → 布尔漏检。
//
// 判据（与危害同源）：HTML 响应按标签边界（'<'）切 token——变长内容被关在单个 token
// 里，不再向后续传播位移；把「在所有基线中都出现（按最低重数）」的 token 视为稳定骨架，
// similar(a,b) = 骨架 bag 同时被 a 与 b 的 token 袋包含（无序，天然免疫块洗牌）。
// 布尔信号在骨架语义下依然成立：基线是同内容请求，凡基线间变化的必是噪声；假条件
// 缺结果行 → 结果行 token 不在假响应袋里 → 包含失败 → 判「不相似」。
//
// 边界与回退：
//   · 仅当基线呈 HTML 形态（'<' 密度达标）才可用；非 HTML 由调用方回退 positional 现状。
//   · 基线 < 2 或稳定骨架为空 → 返回 null（调用方回退现状，默认路径零变化）。
//   · token 袋按 body 串做有界 memo（同一批采样会被反复比较），超限整体清空。
// ============================================================================
function fnv1a32(str) {
  let h = 0x811c9dc5;
  for (let j = 0; j < str.length; j++) {
    h ^= str.charCodeAt(j);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** HTML 形态判据：'<' 密度 ≥ 2/100 字符（JSON/纯文本 API 回退现状） */
function isHtmlShaped(body) {
  if (!body || body.length < 8) return false;
  return ((String(body).match(/</g) ?? []).length * 100) / body.length >= 2;
}

const TOKEN_BAG_MEMO_MAX = 512;
const tokenBagMemo = new Map(); // body → Map(hash → count)

function tokenBagOf(body) {
  const hit = tokenBagMemo.get(body);
  if (hit) return hit;
  const bag = new Map();
  for (const tok of String(body ?? '').split(/(?=<)/)) {
    if (!tok) continue;
    const h = fnv1a32(tok);
    bag.set(h, (bag.get(h) ?? 0) + 1);
  }
  if (tokenBagMemo.size >= TOKEN_BAG_MEMO_MAX) tokenBagMemo.clear();
  tokenBagMemo.set(body, bag);
  return bag;
}

/**
 * HTML 动态页的稳定骨架相似判定。
 * @param {string[]} baselines 同一注入点的多次基线响应体（≥2 且均 HTML 形态）
 * @returns {function|null} (a, b) => boolean；不可用时返回 null（调用方回退现状）
 */
export function buildTokenBagSimilarFn(baselines) {
  const arr = (baselines || []).map((b) => String(b ?? '')).filter((b) => b.length > 0);
  if (arr.length < 2 || !arr.every(isHtmlShaped)) return null;
  const bags = arr.map((b) => tokenBagOf(b));
  // 稳定骨架：在所有基线中都出现（按最低重数）的 token
  const stable = new Map();
  for (const [h, c] of bags[0]) {
    let min = c;
    for (let i = 1; i < bags.length && min > 0; i++) min = Math.min(min, bags[i].get(h) ?? 0);
    if (min > 0) stable.set(h, min);
  }
  if (stable.size === 0) return null;
  const containsStable = (bag) => {
    for (const [h, c] of stable) {
      if ((bag.get(h) ?? 0) < c) return false;
    }
    return true;
  };
  // similar(a, b)：骨架同时被 a、b 包含。基线之间构造性恒相似（噪声地板=0，
  // adaptiveMinStable 落回下限——门槛语义不变）；假条件缺稳定 token → 包含失败 → 判不相似。
  return (a, b) => containsStable(tokenBagOf(a)) && containsStable(tokenBagOf(b));
}

// 两比例 z 检验：判断"注入引起的变化率"是否显著高于"基线自然抖动率"（抗误报）。
// rateA/nA = 观测组（如 false 条件响应偏离基线的比例与样本数）；
// rateB/nB = 对照组（如基线两两自比较的差异比例与配对对数）。
// 返回 z 分数（单侧用，正值=观测组显著高于对照组）。
// 分母不足（nA<1 或 nB<1）或合并比例标准误为 0 时返回 null（无法确定显著性，保守处理为"不显著"）。
export function twoProportionZ(rateA, nA, rateB, nB) {
  if (!(nA >= 1) || !(nB >= 1)) return null;
  const total = nA + nB;
  if (total < 2) return null;
  const pA = Math.min(1, Math.max(0, rateA));
  const pB = Math.min(1, Math.max(0, rateB));
  const pPool = (pA * nA + pB * nB) / total;
  const se = Math.sqrt(pPool * (1 - pPool) * (1 / nA + 1 / nB));
  if (se === 0) return null;
  return (pA - pB) / se;
}

// 显著性判定（单侧）：z > 临界值即视为"观测变化显著超过自然抖动"。
// 默认 95% 单侧 zCrit=1.645；z 为 null（无法确定）时保守返回 false（不声明确显著，避免误报）。
export function isSignificant(rateA, nA, rateB, nB, zCrit = 1.645) {
  const z = twoProportionZ(rateA, nA, rateB, nB);
  if (z === null) return false;
  return z > zCrit;
}
