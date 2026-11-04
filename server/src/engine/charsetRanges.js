// ============================================================================
// charsetRanges.js —— [D202 对标 sqlmap --charset] 盲注字节提取的字符类区间
//
// 语义：把用户给的字符集（如 "0123456789abcdef"）转成按码值排序的连续区间，
// 供 blindExtractor 的类探测阶段逐个试。`--charset` 不是「报告里写个说明」，
// 而是真的改变每位置发出的 BETWEEN 探测区间 —— 目标已知字符集时能少发请求。
//
// 边界：
//   · 只收单字节码值 0..255（提取走 ASCII(SUBSTRING(...))，与既有实现同域）；
//   · 未配置 / 非法 → 返回默认区间 [[48,57],[97,122]]（数字、小写字母），
//     与 D202 之前硬编码的两类逐值等价，默认路径零回归；
//   · 最多 8 个区间：区间数即最坏情况下每位置多发的请求数，防用户给超大集合拖死扫描；
//   · 全部区间都未命中时回退全区间 [0,255] 二分（收敛语义与旧行为一致）。
// ============================================================================

/** @type {Array<[number, number]>} */
const DEFAULT_CHARSET_RANGES = [[48, 57], [97, 122]];
const MAX_CHARSET_RANGES = 8;

/**
 * @param {unknown} spec 用户字符集字符串
 * @returns {Array<[number, number]>} 排序去重后的连续区间
 */
export function charsetRanges(spec) {
  if (typeof spec !== 'string' || !spec) return DEFAULT_CHARSET_RANGES;
  /** @type {number[]} */
  const codes = [];
  for (const ch of spec) {
    const n = ch.codePointAt(0);
    if (n !== undefined && n >= 0 && n <= 255 && !codes.includes(n)) codes.push(n);
  }
  codes.sort((a, b) => a - b);
  if (!codes.length) return DEFAULT_CHARSET_RANGES;
  /** @type {Array<[number, number]>} */
  const ranges = [];
  let start = codes[0] ?? 0;
  let prev = codes[0] ?? 0;
  for (const c of codes.slice(1)) {
    if (c === prev + 1) { prev = c; continue; }
    ranges.push([start, prev]);
    start = c;
    prev = c;
  }
  ranges.push([start, prev]);
  return ranges.slice(0, MAX_CHARSET_RANGES);
}

/**
 * 类探测阶段的一次状态推进（抽成纯函数，主循环圈复杂度只减不增）。
 * @param {{lo:number,hi:number,phase:string,clsIdx:number}} s 单位置状态（原地改）
 * @param {boolean} ok 本次探测是否为真
 * @param {Array<[number, number]>} ranges 候选区间
 * @returns {void}
 */
export function classProbeStep(s, ok, ranges) {
  if (ok) {
    const hit = ranges[s.clsIdx];
    if (hit) { s.lo = hit[0]; s.hi = hit[1]; }
    s.phase = 'bisect';
  } else if (s.clsIdx + 1 < ranges.length) {
    s.clsIdx += 1;
  } else {
    s.phase = 'bisect'; // 全部候选未命中 → 回退全区间 [0,255]
  }
}
