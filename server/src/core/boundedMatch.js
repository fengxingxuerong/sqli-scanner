// ============================================================================
// boundedMatch.js —— 大响应正文的有界正则匹配（[P1-PERF 2026-11-02]）
//
// 为什么需要：检测热路径会把目标可控的响应体直接喂给 `ERROR_SIG` / 拦截页正则。
// 单响应上限 10MB，一个注入点几百个探针 × 全文 match —— 大页面会把事件循环切成长条，
// 扫描期间 REST/SSE 一起卡顿（卡死风险报告 P0-1/P0-3）。
//
// 策略：按窗口切片匹配，窗口间保留 overlap（默认 256 字符），既限制单次正则的输入规模，
// 又避免「签名恰好跨窗口边界」被截断漏匹配。正则先去掉 g/y 标志，避免 lastIndex 状态
// 在多次调用间串味。
// ============================================================================

/** 单次匹配窗口（字符数）。512KB 是经验值：覆盖常见报错页前缀，同时把单次正则控制在毫秒级。 */
const MATCH_WINDOW_CHARS = 512 * 1024;

/** 窗口重叠字符数：覆盖 `[^\n]{0,80}` 这类最长跨度的签名，防止边界截断漏匹配。 */
const MATCH_WINDOW_OVERLAP = 256;

/**
 * 在长文本上做有界正则匹配。
 *
 * @param {unknown} text 待匹配文本（非字符串会被 String() 化）
 * @param {RegExp} regexp 目标正则（g/y 标志会被忽略）
 * @param {{windowChars?:number, overlap?:number}} [opts]
 * @returns {RegExpMatchArray|null} 第一个命中（与 String.match 同形）；无命中返回 null
 */
export function matchBounded(text, regexp, opts = {}) {
  const s = String(text ?? '');
  if (!s || !regexp) return null;
  const windowChars = Math.max(1024, Number(opts.windowChars) || MATCH_WINDOW_CHARS);
  const overlap = Math.max(0, Math.min(Number(opts.overlap) || MATCH_WINDOW_OVERLAP, windowChars - 1));
  // 去掉 g/y：这两个标志会让 exec/test 依赖 lastIndex，跨窗口调用会漏掉或重复命中。
  const re = new RegExp(regexp.source, regexp.flags.replace(/[gy]/g, ''));
  if (s.length <= windowChars) return s.match(re);

  let start = 0;
  while (start < s.length) {
    const end = Math.min(s.length, start + windowChars);
    // 前一窗口尾部回读 overlap：签名跨边界时仍能在当前窗口完整命中。
    const from = Math.max(0, start - overlap);
    const chunk = s.slice(from, end);
    const m = chunk.match(re);
    if (m) return m;
    if (end >= s.length) break;
    start = end;
  }
  return null;
}

/**
 * 布尔版：只判断是否存在命中（语义与 `regexp.test(text)` 一致，但输入有界）。
 * @param {unknown} text
 * @param {RegExp} regexp
 * @param {{windowChars?:number, overlap?:number}} [opts]
 * @returns {boolean}
 */
export function hasBoundedMatch(text, regexp, opts = {}) {
  return matchBounded(text, regexp, opts) !== null;
}

export default matchBounded;
