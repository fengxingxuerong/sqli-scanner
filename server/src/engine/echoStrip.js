// ============================================================================
// echoStrip.js —— 响应「回显归一化」共享工具
//
// 为什么需要它（2026-09-17 归纳）：
// 同一个坑在本项目已出现三次，根因完全相同 —— **所有基于「响应长度/内容」的判定，
// 在「回显输入」的目标上都会失真**：
//   ① P0 ErrorDetector：回显 payload → ERROR_SIG 自我匹配 → 误报 6/7
//   ② L2 定库探针：回显 payload 里的标记 → 每次探测「看似成功」→ MySQL 判成 SQLite
//   ③ 列数探测：回显 SQL → 错误页不缩水 → len 判据失效 → 猜列收敛到上限 50
//
// 此前这套逻辑散落三处（ErrorDetector 内部、L2 内联、诊断脚本），判据必然漂移。
// 现收敛到这里；**新增任何基于响应内容的判定，都应先过一遍本模块**。
// ============================================================================

/**
 * 把响应文本归一化为「纯文本」：HTML 实体 → 字符 → URL 解码（两轮，防双重编码）。
 * 回显常见混合形态，例如 Express 404 页把 `'` 转成 `&#39;`、空格转成 `%20`，
 * 只还原其中一种都还原不出原文。
 * @param {string} s
 * @returns {string}
 */
export function normalizeEcho(s) {
  let t = String(s || '');
  t = t
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d) || 0))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => String.fromCharCode(parseInt(h, 16) || 0))
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, String.fromCharCode(34))
    .replace(/&apos;/g, String.fromCharCode(39))
    .replace(/&amp;/g, '&');
  for (let i = 0; i < 2; i++) {
    try {
      const d = decodeURIComponent(t.replace(/\+/g, ' '));
      if (d !== t) t = d; else break;
    } catch {
      break;
    }
  }
  return t;
}

/**
 * 剔除响应中被回显的 payload 原文（含其归一化/URL 编码变体）。
 *
 * 用途：判定「响应里是否出现了某个由表达式产生的内容」之前，先把「payload 自带的
 * 同一串」去掉，否则回显会把每一次探测都变成假阳性（见文件头 ①②）。
 *
 * 只做字符串剔除，不改变调用方原有的匹配语义。
 * @param {string} body 响应体
 * @param {string} payload 本次注入的 payload（可为空）
 * @returns {string}
 */
export function stripEchoedPayload(body, payload) {
  if (!body) return '';
  let t = normalizeEcho(body);
  if (!payload) return t;
  const variants = new Set([String(payload), normalizeEcho(payload)]);
  try {
    variants.add(encodeURIComponent(payload));
  } catch { /* 非法字符忽略 */ }
  for (const v of variants) {
    if (v && v.length > 3) t = t.split(v).join('');
  }
  return t;
}

/**
 * 响应「骨架」：剥离数字与连续空白，只保留结构性的文案与标签。
 *
 * 用途：比较两次响应是否「同形」时，长度不可靠（会被回显与 payload 长度污染），
 * 逐字比较又会被 payload 里那个变化的数字（如 `ORDER BY 4` / `ORDER BY 5`）打断。
 * 剥掉数字后，两者骨架相同 ⟺ 它们是同一类页面（同一份模板 + 同一段文案）。
 * @param {string} s
 * @returns {string}
 */
export function responseSkeleton(s) {
  return String(s || '')
    .replace(/\d+/g, 'N')
    .replace(/\s+/g, ' ')
    .trim();
}

export default { normalizeEcho, stripEchoedPayload, responseSkeleton };
