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
  for (const v of echoVariants(payload)) {
    if (v && v.length > 3) t = t.split(v).join('');
  }
  // 截断型回显：目标常把用户输入截到固定长度再回显（日志/错误消息/前端省略），
  // 整串与所有变体都剔不掉，但**最长前缀**仍在 —— 逐长度递减找首个命中的前缀。
  // ⚠ 阈值 ECHO_TRUNC_MIN=16 是防误伤：低于该长度的前缀可能与真实报错文案重合，
  //    而 16 字符以上的注入值前缀只可能是回显（真报错不会恰好以注入值开头）。
  t = stripLongestPrefix(t, payload, ECHO_TRUNC_MIN);
  return t;
}

/** 截断回显的最短前缀长度（低于此不剔，防误删真实报错文本） */
export const ECHO_TRUNC_MIN = 16;

/**
 * 剔除 `t` 中出现的 `payload` 最长前缀（长度 ≥ minLen）。
 * 只剔**一次**最长的那个：更短的前缀一定包含在它里面，无需重复。
 * @param {string} t 已归一化并剔过完整变体的响应
 * @param {string} payload
 * @param {number} minLen
 * @returns {string}
 */
export function stripLongestPrefix(t, payload, minLen = ECHO_TRUNC_MIN) {
  const p = String(payload || '');
  if (p.length < minLen) return t;
  for (let n = p.length; n >= minLen; n--) {
    const pre = p.slice(0, n);
    if (t.includes(pre)) return t.split(pre).join('');
  }
  return t;
}

/**
 * payload 在响应里可能出现的**全部形态**（回显变体全集）。
 *
 * 为什么抽成独立函数（[D112 2026-10-20] 之前的形态是内联在 stripEchoedPayload 里）：
 * 本文件已经因为「抓到一个补一个」补了四轮（SQL 转义 → 反斜杠 → URL 编码 → JSON 转义），
 * 每轮都只有**当时那一种**形态被测到，其余形态仍在漏。抽出来后单测可以**逐变体矩阵**
 * 遍历（新增形态必须补进矩阵，否则矩阵会红），把「补一个漏一片」变成「补一个锁一片」。
 *
 * 每条形变的实测出处（没有出处的形态不写进来 —— 那是想象，不是证据）：
 *  · 原文 / normalizeEcho：文件路径回显（Express 404，2026-09-16 P0）
 *  · SQL 转义 `''` 与反斜杠 `\'`：recall-lab `/escape` 靶点（2026-09-17）
 *  · URL 编码：Express 404 页 `%20`/`&#39;` 混合（2026-09-16）
 *  · JSON 转义（含双层）：DVGA `/graphql` 的 errors.message（2026-10-20，D112）
 *  · Unicode `\uXXXX`：JSON 序列化器把引号写成 \u0027/\u0022（与 JSON 转义同源的另一档实现）
 *  · 双重 URL 编码：WAF/网关二次解码后再回显（与 normalizeEcho 的两轮解码对应）
 *  · base64：把用户输入编码后回显的日志/调试面
 * @param {string} payload
 * @returns {string[]} 去重后的变体（含原文）
 */
export function echoVariants(payload) {
  const p = String(payload ?? '');
  if (!p) return [];
  const variants = new Set([p, normalizeEcho(p)]);
  for (const v of [...variants]) {
    if (!v) continue;
    variants.add(v.replace(/'/g, "''")); // SQL 转义：' → ''
    variants.add(v.replace(/'/g, "\\'")); // 反斜杠转义：' → \'
  }
  try {
    variants.add(encodeURIComponent(p));
    // 双重 URL 编码（网关二次解码后回显；与 normalizeEcho 的两轮解码对应）
    variants.add(encodeURIComponent(encodeURIComponent(p)));
  } catch { /* 非法字符忽略 */ }
  try {
    const jsonEsc = JSON.stringify(p).slice(1, -1);
    variants.add(jsonEsc);
    // 双层：JSON 里再嵌一层 JSON（错误消息套娃 / 日志二次序列化）
    variants.add(JSON.stringify(jsonEsc).slice(1, -1));
  } catch { /* 非法字符忽略 */ }
  // Unicode 转义：`'` → `\u0027`、`"` → `\u0022`、`\` → `\u005c`
  // （JSON.stringify 只保证合法转义，部分序列化器把 ASCII 引号也输出成 \u 形式）
  try {
    variants.add(p.replace(/['"\\]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')));
  } catch { /* 非法字符忽略 */ }
  // base64（调试面把用户输入编码后回显）
  try {
    if (typeof Buffer !== 'undefined') variants.add(Buffer.from(p, 'utf8').toString('base64'));
  } catch { /* 非法字符忽略 */ }
  return [...variants].filter(Boolean);
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

export default { normalizeEcho, stripEchoedPayload, responseSkeleton, echoVariants, stripLongestPrefix };
