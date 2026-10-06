// ============================================================================
// quoteScan.js —— SQL 字面量扫描的**单一真源**
//
// ── 为什么单独抽出来 ────────────────────────────────────────────────────────
// 2026-10-05 发现同型缺陷在 tamper/plugins/ 里重复了 23 个文件、47 处：
//   `src[i - 1] !== '\\'` 被用来判断"这个引号是否被转义"。
// 那不是判据。真正的判据是**连续反斜杠的奇偶性**：
//   'a\'    1 个反斜杠 ⇒ 末位 ' 被转义，字面量**未闭合**
//   'a\\'   2 个反斜杠 ⇒ 末位 ' 未被转义，字面量**闭合**
//
// 只看前一个字符会把后两种一律判成"被转义"。后果分两档：
//   · 状态机式（safedog / space2morehash / if2case）：引号状态永不复位 ⇒
//     该引号之后整段文本都被当成字面量，关键字不再混淆（原样发出撞 WAF）、
//     空格替换也一并失效 —— **全盘失效**。
//   · 一次性扫描式（str2hex / rot13 / xor 等 20 余个）：单次扫描边界错，
//     字面量内容与外部内容互相污染 —— 输出非法 SQL。
//
// 抽成单一真源而不是逐个改 23 遍，理由与 Extractor.js 的 posInt、ipBytes.js
// 的教训一致：**同一判据多份实现，必然只改一处**。
// ============================================================================

/**
 * 该位置的引号是否被反斜杠转义（按连续反斜杠的**奇偶性**判定）。
 *
 * @param {string} s 被扫描的字符串
 * @param {number} idx 引号所在下标
 * @returns {boolean} 前面是奇数个连续反斜杠 ⇒ 被转义
 */
export function isQuoteEscaped(s, idx) {
  let n = 0;
  for (let k = idx - 1; k >= 0 && s[k] === '\\'; k--) n++;
  return n % 2 === 1;
}

/**
 * 从 start 处读取一个 SQL 字符串字面量。
 *
 * @param {string} s 源串
 * @param {number} start 开引号所在下标
 * @param {'"'|'\''} quote 引号字符
 * @returns {{start:number, end:number, body:string, closed:boolean}}
 *   closed=false 表示扫描到末尾仍未闭合 —— 调用方**必须**区别对待：
 *   绝不能把未闭合的剩余内容当字面量编码掉（会产出语法错误的 SQL）。
 */
export function readSqlLiteral(s, start, quote) {
  let body = '';
  for (let j = start + 1; j < s.length; j++) {
    if (s[j] === quote && !isQuoteEscaped(s, j)) {
      return { start, end: j, body, closed: true };
    }
    body += s[j];
  }
  return { start, end: s.length - 1, body, closed: false };
}

/**
 * 把字符串按「字面量 / 非字面量」分段，供 transform 逐段处理。
 *
 * 这是本模块的主力函数：绝大多数 tamper 的语义都是
 *   「引号内的东西不动（或按字面量处理），引号外的才做替换/编码」。
 * 过去 20 多个插件各写一遍内层扫描循环，于是判据漂移、各自出错。
 *
 * 契约（务必按此使用，否则重蹈"未闭合被吃掉"的覆辙）：
 *   · 返回的每段都带 kind，'literal' 段的 text **不含**引号本身
 *   · **未闭合**的字面量，其后所有内容合并为**最后一个** literal 段，
 *     且 closed=false —— 调用方看到 closed=false 时应当放弃编码、原样输出，
 *     绝不能只输出半截编码结果（那会产出发不出去的 SQL）
 *
 * @param {string} s 源串
 * @param {'"'|'\''} quote 引号字符
 * @returns {Array<{kind:'text'|'literal', text:string, closed:boolean}>}
 */
export function splitByLiteral(s, quote) {
  /** @type {Array<{kind:'text'|'literal', text:string, closed:boolean}>} */
  const segs = [];
  let i = 0;
  while (i < s.length) {
    const j = s.indexOf(quote, i);
    if (j < 0) {
      if (i < s.length) segs.push({ kind: 'text', text: s.slice(i), closed: true });
      break;
    }
    if (j > i) segs.push({ kind: 'text', text: s.slice(i, j), closed: true });
    const lit = readSqlLiteral(s, j, quote);
    segs.push({ kind: 'literal', text: lit.body, closed: lit.closed });
    if (!lit.closed) break;              // 未闭合：剩余已全部并入本段
    i = lit.end + 1;
  }
  return segs;
}
