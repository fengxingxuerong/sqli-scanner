// 将字母字符编码为 %uXXXX（Unicode/宽字节注入绕过）。
// 目标在解码参数时会还原为原字符；对只做关键字字面匹配的 WAF 可绕过。
//
// [T-3 2026-10-07] 十六进制改用**大写**（`%u004C` 而非 `%u004c`），与上游 sqlmap
//   1.10.10 的 `'%%u%.4X'` 一致。大小写不是排版问题：`%u` 编码只按**字面**匹配，
//   WAF 规则里写成大写形态时小写变体照样命中。
// 有意保留的两处与上游不同（已记入 tamper-upstream-examples-baseline.json）：
//   ① 只编码字母、不编码数字与符号 —— 上游对整串逐字符编码（含空格/括号），
//      那要求目标侧对**整串**做 %u 解码（上游标注仅适用 ASP/ASP.NET）；
//   ② 不重复编码输入里已存在的 `%XX`（上游会把 `%20` 变成 `%u0020`）——
//      二次编码护栏：给已经编过码的点位再编一层会让请求彻底解不开。
export const charunicodeencode = {
  name: 'charunicodeencode',
  description: '将字母字符编码为 %uXXXX（宽字节/Unicode 注入绕过）',
  doctests: [
    // 大写十六进制（上游形态）
    { input: 'L', output: '%u004C' },
    { input: 'ab', output: '%u0061%u0062' },
    // ② 已编码的 %XX 不被二次编码
    { input: 'a%20b', output: '%u0061%20%u0062' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return String(payload ?? '').replace(/[A-Za-z]/g,
      (c) => '%u' + c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0'));
  },
};

export default charunicodeencode;
