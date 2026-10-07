// CONCAT() 转 CONCAT_WS(MID(CHAR(0),0,0), ...)，变换函数形态
//
// [T-5 2026-10-07] 对齐上游 sqlmap 1.10.10 tamper/concat2concatws.py 的两处：
//   ① **分隔符改用 `MID(CHAR(0),0,0)`**（旧为 `CHAR(32)`）。`CHAR(32)` 是空格的
//      字面写法，分隔符本身仍以空白形态出现 ⇒ 打空白/CHAR(32) 型规则时等于没换；
//      `MID(CHAR(0),0,0)` 求值为空串，CONCAT_WS 的拼接语义不变而形态里不再有空格。
//   ② **`GROUP_CONCAT(` 保护**：上游用 `(?<!GROUP_)CONCAT\(` —— 旧实现没有这个
//      后视断言，`GROUP_CONCAT(x)` 会被改成 `GROUP_CONCAT_WS(...)`，
//      这是**不存在的函数**（MySQL 只有 GROUP_CONCAT）⇒ 直接产出非法 SQL。
//      该漏包与 D7 那次 `equaltorlike` 兄弟件漏改是同一族缺陷（同型只修了一半）。
export const concat2concatws = {
  name: 'concat2concatws',
  description: '将 CONCAT(...) 改写为 CONCAT_WS(MID(CHAR(0),0,0), ...)，变换函数形态（跳过 GROUP_CONCAT）',
  doctests: [
    // 上游官方示例（tag 1.10.10）
    { input: 'CONCAT(1,2)', output: 'CONCAT_WS(MID(CHAR(0),0,0),1,2)' },
    { input: 'CONCAT(a,b)', output: 'CONCAT_WS(MID(CHAR(0),0,0),a,b)' },
    // ② GROUP_CONCAT 不得被切开
    { input: 'GROUP_CONCAT(a)', output: 'GROUP_CONCAT(a)' },
    { input: 'group_concat(a)', output: 'group_concat(a)' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return String(payload ?? '').replace(/(?<!GROUP_)CONCAT\(/gi, 'CONCAT_WS(MID(CHAR(0),0,0),');
  },
};
export default concat2concatws;
