// 字符串 → 十六进制（全部）：将所有字符串字面量编码为十六进制（对标 sqlmap string2hexall.py）
// 例如：'admin' → 0x61646d696e
//
// [2026-10-05 重写] 原实现有三个真实缺陷，其中 ② 会直接产出**发不出去**的 SQL：
//
// ① **未闭合字面量吞掉后续内容**（最重）。j 循环走完仍未遇到闭引号时，
//    `i` 停在 src.length、str 攒了剩余全部字符，然后照常输出 `0x<hex>` ——
//    既丢了开引号（字面量没闭合），又把后面的 ` AND SLEEP(5)` 一并编码进去。
//    实测：`SELECT 'unterminated` → `SELECT 0x756e...74unterminated`，语法错误。
//    WAF 一旦拦掉带引号的 payload，tamper 链正需要它**继续可用**，不能改坏。
//    修复：未闭合时放弃编码，整段连引号原样透出（宁可不改写，不可改坏）。
//
// ② **转义判别只看前一个字符**：`src[j-1] !== '\\'` 不是判据，连续反斜杠的
//    **奇偶性**才是。同型缺陷已在本目录 24 个插件、47 处出现
//    （space2morehash 已修，本文件一并修）。MySQL/MSSQL 默认反斜杠转义。
//
// ③ **`prev = src[i-1]` 跨轮次失效**：内层循环把 `i` 推到闭引号位置后，
//    `src[i-1]` 指向的是字面量内容最后一个字符而非闭引号本身，外层引号判断
//    与实际状态脱节。实测 `'a'b'c'` → `0x61b'c0x`（第二个 'a' 丢失）。
//    改为按当前下标现取，不缓存跨轮次的 prev。
//
// 重写为「读到闭引号才编码」的单一路径，同时消掉原本 inSingle/inDouble
// 两份几乎相同的状态机（重复实现 ⇒ 迟早只改一处，见 ipBytes.js 教训）。
// 转义奇偶性与字面量读取统一走 quoteScan.js（单一真源，勿再内联复制）。
import { readSqlLiteral } from '../quoteScan.js';
export const string2hexall = {
  name: 'string2hexall',
  description: '将所有字符串字面量编码为十六进制 0xHEX，绕过 WAF 字符串检测',
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const src = String(payload ?? '');
    let out = '';
    for (let i = 0; i < src.length; i++) {
      const ch = src[i];
      if (ch === "'" || ch === '"') {
        const lit = readSqlLiteral(src, i, ch);
        if (!lit.closed) {
          out += src.slice(i); // 未闭合：剩余全部原样透出（头注①）
          break;
        }
        out += `0x${Buffer.from(lit.body).toString('hex')}`;
        i = lit.end; // 跳过闭引号（头注③：不要缓存跨轮次的 prev）
        continue;
      }
      out += ch;
    }
    return out;
  },
};
export default string2hexall;
