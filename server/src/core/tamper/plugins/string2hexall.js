// 字符串 → 十六进制（全部）：将所有字符串字面量编码为十六进制（对标 sqlmap string2hexall.py）
// 例如：'admin' → 0x61646d696e
//
// [2026-10-05 重写] 旧实现三处真实缺陷（未闭合吞后续内容 / 转义判据只看前一字符 /
// 跨轮次 prev 失效）已修，重写为「读到闭引号才编码」的路径。
// [D57] 与 literalWalk 的回调口径完全同构，改为统一抽象调用（行为逐字不变）。
import { walkLiterals } from '../literalWalk.js';

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
    return walkLiterals(payload, {
      onLiteral: (body) => `0x${Buffer.from(body).toString('hex')}`,
    });
  },
};
export default string2hexall;
