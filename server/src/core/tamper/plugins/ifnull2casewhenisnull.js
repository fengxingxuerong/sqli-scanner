// IFNULL(a, b) 转 CASE WHEN ISNULL(a) THEN (b) ELSE (a) END，变换函数形态
//
// [T-8 2026-10-07] 对齐上游 sqlmap 1.10.10 tamper/ifnull2casewhenisnull.py 的三处：
//   ① **分支加括号** `THEN (b) ELSE (a)` —— 旧实现不加，分支为复合表达式时
//      （如 `IFNULL(a, b AND c)`）会被算子优先级吞掉，语义静默改变；
//   ② **括号深度感知**：旧实现用 `([^,]+),\s*([^)]+)` 抓参数，遇到嵌套函数调用
//      （`IFNULL(IFNULL(a,b),c)`）会在第一个 `)` 处提前收尾 ⇒ 产出畸形 SQL；
//      现按上游逐字符扫 depth，只在 depth==1 处认逗号与右括号；
//   ③ **引号感知**：逗号/括号落在字符串字面量内时不计数（上游同判据）。
//      转义判据沿用本仓单一真源 quoteScan.js 的 isQuoteEscaped（比上游"看前一个
//      字符是不是反斜杠"更严），上游三条示例不受影响。
// ⚠️ 与上游一致：替换后若参数里还嵌着 IFNULL(，会继续被展开（上游 while 循环同理），
//    ⇒ 嵌套形态会被**逐层展开**，这不是无限递归（嵌套深度单调下降）。
import { isQuoteEscaped } from '../quoteScan.js';

const NEEDLE_RE = /IFNULL\(/gi;

export const ifnull2casewhenisnull = {
  name: 'ifnull2casewhenisnull',
  description: '将 IFNULL(a, b) 改写为 CASE WHEN ISNULL(a) THEN (b) ELSE (a) END',
  doctests: [
    // 上游官方示例（tag 1.10.10）
    { input: 'IFNULL(1, 2)', output: 'CASE WHEN ISNULL(1) THEN (2) ELSE (1) END' },
    { input: 'IFNULL(a,b)', output: 'CASE WHEN ISNULL(a) THEN (b) ELSE (a) END' },
    // ③ 字面量内的逗号不参与切分
    { input: "IFNULL('a,b',c)", output: "CASE WHEN ISNULL('a,b') THEN (c) ELSE ('a,b') END" },
    // 不配对 ⇒ 放弃，绝不猜
    { input: 'IFNULL(a,b', output: 'IFNULL(a,b' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    let s = String(payload ?? '');
    for (;;) {
      NEEDLE_RE.lastIndex = 0;
      const hit = NEEDLE_RE.exec(s);
      if (!hit) break;
      const index = hit.index;
      const argStart = index + hit[0].length;
      let depth = 1;
      let comma = -1;
      let end = -1;
      let inSingle = false;
      let inDouble = false;
      for (let i = argStart; i < s.length; i++) {
        const c = s[i];
        if (c === "'" && !isQuoteEscaped(s, i)) inSingle = !inSingle;
        else if (c === '"' && !isQuoteEscaped(s, i)) inDouble = !inDouble;
        if (inSingle || inDouble) continue;
        if (depth === 1 && c === ',') { comma = i; continue; }
        if (depth === 1 && c === ')') { end = i; break; }
        if (c === '(') depth++;
        else if (c === ')') depth--;
      }
      // 找不到成对的分隔符 ⇒ 放弃整条（上游同样是 break），绝不猜
      if (comma < 0 || end < 0) break;
      const a = s.slice(argStart, comma);
      const b = s.slice(comma + 1, end).replace(/^\s+/, '');
      s = `${s.slice(0, index)}CASE WHEN ISNULL(${a}) THEN (${b}) ELSE (${a}) END${s.slice(end + 1)}`;
    }
    return s;
  },
};
export default ifnull2casewhenisnull;
