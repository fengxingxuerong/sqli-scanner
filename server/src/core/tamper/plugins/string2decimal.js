// 字符串 → 十进制：将字符串字面量编码为十进制 CHAR() 序列（对标 sqlmap string2decimal.py）
export const string2decimal = {
  name: 'string2decimal',
  description: '将字符串字面量编码为十进制 CHAR() 序列，绕过 WAF 字符串检测',
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const src = String(payload ?? '');
    let out = '';
    let inSingle = false, inDouble = false;
    for (let i = 0; i < src.length; i++) {
      const ch = src[i], prev = src[i - 1];
      if (inSingle) {
        if (ch === "'" && prev !== '\\') { inSingle = false; out += ch; }
        else out += ch;
        continue;
      }
      if (inDouble) {
        if (ch === '"' && prev !== '\\') { inDouble = false; out += ch; }
        else out += ch;
        continue;
      }
      if (ch === "'") {
        inSingle = true; let str = '';
        for (let j = i + 1; j < src.length; j++) { const c = src[j]; if (c === "'" && src[j - 1] !== '\\') { i = j; break; } str += c; }
        out += `CONCAT(${str.split('').map(c => `CHAR(${c.charCodeAt(0)})`).join(',')})`;
      } else if (ch === '"') {
        inDouble = true; let str = '';
        for (let j = i + 1; j < src.length; j++) { const c = src[j]; if (c === '"' && src[j - 1] !== '\\') { i = j; break; } str += c; }
        out += `CONCAT(${str.split('').map(c => `CHAR(${c.charCodeAt(0)})`).join(',')})`;
      } else out += ch;
    }
    return out;
  },
};
export default string2decimal;
