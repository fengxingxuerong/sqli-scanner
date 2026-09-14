// 八进制编码：将字符串字面量中的字符编码为八进制转义序列
// 对标 sqlmap octalencode.py
export const octalencode = {
  name: 'octalencode',
  description: '将字符串字面量编码为八进制转义序列，绕过 WAF 字符串检测',
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
        else out += `\\${ch.charCodeAt(0).toString(8).padStart(3, '0')}`;
        continue;
      }
      if (inDouble) {
        if (ch === '"' && prev !== '\\') { inDouble = false; out += ch; }
        else out += `\\${ch.charCodeAt(0).toString(8).padStart(3, '0')}`;
        continue;
      }
      if (ch === "'") { inSingle = true; out += ch; }
      else if (ch === '"') { inDouble = true; out += ch; }
      else out += ch;
    }
    return out;
  },
};
export default octalencode;
