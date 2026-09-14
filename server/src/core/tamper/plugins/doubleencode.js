// 双重 URL 编码：将字符串字面量中的字符进行双重 URL 编码（对标 sqlmap doubleencode.py）
export const doubleencode = {
  name: 'doubleencode',
  description: '双重 URL 编码字符串字面量，绕过 WAF 对 URL 编码的检测',
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
        else out += `%25${ch.charCodeAt(0).toString(16).padStart(2, '0')}`;
        continue;
      }
      if (inDouble) {
        if (ch === '"' && prev !== '\\') { inDouble = false; out += ch; }
        else out += `%25${ch.charCodeAt(0).toString(16).padStart(2, '0')}`;
        continue;
      }
      if (ch === "'") { inSingle = true; out += ch; }
      else if (ch === '"') { inDouble = true; out += ch; }
      else out += ch;
    }
    return out;
  },
};
export default doubleencode;
