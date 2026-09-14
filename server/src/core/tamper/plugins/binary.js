// 二进制编码：将字符串字面量内的字符编码为二进制格式（对标 sqlmap binary.py）
// 对 WAF 中 SQL 关键字检测的绕过效果好，但 payload 会显著膨胀。
export const binary = {
  name: 'binary',
  description: '将字符串字面量编码为二进制表示，绕过 WAF 关键字检测',
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
      const ch = src[i];
      const prev = src[i - 1];
      if (inSingle) {
        if (ch === "'" && prev !== '\\') { inSingle = false; out += ch; }
        else out += `0b${ch.charCodeAt(0).toString(2)}`;
        continue;
      }
      if (inDouble) {
        if (ch === '"' && prev !== '\\') { inDouble = false; out += ch; }
        else out += `0b${ch.charCodeAt(0).toString(2)}`;
        continue;
      }
      if (ch === "'") { inSingle = true; out += ch; }
      else if (ch === '"') { inDouble = true; out += ch; }
      else out += ch;
    }
    return out;
  },
};
export default binary;
