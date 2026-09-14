// 随机 ASCII 编码：将随机字符用 ASCII 编码（对标 sqlmap randomascii.py）
// 对 payload 中的一些字符随机选择用 CHAR() 编码
export const randomascii = {
  name: 'randomascii',
  description: '随机选择字符用 CHAR() 编码，绕过 WAF 关键字检测',
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
      if (inSingle) { out += ch; if (ch === "'" && prev !== '\\') inSingle = false; continue; }
      if (inDouble) { out += ch; if (ch === '"' && prev !== '\\') inDouble = false; continue; }
      if (ch === "'") { inSingle = true; out += ch; }
      else if (ch === '"') { inDouble = true; out += ch; }
      else if (/[a-zA-Z]/.test(ch) && Math.random() > 0.7) {
        // 30% 概率将字母编码为 CHAR()
        out += `CHAR(${ch.charCodeAt(0)})`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default randomascii;
