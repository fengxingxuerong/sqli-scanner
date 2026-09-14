// 随机大小写所有字符：对 payload 中所有字母字符随机大小写（对标 sqlmap randomcaseall.py）
// 比 randomcase 更激进：包括所有非关键字字母
export const randomcaseall = {
  name: 'randomcaseall',
  description: '对 payload 中所有字母字符随机大小写，绕过 WAF 检测',
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
      else if (/[a-zA-Z]/.test(ch)) out += Math.random() > 0.5 ? ch.toUpperCase() : ch.toLowerCase();
      else out += ch;
    }
    return out;
  },
};
export default randomcaseall;
