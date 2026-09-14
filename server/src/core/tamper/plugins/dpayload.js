// 动态 payload：随机大小写化每个字母（对标 sqlmap dpayload.py）
// 比 randomcase 更激进：每个字母独立随机大小写
export const dpayload = {
  name: 'dpayload',
  description: '动态大小写混淆每个字母，绕过 WAF 关键字检测（比 randomcase 更激进）',
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
      else if (/[a-zA-Z]/.test(ch)) { out += Math.random() > 0.5 ? ch.toUpperCase() : ch.toLowerCase(); }
      else out += ch;
    }
    return out;
  },
};
export default dpayload;
