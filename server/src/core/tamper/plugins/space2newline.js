// 空格 → 换行符：将空格替换为换行符（对标 sqlmap space2newline.py）
export const space2newline = {
  name: 'space2newline',
  description: '将空格替换为换行符，绕过 WAF 空格过滤（引号保护）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const src = String(payload ?? '');
    let out = '';
    let inSingle = false, inDouble = false, inLine = false;
    for (let i = 0; i < src.length; i++) {
      const ch = src[i], prev = src[i - 1];
      if (inLine) { out += ch; if (ch === '\n') inLine = false; continue; }
      if (inSingle) { out += ch; if (ch === "'" && prev !== '\\') inSingle = false; continue; }
      if (inDouble) { out += ch; if (ch === '"' && prev !== '\\') inDouble = false; continue; }
      if (ch === "'") { inSingle = true; out += ch; }
      else if (ch === '"') { inDouble = true; out += ch; }
      else if (ch === '-' && src[i + 1] === '-') { inLine = true; out += ch; }
      else if (ch === ' ') out += '\n';
      else out += ch;
    }
    return out;
  },
};
export default space2newline;
