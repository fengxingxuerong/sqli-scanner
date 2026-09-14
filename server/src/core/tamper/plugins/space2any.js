// 空格 → 随机可见字符：将空格替换为随机 ASCII 可见字符（对标 sqlmap space2any.py）
const CHARS = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
export const space2any = {
  name: 'space2any',
  description: '将空格替换为随机可见字符，绕过 WAF 空格过滤（引号保护）',
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
      else if (ch === ' ') out += CHARS[Math.floor(Math.random() * CHARS.length)];
      else out += ch;
    }
    return out;
  },
};
export default space2any;
