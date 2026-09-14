// 相等 → LIKE 替换：将 = 替换为 LIKE，绕过 = 过滤规则（对标 sqlmap noequals.py）
// 适用于 WAF 对 = 符号有严格检测规则的场景
export const noequals = {
  name: 'noequals',
  description: '将 = 替换为 LIKE，绕过 WAF 对等号的过滤规则（引号保护）',
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
      else if (ch === '=') out += 'LIKE';
      else out += ch;
    }
    return out;
  },
};
export default noequals;
