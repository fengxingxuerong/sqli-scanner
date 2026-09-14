// 空格 -> <span> 标签，绕过 WAF 空格过滤规则（对标 sqlmap space2span.py）
// 适用于 HTML 解析场景，利用 <span> 标签的空白字符绕过
export const space2span = {
  name: 'space2span',
  description: '将空格替换为 <span> 标签，绕过 WAF 空格过滤（引号保护）',
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
      const ch = src[i];
      const prev = src[i - 1];
      if (inLine) { out += ch; if (ch === '\n') inLine = false; continue; }
      if (inSingle) { out += ch; if (ch === "'" && prev !== '\\') inSingle = false; continue; }
      if (inDouble) { out += ch; if (ch === '"' && prev !== '\\') inDouble = false; continue; }
      if (ch === "'") { inSingle = true; out += ch; }
      else if (ch === '"') { inDouble = true; out += ch; }
      else if (ch === '-' && src[i + 1] === '-') { inLine = true; out += ch; }
      else if (ch === ' ') out += '<span> </span>';
      else out += ch;
    }
    return out;
  },
};
export default space2span;
