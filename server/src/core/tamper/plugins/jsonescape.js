// JSON 转义：对字符串字面量内的 JSON 特殊字符做转义处理（对标 sqlmap jsonescape.py）
// 适用于 JSON API 场景
export const jsonescape = {
  name: 'jsonescape',
  description: '对字符串字面量中的 JSON 特殊字符做转义，绕过 JSON API WAF',
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
        else if (ch === '\\' || ch === '"' || ch === '\b' || ch === '\f' || ch === '\n' || ch === '\r' || ch === '\t') {
          out += '\\' + ch;
        } else {
          out += ch;
        }
        continue;
      }
      if (inDouble) {
        if (ch === '"' && prev !== '\\') { inDouble = false; out += ch; }
        else if (ch === '\\' || ch === '"' || ch === '\b' || ch === '\f' || ch === '\n' || ch === '\r' || ch === '\t') {
          out += '\\' + ch;
        } else {
          out += ch;
        }
        continue;
      }
      if (ch === "'") { inSingle = true; out += ch; }
      else if (ch === '"') { inDouble = true; out += ch; }
      else out += ch;
    }
    return out;
  },
};
export default jsonescape;
