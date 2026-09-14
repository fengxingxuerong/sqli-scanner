// JSON 编码：将字符串字面量编码为 JSON 格式（对标 sqlmap json.py）
// 适用于 JSON API 后端，对 WAF 的字符串检测绕过效果好
export const json = {
  name: 'json',
  description: '将字符串字面量 JSON 编码，绕过 JSON API WAF 检测',
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
        else out += ch;
        continue;
      }
      if (inDouble) {
        if (ch === '"' && prev !== '\\') { inDouble = false; out += ch; }
        else out += ch;
        continue;
      }
      if (ch === "'") {
        inSingle = true;
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === "'" && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        const encoded = JSON.stringify(str);
        out += `'${encoded.slice(1, -1)}'`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === '"' && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        const encoded = JSON.stringify(str);
        out += `"${encoded.slice(1, -1)}"`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default json;
