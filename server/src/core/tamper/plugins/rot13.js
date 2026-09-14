// ROT13 编码：将字符串字面量中的字母用 ROT13 编码（对标 sqlmap rot13.py）
// 通过 CHAR() 函数解码还原
export const rot13 = {
  name: 'rot13',
  description: 'ROT13 编码字符串字面量，绕过 WAF 字符串检测',
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
        const encoded = str.split('').map(c => {
          if (/[a-zA-Z]/.test(c)) {
            const code = c.charCodeAt(0);
            const base = code >= 97 ? 97 : 65;
            return String.fromCharCode(base + ((code - base + 13) % 26));
          }
          return c;
        }).join('');
        out += `CONCAT(CHAR(61),'${encoded}')`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === '"' && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        const encoded = str.split('').map(c => {
          if (/[a-zA-Z]/.test(c)) {
            const code = c.charCodeAt(0);
            const base = code >= 97 ? 97 : 65;
            return String.fromCharCode(base + ((code - base + 13) % 26));
          }
          return c;
        }).join('');
        out += `CONCAT(CHAR(61),'${encoded}')`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default rot13;
