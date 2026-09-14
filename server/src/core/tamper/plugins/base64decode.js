// Base64 解码：将字符串字面量用 base64 编码后通过 FROM_BASE64 解码还原
// 对标 sqlmap base64decode.py，与 base64encode（整体编码）不同，仅操作字符串字面量
export const base64decode = {
  name: 'base64decode',
  description: '将字符串字面量 base64 编码后用 FROM_BASE64() 解码，绕过 WAF 字符串检测',
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
        out += `FROM_BASE64('${Buffer.from(str).toString('base64')}')`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === '"' && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        out += `FROM_BASE64('${Buffer.from(str).toString('base64')}')`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default base64decode;
