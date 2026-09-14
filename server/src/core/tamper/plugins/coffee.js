// CoffeeScript 编码：将字符串字面量用 CoffeeScript 风格的编码（对标 sqlmap coffee.py）
// 适用于使用 CoffeeScript 的 Node.js 后端
export const coffee = {
  name: 'coffee',
  description: 'CoffeeScript 编码字符串字面量，绕过 CoffeeScript 后端 WAF',
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
        else out += `\\x${ch.charCodeAt(0).toString(16).padStart(2, '0')}`;
        continue;
      }
      if (inDouble) {
        if (ch === '"' && prev !== '\\') { inDouble = false; out += ch; }
        else out += `\\x${ch.charCodeAt(0).toString(16).padStart(2, '0')}`;
        continue;
      }
      if (ch === "'") { inSingle = true; out += ch; }
      else if (ch === '"') { inDouble = true; out += ch; }
      else out += ch;
    }
    return out;
  },
};
export default coffee;
