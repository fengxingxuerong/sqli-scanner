// 反转字符串：将字符串字面量反转后通过 REVERSE() 还原（对标 sqlmap reversestring.py）
// 例如：'admin' → REVERSE('nimda')
export const reversestring = {
  name: 'reversestring',
  description: '将字符串字面量反转后用 REVERSE() 还原，绕过 WAF 字符串检测',
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
        out += `REVERSE('${str.split('').reverse().join('')}')`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === '"' && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        out += `REVERSE("${str.split('').reverse().join('')}")`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default reversestring;
