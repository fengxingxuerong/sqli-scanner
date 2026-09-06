// 字符 → ASCII 码编码：将字符串字面量中的字符编码为 ASCII 十进制（对标 sqlmap char2ascii.py）
// 适用于 WAF 对字符串内容的检测绕过
export const char2ascii = {
  name: 'char2ascii',
  description: '将字符串字面量编码为 ASCII 十进制数字序列，绕过 WAF 字符串检测',
  transform(payload, ctx) {
    const src = String(payload ?? '');
    let out = '';
    let inSingle = false, inDouble = false;
    for (let i = 0; i < src.length; i++) {
      const ch = src[i], prev = src[i - 1];
      if (inSingle) {
        if (ch === "'" && prev !== '\\') { inSingle = false; out += ch; }
        else out += ch.charCodeAt(0).toString();
        continue;
      }
      if (inDouble) {
        if (ch === '"' && prev !== '\\') { inDouble = false; out += ch; }
        else out += ch.charCodeAt(0).toString();
        continue;
      }
      if (ch === "'") { inSingle = true; out += ch; }
      else if (ch === '"') { inDouble = true; out += ch; }
      else out += ch;
    }
    return out;
  },
};
export default char2ascii;