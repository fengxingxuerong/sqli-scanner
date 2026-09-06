// 二进制 → ASCII：将字符串字面量编码为二进制位串（对标 sqlmap bin2ascii.py）
// 例如：'a' → 01100001
export const bin2ascii = {
  name: 'bin2ascii',
  description: '将字符串字面量编码为二进制位串，绕过 WAF 字符串检测',
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
  transform(payload, ctx) {
    const src = String(payload ?? '');
    let out = '';
    let inSingle = false, inDouble = false;
    for (let i = 0; i < src.length; i++) {
      const ch = src[i], prev = src[i - 1];
      if (inSingle) {
        if (ch === "'" && prev !== '\\') { inSingle = false; out += ch; }
        else out += ch.charCodeAt(0).toString(2).padStart(8, '0');
        continue;
      }
      if (inDouble) {
        if (ch === '"' && prev !== '\\') { inDouble = false; out += ch; }
        else out += ch.charCodeAt(0).toString(2).padStart(8, '0');
        continue;
      }
      if (ch === "'") { inSingle = true; out += ch; }
      else if (ch === '"') { inDouble = true; out += ch; }
      else out += ch;
    }
    return out;
  },
};
export default bin2ascii;