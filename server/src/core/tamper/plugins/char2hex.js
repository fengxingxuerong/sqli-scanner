// 字符 → 十六进制转义：将字符串字面量内的字符编码为 \\xHH 转义序列（对标 sqlmap char2hex.py）
export const char2hex = {
  name: 'char2hex',
  description: '将字符串字面量内的字符编码为 \\xHH 十六进制转义序列，绕过 WAF 检测',
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
export default char2hex;