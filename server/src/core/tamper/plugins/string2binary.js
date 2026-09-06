// 字符串 → 二进制：将字符串字面量编码为二进制 0b 表示（对标 sqlmap string2binary.py）
export const string2binary = {
  name: 'string2binary',
  description: '将字符串字面量编码为二进制 0b 表示，绕过 WAF 字符串检测',
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
        inSingle = true; let str = '';
        for (let j = i + 1; j < src.length; j++) { const c = src[j]; if (c === "'" && src[j - 1] !== '\\') { i = j; break; } str += c; }
        out += `0b${str.split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join('')}`;
      } else if (ch === '"') {
        inDouble = true; let str = '';
        for (let j = i + 1; j < src.length; j++) { const c = src[j]; if (c === '"' && src[j - 1] !== '\\') { i = j; break; } str += c; }
        out += `0b${str.split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join('')}`;
      } else out += ch;
    }
    return out;
  },
};
export default string2binary;