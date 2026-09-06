// 字符串 → 十六进制（全部）：将所有字符串字面量编码为十六进制（对标 sqlmap string2hexall.py）
// 例如：'admin' → 0x61646d696e
export const string2hexall = {
  name: 'string2hexall',
  description: '将所有字符串字面量编码为十六进制 0xHEX，绕过 WAF 字符串检测',
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
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
        out += `0x${Buffer.from(str).toString('hex')}`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === '"' && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        out += `0x${Buffer.from(str).toString('hex')}`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default string2hexall;