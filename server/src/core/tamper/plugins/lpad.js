// 字符串 → LPAD 包装：将字符串字面量包装为 LPAD(char,length,string) 调用
// 对标 sqlmap lpad.py，绕过 WAF 字符串检测
export const lpad = {
  name: 'lpad',
  description: '将字符串字面量包装为 LPAD() 调用，绕过 WAF 字符串检测',
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
        out += `LPAD('${str}',${str.length + 1},'${str.slice(0, 1) || 'x'}')`;
      } else if (ch === '"') {
        inDouble = true;
        let str = '';
        for (let j = i + 1; j < src.length; j++) {
          const c = src[j];
          if (c === '"' && src[j - 1] !== '\\') { i = j; break; }
          str += c;
        }
        out += `LPAD("${str}",${str.length + 1},"${str.slice(0, 1) || 'x'}")`;
      } else {
        out += ch;
      }
    }
    return out;
  },
};
export default lpad;