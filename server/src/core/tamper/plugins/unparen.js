// 多余括号移除：移除 SQL 中多余的括号（对标 sqlmap unparen.py）
// 适用于 WAF 对括号有检测规则的场景
export const unparen = {
  name: 'unparen',
  description: '移除 SQL 中多余的括号，绕过 WAF 对括号的检测',
  transform(payload, ctx) {
    const src = String(payload ?? '');
    let out = '';
    let depth = 0;
    let inSingle = false, inDouble = false;
    for (let i = 0; i < src.length; i++) {
      const ch = src[i], prev = src[i - 1];
      if (inSingle) { out += ch; if (ch === "'" && prev !== '\\') inSingle = false; continue; }
      if (inDouble) { out += ch; if (ch === '"' && prev !== '\\') inDouble = false; continue; }
      if (ch === "'") { inSingle = true; out += ch; }
      else if (ch === '"') { inDouble = true; out += ch; }
      else if (ch === '(') { depth++; if (depth > 1) out += ch; }
      else if (ch === ')') { if (depth > 1) out += ch; depth--; }
      else out += ch;
    }
    return out;
  },
};
export default unparen;