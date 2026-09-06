// 反斜杠 -> 正斜杠，绕过路径过滤和 WAF 规则（对标 sqlmap backslash2forward.py）
export const backslash2forward = {
  name: 'backslash2forward',
  description: '将反斜杠替换为正斜杠，绕过路径过滤（引号状态机保护字符串字面量）',
  transform(payload, ctx) {
    const src = String(payload ?? '');
    let out = '';
    let inSingle = false, inDouble = false;
    for (let i = 0; i < src.length; i++) {
      const ch = src[i];
      const prev = src[i - 1];
      if (inSingle) { out += ch; if (ch === "'" && prev !== '\\') inSingle = false; continue; }
      if (inDouble) { out += ch; if (ch === '"' && prev !== '\\') inDouble = false; continue; }
      if (ch === "'") { inSingle = true; out += ch; }
      else if (ch === '"') { inDouble = true; out += ch; }
      else if (ch === '\\') out += '/';
      else out += ch;
    }
    return out;
  },
};
export default backslash2forward;