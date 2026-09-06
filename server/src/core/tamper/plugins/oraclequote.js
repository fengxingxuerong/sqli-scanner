// 对标 sqlmap oraclequote.py（Oracle 10g+ 专用）：
// 单引号字符串转 Oracle q-引号（'abc' -> q'[abc]'）
// q 引号用自定义定界符包裹，内部无需单引号 → 绕过单引号过滤
// 定界符候选：[] {} () <> !! || ##，选第一个不出现在字面量中的
export const oraclequote = {
  name: 'oraclequote',
  description: "单引号字符串转 Oracle q-引号（'abc' → q'[abc]'，绕过单引号过滤）",
  doctests: [
    { input: "SELECT 'abc' FROM DUAL", output: "SELECT q'[abc]' FROM DUAL" },
    { input: "'a[b'", output: "q'{a[b}'" }, // 含 [ 时选下一个定界符
    { input: "1 AND 1=1", output: '1 AND 1=1' }, // 无引号不动
  ],
  dbms: ['Oracle'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  transform(payload) {
    return String(payload ?? '').replace(/'([^']*)'/g, (m, value) => {
      const pairs = [
        ['[', ']'], ['{', '}'], ['(', ')'], ['<', '>'],
        ['!', '!'], ['|', '|'], ['#', '#'],
      ];
      for (const [start, end] of pairs) {
        if (!value.includes(start) && !value.includes(end)) {
          return `q'${start}${value}${end}'`;
        }
      }
      return m; // 所有定界符都出现 → 原样
    });
  },
};
export default oraclequote;
