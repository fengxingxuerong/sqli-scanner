// e2e/waf-lab/waf-signatures.js
// 简化的 CRS 类 SQLi 签名集（"空格锚定"正则），用于复刻 ModSecurity CRS 类拦截。
//
// 关键设计（决定 e2e 能否演示 tamper 绕过差异）：
//   - union_select 用 /union\s+select/i（要求 UNION 与 SELECT 之间**有空白**）。
//     space2comment 把空格变成 /**/ 后，UNION 与 SELECT 之间不再是空白 → 不再匹配 → 绕过成功。
//   - 刻意**不**包含 inline_cmt(/\/\*.*\*\//) 与 quote_anom（见下），否则会误杀绕过后的请求。
//
// 有意排除的签名（坑：会破坏 space2comment 绕过机制）：
//   - inline_cmt = /\/\*.*\*\//：space2comment 的产物正是 UNION/**/SELECT，含 /**/ → 会被它拦截，
//     导致"绕过"反而被自己拦下，e2e 无法产出开>关差异。
//   - quote_anom = /'[^']*'[^']*'/：联合注入回显标记写法 'SQLISCANNER0','SQLISCANNER1' 含多个单引号，
//     会被它判定命中 → 绕过后的请求仍被拦截。
export const WAF_SIGNATURES = [
  { id: 'union_select', re: /union\s+select/i },
  { id: 'or_eq', re: /or\s+\d+\s*=\s*\d+/i },
  { id: 'comment_dash', re: /--|#/ },
  { id: 'hex_encode', re: /0x[0-9a-f]+/i },
  { id: 'sleep', re: /sleep\s*\(/i },
];

export default WAF_SIGNATURES;
