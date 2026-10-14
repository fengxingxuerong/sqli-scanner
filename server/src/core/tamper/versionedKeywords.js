// ============================================================================
// versionedKeywords.js —— 版本化注释族的**关键字表单一真源**（T-6，2026-10-14）
//
// 为什么抽出来：versionedmorekeywords / halfversionedmorekeywords 两件套的关键字表
// **逐字相同**（33 词），各自维护一份 = 「同一判据多份实现，必然只改一处」——这正是
// literalWalk / quoteScan 收敛前的同一族病灶。T-6 补函数名时一次改动即两处生效。
//
// [T-6] 补**函数名**：上游 morekeywords 族对函数名同样做版本化包裹
// （CONCAT / CHAR / IFNULL / CAST / CURRENT_USER …）。函数名是 WAF 关键字检测的
// 主要目标之一——漏包它们属**同族内不自洽**：examples 反测实测上游包 CONCAT、
// 本仓不包（见 tamper-upstream-examples-baseline.json 的 drift 记录）。
//
// ⚠️ 顺序约束（正则 alternation 从左到右，先到先得）：**长词必须排在短词之前**，
// 否则 `CURRENT_USER` 里的 `USER`、`GROUP_CONCAT` 里的 `COUNT` 会被截断匹配。
//   GROUP_CONCAT < COUNT ✅　CURRENT_USER < USER ✅　SUBSTRING 无冲突
//   （关键字表里的 DATABASE / VERSION 兼作函数名，无需重复登记）
// ============================================================================

/**
 * 版本化注释「更激进」档的关键字表（关键字 + 函数名），已按长词优先排序。
 * **模块内私有**：外部只需 versionedWordsRe()，直接导出本表会被死代码门禁记为
 * 未使用导出（消费方全在同文件内）。
 * @type {string[]}
 */
const MORE_VERSIONED_WORDS = [
  // —— SQL 关键字（原 33 词，字面不动）——
  'SELECT', 'UNION', 'ALL', 'DISTINCT', 'FROM', 'WHERE', 'AND', 'ORDER', 'BY',
  'GROUP', 'HAVING', 'LIMIT', 'OFFSET', 'INSERT', 'UPDATE', 'DELETE', 'INTO',
  'VALUES', 'SET', 'DROP', 'CREATE', 'TABLE', 'DATABASE', 'VERSION', 'JOIN',
  'ON', 'BETWEEN', 'LIKE', 'NULL', 'IS', 'IN', 'NOT', 'AS',
  // —— 函数名（T-6 新增：上游同族覆盖，漏包即同族不自洽）——
  'GROUP_CONCAT', 'CURRENT_USER', 'SESSION_USER', 'SUBSTRING', 'CONCAT',
  'IFNULL', 'NULLIF', 'COALESCE', 'BENCHMARK', 'CONVERT', 'SLEEP', 'CHAR',
  'CAST', 'COUNT', 'ASCII', 'BINARY', 'SCHEMA', 'MID', 'ORD', 'USER', 'IF',
];

/**
 * 按上表编译出「全词匹配 + 忽略大小写」的正则（带捕获组，供 $1 回引）。
 * @param {string[]} [words]
 * @returns {RegExp}
 */
export function versionedWordsRe(words = MORE_VERSIONED_WORDS) {
  return new RegExp(`\\b(${words.join('|')})\\b`, 'gi');
}
