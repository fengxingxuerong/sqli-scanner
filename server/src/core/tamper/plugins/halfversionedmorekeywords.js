// MySQL 半版本化注释：/*!50540 KEYWORD*/ 包裹关键字与函数名（仅 MySQL 5.5.40+ 执行注释内语法）
// [T-6 2026-10-14] 关键字表收敛到 versionedKeywords.js 单一真源，并补齐上游同族覆盖的函数名。
// 注：本件用版本号 50540（5.5.40+），上游用 /*!0（全部版本）——**有意保留的形态差异**：
// 半版本号本身是本件的语义（对 5.5.40 以下目标无效），改它属行为变化，须有靶场证据。
import { versionedWordsRe } from '../versionedKeywords.js';

const RE = versionedWordsRe();

export const halfversionedmorekeywords = {
  name: 'halfversionedmorekeywords',
  description: '用 /*!50540 KEYWORD*/ 包裹关键字与函数名（MySQL 5.5.40+ 执行），绕过 WAF 注释剥离',
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  doctests: [
    { input: 'UNION ALL SELECT', output: '/*!50540 UNION*/ /*!50540 ALL*/ /*!50540 SELECT*/' },
    { input: 'CONCAT(1)', output: '/*!50540 CONCAT*/(1)' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(RE, '/*!50540 $1*/');
  },
};

export default halfversionedmorekeywords;
