// 大小写互换：对关键字进行大小写互换（对标 sqlmap swapcase.py）
// 例如：SELECT → sElEcT, UNION → uNiOn
export const swapcase = {
  name: 'swapcase',
  description: '对关键字进行大小写互换，绕过 WAF 关键字检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '')
      .replace(/\bSELECT\b/gi, 'sElEcT')
      .replace(/\bUNION\b/gi, 'uNiOn')
      .replace(/\bWHERE\b/gi, 'wHeRe')
      .replace(/\bFROM\b/gi, 'fRoM')
      .replace(/\bAND\b/gi, 'aNd')
      .replace(/\bOR\b/gi, 'oR')
      .replace(/\bORDER\b/gi, 'oRdEr')
      .replace(/\bGROUP\b/gi, 'gRoUp')
      .replace(/\bHAVING\b/gi, 'hAvInG')
      .replace(/\bLIMIT\b/gi, 'lImIt')
      .replace(/\bINSERT\b/gi, 'iNsErT')
      // [2026-10-05 补齐] 原先漏 UPDATE / DELETE 两个关键字。
      // 影响是真实的：本仓 payload 确有 UPDATE SET 子句注入与 DELETE FROM 子句注入
      // （mysql.js UPDATE SET / DELETE WHERE，postgres.js DELETE USING，
      // sqlserver.js UPDATE 逗号拼接），exploit/fileRead.js 还用
      // `; DELETE FROM SQLI_DUMP-- -` 做临时表清理 —— tamper 链一旦选中 swapcase，
      // 这些向量里的关键字原样发出，直接撞上 WAF 的关键字检测。
      // 兄弟插件 mixedcase 早已覆盖这两个（两文件曾共享 21 个 5-gram，据此定位）。
      // 改写同样遵循"逐位大小写互换"（与上方 11 条规则一致）。
      .replace(/\bUPDATE\b/gi, 'uPdAtE')
      .replace(/\bDELETE\b/gi, 'dElEtE');
  },
};
export default swapcase;
