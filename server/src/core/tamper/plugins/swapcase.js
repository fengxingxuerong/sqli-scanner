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
      .replace(/\bINSERT\b/gi, 'iNsErT');
  },
};
export default swapcase;
