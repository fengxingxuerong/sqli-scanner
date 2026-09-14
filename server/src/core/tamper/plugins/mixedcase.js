// 混合大小写：对关键字采用混合大小写模式（对标 sqlmap mixedcase.py）
// 与 randomcase 不同：对每个关键字内部采用固定模式如大写首字母+小写其余
export const mixedcase = {
  name: 'mixedcase',
  description: '混合大小写模式混淆关键字，绕过 WAF 关键字检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '')
      .replace(/\bSELECT\b/gi, 'SeLeCt')
      .replace(/\bUNION\b/gi, 'UnIoN')
      .replace(/\bWHERE\b/gi, 'WhErE')
      .replace(/\bFROM\b/gi, 'FrOm')
      .replace(/\bAND\b/gi, 'AnD')
      .replace(/\bOR\b/gi, 'Or')
      .replace(/\bORDER\b/gi, 'OrDeR')
      .replace(/\bGROUP\b/gi, 'GrOuP')
      .replace(/\bHAVING\b/gi, 'HaViNg')
      .replace(/\bLIMIT\b/gi, 'LiMiT')
      .replace(/\bINSERT\b/gi, 'InSeRt')
      .replace(/\bUPDATE\b/gi, 'UpDaTe')
      .replace(/\bDELETE\b/gi, 'DeLeTe');
  },
};
export default mixedcase;
