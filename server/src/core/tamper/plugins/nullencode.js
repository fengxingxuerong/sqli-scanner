// NULL 字节编码：在关键字之间插入 NULL 字节（对标 sqlmap nullencode.py）
// 适用于某些对 NULL 字节处理不当的 WAF
export const nullencode = {
  name: 'nullencode',
  description: '在关键字之间插入 NULL 字节，绕过对 NULL 字节处理不当的 WAF',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '')
      .replace(/\bUNION\b/gi, (m) => m[0] === 'U' ? 'UN%00ION' : 'un%00ion')
      .replace(/\bSELECT\b/gi, (m) => m[0] === 'S' ? 'SEL%00ECT' : 'sel%00ect')
      .replace(/\bAND\b/gi, (m) => m[0] === 'A' ? 'AN%00D' : 'an%00d');
  },
};
export default nullencode;
