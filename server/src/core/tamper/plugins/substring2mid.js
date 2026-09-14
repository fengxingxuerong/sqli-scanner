// SUBSTRING → MID 替换：将 SUBSTRING(str,pos,len) 替换为 MID()（对标 sqlmap substring2mid.py）
export const substring2mid = {
  name: 'substring2mid',
  description: '将 SUBSTRING() 替换为 MID()，绕过函数过滤规则',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '')
      .replace(/SUBSTRING\s*\(/gi, (match) => {
        return match[0] === 'S' ? 'MID(' : 'mid(';
      });
  },
};
export default substring2mid;
