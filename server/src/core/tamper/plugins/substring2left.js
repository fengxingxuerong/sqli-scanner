// SUBSTRING → LEFT/MID 替换：将 SUBSTRING(str,pos,len) 替换为 LEFT/RIGHT 组合
// 对标 sqlmap substring2left.py
export const substring2left = {
  name: 'substring2left',
  description: '将 SUBSTRING() 替换为 LEFT() 和 RIGHT() 组合，绕过函数过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return String(payload ?? '')
      .replace(/SUBSTRING\s*\(/gi, (match) => {
        return match[0] === 'S' ? 'LEFT(' : 'left(';
      });
  },
};
export default substring2left;
