// MID(a, b, c) 转 MID(a FROM b FOR c)，去除逗号（绕过逗号过滤）
export const commalessmid = {
  name: 'commalessmid',
  description: '将 MID(a, b, c) 改写为 MID(a FROM b FOR c)，去除逗号',
  /**
   * @param {string} payload
   * @returns {string}
   */
  transform(payload) {
    return payload.replace(/MID\(([^,]+),\s*(\d+),\s*(\d+)\)/gi, 'MID($1 FROM $2 FOR $3)');
  },
};
export default commalessmid;
