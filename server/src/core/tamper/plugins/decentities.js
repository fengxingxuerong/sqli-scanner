// 字符 → 十进制 HTML 实体 &#DD;（对标 sqlmap decentities.py）
// 对 payload 全部字符做 &#<dec>; 编码，绕过对明文 SQL 关键字的 WAF 匹配。
export const decentities = {
  name: 'decentities',
  description: '将全部字符编码为十进制 HTML 实体 &#DD;，绕过关键字字面匹配',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    let out = '';
    for (const ch of payload) out += `&#${ch.charCodeAt(0)};`;
    return out;
  },
};

export default decentities;
