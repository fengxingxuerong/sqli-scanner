// 字符 → 十六进制 HTML 实体 &#xHH;（对标 sqlmap hexentities.py）
// 对 payload 全部字符做 &#x<hex>; 编码，绕过对明文 SQL 关键字的 WAF 匹配。
export const hexentities = {
  name: 'hexentities',
  description: '将全部字符编码为十六进制 HTML 实体 &#xHH;，绕过关键字字面匹配',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    let out = '';
    for (const ch of payload) out += `&#x${ch.charCodeAt(0).toString(16)};`;
    return out;
  },
};

export default hexentities;
