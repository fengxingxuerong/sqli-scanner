// XPath → JSON 转换：将 XPATH 函数替换为 JSON 函数（对标 sqlmap xpath2json.py）
// 适用于 WAF 对 XPATH 关键词有检测规则的场景
export const xpath2json = {
  name: 'xpath2json',
  description: '将 XPATH 函数替换为 JSON 函数，绕过 WAF 对 XPATH 关键词的检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    let s = String(payload ?? '');
    s = s.replace(/EXTRACTVALUE\s*\(/gi, (m) => m[0] === 'E' ? 'JSON_EXTRACT(' : 'json_extract(');
    s = s.replace(/UPDATEXML\s*\(/gi, (m) => m[0] === 'U' ? 'JSON_SET(' : 'json_set(');
    return s;
  },
};
export default xpath2json;
