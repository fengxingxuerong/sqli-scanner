// XML → JSON 转换：将 SQL 查询中的 XML 函数转换为 JSON 函数（对标 sqlmap xml2json.py）
// 适用于 WAF 对 XML 函数有检测规则的场景
export const xml2json = {
  name: 'xml2json',
  description: '将 XML 函数替换为 JSON 函数，绕过 WAF 对 XML 关键词的检测',
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
export default xml2json;
