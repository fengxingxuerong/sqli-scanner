// 字符 → \\uXXXX Unicode 转义（对标 sqlmap charunicodeescape.py）
// 对 payload 全部字符做 Unicode 转义（已编码的 %XX 归一为 \\u00XX），
// 用于绕过 JSON 等上下文中的弱过滤 / WAF。
export const charunicodeescape = {
  name: 'charunicodeescape',
  description: '将全部字符 Unicode 转义为 \\uXXXX，绕过 JSON 上下文弱过滤',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    let out = '';
    for (let i = 0; i < payload.length; i++) {
      const ch = payload[i];
      if (ch === '%' && i + 2 < payload.length && /^[0-9a-fA-F]{2}$/.test(payload.slice(i + 1, i + 3))) {
        out += '\\u00' + payload.slice(i + 1, i + 3).toUpperCase();
        i += 2;
      } else {
        out += '\\u' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0');
      }
    }
    return out;
  },
};

export default charunicodeescape;
