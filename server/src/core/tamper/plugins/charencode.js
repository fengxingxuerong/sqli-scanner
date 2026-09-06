// 字符 URL 编码（类名 charencode，对齐 sqlmap 官方语义）
// 对 payload 全部字符做 URL 编码（已编码的 %XX 序列原样保留），大写十六进制。
// 例：SELECT -> %53%45%4C%45%43%54
// [P0-FIX 2026-09-05] 原实现用 encodeURIComponent，保留集含 !'()*-._~，
// 单引号/括号/星号漏编码 —— 恰是 WAF 最常拦的字符，绕过能力归零。
// 官方参考：sqlmap/tamper/charencode.py（'%%%02X' % ord(c)，%XX 透传）。
export const charencode = {
  name: 'charencode',
  description: '对 payload 全部字符做 URL 编码（已编码 %XX 保留），大写十六进制，绕过不预解码的弱 WAF',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
  transform(payload, ctx) {
    if (typeof payload !== 'string' || payload.length === 0) return payload;
    let out = '';
    for (let i = 0; i < payload.length; i++) {
      if (payload[i] === '%' && /^[0-9A-Fa-f]{2}$/.test(payload.slice(i + 1, i + 3))) {
        out += payload.slice(i, i + 3); // 已编码序列，透传
        i += 2;
      } else {
        out += '%' + payload.charCodeAt(i).toString(16).toUpperCase().padStart(2, '0');
      }
    }
    return out;
  },
};

export default charencode;
