// 双重 URL 编码（类名 chardoubleencode，对齐 sqlmap 官方语义）
// 每个字符双重编码（已编码 %XX 视作单次，补一层 %25）。大写十六进制。
// 例：SELECT -> %2553%2545%254C%2545%2543%2554；空格 -> %2520；已有 %20 -> %2520
// [P0-FIX 2026-09-05] 原实现 encodeURIComponent(encodeURIComponent(c)) 漏编
// !'()*-._~，与 charencode 同病。官方参考：sqlmap/tamper/chardoubleencode.py。
export const chardoubleencode = {
  name: 'chardoubleencode',
  description: '对 payload 全部字符做双重 URL 编码（已有 %XX 补一层 %25），绕过只解码一次的 WAF',
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
  transform(payload) {
    if (typeof payload !== 'string' || payload.length === 0) return payload;
    let out = '';
    for (let i = 0; i < payload.length; i++) {
      if (payload[i] === '%' && /^[0-9A-Fa-f]{2}$/.test(payload.slice(i + 1, i + 3))) {
        out += '%25' + payload.slice(i + 1, i + 3); // %XX -> %25XX
        i += 2;
      } else {
        out += '%25' + payload.charCodeAt(i).toString(16).toUpperCase().padStart(2, '0');
      }
    }
    return out;
  },
};

export default chardoubleencode;
