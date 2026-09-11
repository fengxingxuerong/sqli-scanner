// 双重 URL 编码（类名 chardoubleencode，对齐 sqlmap 官方语义）
// 每个字符双重编码（已编码 %XX 视作单次，补一层 %25）。大写十六进制。
// 例：SELECT -> %2553%2545%254C%2545%2543%2554；空格 -> %2520；已有 %20 -> %2520
// [P0-FIX 2026-09-05] 原实现 encodeURIComponent(encodeURIComponent(c)) 漏编
// !'()*-._~，与 charencode 同病。官方参考：sqlmap/tamper/chardoubleencode.py。
// [P0-D3 FIX 2026-09-11] 标记豁免：与 charencode 同病 —— 会把数字占位符也编码成
// %25XX，占位符丢失 → 回退无保护 → 提取标记被编码 → UNION 提取静默失败。
// 修复：stash「提取标记 + 占位符」，哨兵字符透传，restore 回去。
import { stashAll, restore, mapSegments } from '../marker.js';

export const chardoubleencode = {
  name: 'chardoubleencode',
  description: '对 payload 全部字符做双重 URL 编码（已有 %XX 补一层 %25），绕过只解码一次的 WAF',
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
  transform(payload) {
    if (typeof payload !== 'string' || payload.length === 0) return payload;
    // [P0-D3 FIX] 抠出提取标记与占位符
    const [staged, slots] = stashAll(payload);
    // [P0-D3 FIX v2] 按哨兵块分段：非哨兵段逐字符双重编码，哨兵段原样
    const out = mapSegments(staged, (seg) => {
      let buf = '';
      for (let i = 0; i < seg.length; i++) {
        const ch = seg[i];
        if (ch === '%' && /^[0-9A-Fa-f]{2}$/.test(seg.slice(i + 1, i + 3))) {
          buf += '%25' + seg.slice(i + 1, i + 3); // %XX -> %25XX
          i += 2;
        } else {
          buf += '%25' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
        }
      }
      return buf;
    });
    // [P0-D3 FIX] 哨兵还原
    return restore(out, slots);
  },
};

export default chardoubleencode;
