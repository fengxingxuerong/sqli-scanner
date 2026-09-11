// 字符 URL 编码（类名 charencode，对齐 sqlmap 官方语义）
// 对 payload 全部字符做 URL 编码（已编码的 %XX 序列原样保留），大写十六进制。
// 例：SELECT -> %53%45%4C%45%43%54
// [P0-FIX 2026-09-05] 原实现用 encodeURIComponent，保留集含 !'()*-._~，
// 单引号/括号/星号漏编码 —— 恰是 WAF 最常拦的字符，绕过能力归零。
// 官方参考：sqlmap/tamper/charencode.py（'%%%02X' % ord(c)，%XX 透传）。
// [P0-D3 FIX 2026-09-11] 标记豁免：编码类插件会把所有字符编码（包括 applyTampers
// 用来保护提取标记的数字占位符），导致占位符还原失败 → 回退无保护 → 标记被编码
// → UNION 提取静默失败。修复：transform 前抠出「提取标记 + 占位符」哨兵暂存，
// 逐字符编码时哨兵字符（\u0001/\u0002）直接透传，编码完 restore 回去。
// 这样插件单独使用或经 applyTampers 链式调用，提取链路都不会静默失败。
import { stashAll, restore, mapSegments } from '../marker.js';

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
    // [P0-D3 FIX] 抠出提取标记与占位符（哨兵暂存）
    const [staged, slots] = stashAll(payload);
    // [P0-D3 FIX v2] 按哨兵块分段：非哨兵段逐字符编码，哨兵段原样（包括其中数字）
    const out = mapSegments(staged, (seg) => {
      let buf = '';
      for (let i = 0; i < seg.length; i++) {
        const ch = seg[i];
        if (ch === '%' && /^[0-9A-Fa-f]{2}$/.test(seg.slice(i + 1, i + 3))) {
          buf += seg.slice(i, i + 3); // 已编码序列，透传
          i += 2;
        } else {
          buf += '%' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
        }
      }
      return buf;
    });
    // [P0-D3 FIX] 哨兵还原
    return restore(out, slots);
  },
};

export default charencode;
