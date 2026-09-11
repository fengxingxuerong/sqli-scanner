import { Buffer } from 'node:buffer';
import { stashAll, restore, mapSegments } from '../marker.js';

// 整串 BASE64 编码（类名 base64encode）
// 对整条 payload 做 BASE64 编码。注意：需目标侧有配套解码触发逻辑
// （如自定义 WAF/代理解码后投递），本插件仅提供编码能力，属"留接口"型。
// [P0-D3 FIX 2026-09-11] 标记豁免：base64 是整体编码（单 Buffer），无法逐字符跳过哨兵。
// 修复：分段 base64 —— 按哨兵块分段，每段独立 base64（保持每段语义），哨兵段原样。
// 语义说明：分段 base64 与整体 base64 输出形态不同（每段独立），需目标侧分段解码；
// 但它保住了提取标记可见 —— 否则 UNION 提取静默失败，比漏报更危险。
export const base64encode = {
  name: 'base64encode',
  description: '整条 payload 做 BASE64 编码（需目标侧配套解码触发）；含提取标记时自动分段编码',
  doctests: [
    { input: 'abc', output: 'YWJj' },
  ],
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  terminal: true, // [P1-FIX] 输出形态固定：其后 tamper 均空转，链上自动截断
  transform(payload, ctx) {
    if (typeof payload !== 'string' || payload.length === 0) return payload;
    // [P0-D3 FIX] 先抠出「提取标记 + 占位符」（哨兵暂存）
    const [staged, slots] = stashAll(payload);
    // 无标记 → 整体 base64（行为不变，零回归）
    if (slots.length === 0) {
      return Buffer.from(payload, 'utf8').toString('base64');
    }
    // 有标记 → 分段 base64（每段独立编码，哨兵段原样）
    const out = mapSegments(staged, (seg) => Buffer.from(seg, 'utf8').toString('base64'));
    // [P0-D3 FIX] 哨兵还原
    return restore(out, slots);
  },
};

export default base64encode;
