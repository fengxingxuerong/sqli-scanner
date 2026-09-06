import { Buffer } from 'node:buffer';

// 整串 BASE64 编码（类名 base64encode）
// 对整条 payload 做 BASE64 编码。注意：需目标侧有配套解码触发逻辑
// （如自定义 WAF/代理解码后投递），本插件仅提供编码能力，属"留接口"型。
export const base64encode = {
  name: 'base64encode',
  description: '整条 payload 做 BASE64 编码（需目标侧配套解码触发）',
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
    return Buffer.from(payload, 'utf8').toString('base64');
  },
};

export default base64encode;
