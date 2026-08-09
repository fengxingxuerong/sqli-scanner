import { Buffer } from 'node:buffer';

// 整串 BASE64 编码（类名 base64encode）
// 对整条 payload 做 BASE64 编码。注意：需目标侧有配套解码触发逻辑
// （如自定义 WAF/代理解码后投递），本插件仅提供编码能力，属"留接口"型。
export const base64encode = {
  name: 'base64encode',
  description: '整条 payload 做 BASE64 编码（需目标侧配套解码触发）',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    return Buffer.from(payload, 'utf8').toString('base64');
  },
};

export default base64encode;
