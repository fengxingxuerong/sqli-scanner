// 延迟 POST 请求：在 POST 请求中插入延迟参数（对标 sqlmap postpon.py）
// 适用于 WAF 对快速连续的 POST 请求有速率检测的场景
export const postpon = {
  name: 'postpon',
  description: '在 POST body 中插入延迟参数，绕过 WAF 速率检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    // 此插件不修改 payload，而是通过 ctx 告知调度器添加延迟
    if (ctx && ctx.config) {
      ctx.config._postpon = true;
    }
    return String(payload ?? '');
  },
};
export default postpon;
