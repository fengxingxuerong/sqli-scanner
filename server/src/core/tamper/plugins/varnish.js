// 追加 X-originating-IP 头绕过 Varnish 防火墙（对标 sqlmap varnish.py）
// Varnish 默认信任 X-originating-IP 为真实客户端地址，伪造为 127.0.0.1 可绕过
// 基于 IP 的访问控制（payload 本身不变）。
function ensureHeaders(ctx) {
  if (ctx && ctx.headers && typeof ctx.headers === 'object') return ctx.headers;
  if (ctx && ctx.target && typeof ctx.target === 'object') {
    ctx.target.headerParams = ctx.target.headerParams || {};
    return ctx.target.headerParams;
  }
  return null;
}

export const varnish = {
  name: 'varnish',
  description: '追加 X-originating-IP: 127.0.0.1 头，绕过 Varnish 防火墙',
  /**
   * @param {string} payload
   * @param {object} ctx 检测上下文
   * @returns {string}
   */
  transform(payload, ctx) {
    const headers = ensureHeaders(ctx);
    if (headers) headers['X-originating-IP'] = '127.0.0.1';
    return payload;
  },
};

export default varnish;
