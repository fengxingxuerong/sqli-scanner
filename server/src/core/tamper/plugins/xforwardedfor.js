// 伪造 X-Forwarded-For 系列请求头（对标 sqlmap xforwardedfor.py）
// 向请求追加 X-Forwarded-For / X-Client-Ip / X-Real-Ip / CF-Connecting-IP / True-Client-IP
// 及 Via、CF-IPCountry 头，绕过基于来源 IP 限流/拦截的 WAF（payload 本身不变）。
// 引擎构建请求时读取 target.headerParams（buildInjectionRequest 会展开为请求头），
// 故本插件通过 ctx 注入头信息；无 ctx 时退化为恒等变换（不改变 payload）。
function randomIP() {
  const octets = [];
  while (octets.length === 0 || octets[0] === 10 || octets[0] === 172 || octets[0] === 192) {
    for (let i = 0; i < 4; i++) octets[i] = Math.floor(Math.random() * 254) + 1;
  }
  return octets.join('.');
}

/** @param {object} ctx */
function ensureHeaders(ctx) {
  if (ctx && ctx.headers && typeof ctx.headers === 'object') return ctx.headers;
  if (ctx && ctx.target && typeof ctx.target === 'object') {
    ctx.target.headerParams = ctx.target.headerParams || {};
    return ctx.target.headerParams;
  }
  return null;
}

export const xforwardedfor = {
  name: 'xforwardedfor',
  description: '追加伪造 X-Forwarded-For 等请求头（随机 IP），绕过基于来源 IP 的 WAF 限流/拦截',
  /**
   * @param {string} payload
   * @param {object} ctx 检测上下文 { httpClient, target, point, dbms, config }
   * @returns {string}
   */
  transform(payload, ctx) {
    const headers = ensureHeaders(ctx);
    if (headers) {
      headers['X-Forwarded-For'] = randomIP();
      headers['X-Client-Ip'] = randomIP();
      headers['X-Real-Ip'] = randomIP();
      headers['CF-Connecting-IP'] = randomIP();
      headers['True-Client-IP'] = randomIP();
      headers['Via'] = '1.1 Chrome-Compression-Proxy';
      headers['CF-IPCountry'] = ['GB', 'US', 'FR', 'AU', 'CA', 'NZ', 'BE', 'DK', 'FI', 'IE', 'AT', 'IT', 'LU', 'NL', 'NO', 'PT', 'SE', 'ES', 'CH'][Math.floor(Math.random() * 19)];
    }
    return payload;
  },
};

export default xforwardedfor;
