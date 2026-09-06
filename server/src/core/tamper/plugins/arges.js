// 添加 X-Forwarded-For / Client-IP 头，绕过基于 IP 的 WAF 规则（对标 sqlmap arges.py）
// 通过注入伪造来源 IP 头，绕过 WAF 对特定 IP 范围的检测规则
export const arges = {
  name: 'arges',
  description: '对请求添加 X-Forwarded-For 和 Client-IP 头，绕过基于 IP 的 WAF 规则',
  transform(payload, ctx) {
    // 此插件不修改 payload，而是修改请求头
    // 通过 ctx.headers 告知上层添加额外头
    if (ctx && ctx.headers) {
      ctx.headers['X-Forwarded-For'] = '127.0.0.1';
      ctx.headers['Client-IP'] = '127.0.0.1';
    }
    return String(payload ?? '');
  },
};
export default arges;