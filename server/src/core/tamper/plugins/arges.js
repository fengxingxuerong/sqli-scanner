// 添加 X-Forwarded-For / Client-IP 头，绕过基于 IP 的 WAF 规则（对标 sqlmap arges.py）
// 通过注入伪造来源 IP 头，绕过 WAF 对特定 IP 范围的检测规则
//
// [2026-10-05 修] 原实现只写 `ctx.headers`，**无 target 回退** —— 而引擎传给
// 插件的 ctx 是检测器上下文 { httpClient, target, point, dbms, config }，
// **根本没有 ctx.headers 这个顶层键**。实测走 obfuscateWithConfig，
// target.headerParams 写前 {} 写后 {}，IP 伪造**静默失效**（不报错、不告警）。
// 引擎真正会展开的是 target.headerParams（buildInjectionRequest）。
// 改调 headerSink.js 单一真源，与 varnish / xforwardedfor / agent 行为对齐。
import { headerSink } from '../headerSink.js';

export const arges = {
  name: 'arges',
  description: '对请求添加 X-Forwarded-For 和 Client-IP 头，绕过基于 IP 的 WAF 规则',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    // 此插件不修改 payload，而是修改请求头
    const headers = headerSink(ctx);
    if (headers) {
      headers['X-Forwarded-For'] = '127.0.0.1';
      headers['Client-IP'] = '127.0.0.1';
    }
    return String(payload ?? '');
  },
};
export default arges;
