// 随机 User-Agent 插件（对标 sqlmap agent.py）
// 通过 ctx 设置随机 UA 头，绕过 WAF 对默认 UA 的检测
//
// [2026-10-05 修] 原实现只写 `ctx.headers`，**无 target 回退**：
//   if (ctx && ctx.headers) { ctx.headers['User-Agent'] = ... }
// 而引擎传给插件的 ctx 是检测器上下文 { httpClient, target, point, dbms, config }，
// **根本没有 ctx.headers 这个顶层键** —— 实测走 obfuscateWithConfig，
// target.headerParams 写前 {} 写后 {}，UA 伪装**静默失效**（不报错、不告警）。
// 引擎真正会展开的是 target.headerParams（buildInjectionRequest）。
// 改调 headerSink.js 单一真源，与 varnish / xforwardedfor 行为对齐。
// （放在 tamper/ 而非 plugins/ 下：plugins/ 里的每个文件都必须注册到
//  tamperRegistry —— tamperPluginCount.guard.test.js 会把"存在但未注册"
//  判为"能写不能用 = 能力缺失"。共享模块不是插件，同 quoteScan.js 的处置。）
import { headerSink } from '../headerSink.js';

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
];

export const agent = {
  name: 'agent',
  description: '随机 User-Agent 头，绕过 WAF 对默认 UA 的检测',
  /**
   * @param {string} payload
   * @param {object} ctx
   * @returns {string}
   */
  transform(payload, ctx) {
    const headers = headerSink(ctx);
    if (headers) {
      headers['User-Agent'] = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
    }
    return String(payload ?? '');
  },
};
export default agent;
