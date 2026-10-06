// 追加 X-originating-IP 头绕过 Varnish 防火墙（对标 sqlmap varnish.py）
// Varnish 默认信任 X-originating-IP 为真实客户端地址，伪造为 127.0.0.1 可绕过
// 基于 IP 的访问控制（payload 本身不变）。
//
// [2026-10-05] 本地那份 ensureHeaders 副本已删除，改调 headerSink.js 单一真源。
// 原副本与 xforwardedfor.js 的逐字相同，而 agent/arges 用的是另一套（无回退）——
// 三份实现、两种契约，且只有带回退的那份在引擎真实 ctx 下生效。
// 详见 tamper/headerSink.js 顶部注释与 tests/tamperHeaderInjectionSingleSource.test.js。
import { headerSink } from '../headerSink.js';

export const varnish = {
  name: 'varnish',
  description: '追加 X-originating-IP: 127.0.0.1 头，绕过 Varnish 防火墙',
  /**
   * @param {string} payload
   * @param {object} ctx 检测上下文
   * @returns {string}
   */
  transform(payload, ctx) {
    const headers = headerSink(ctx);
    if (headers) headers['X-originating-IP'] = '127.0.0.1';
    return payload;
  },
};

export default varnish;
