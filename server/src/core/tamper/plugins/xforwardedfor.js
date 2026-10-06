// 伪造 X-Forwarded-For 系列请求头（对标 sqlmap xforwardedfor.py）
// 向请求追加 X-Forwarded-For / X-Client-Ip / X-Real-Ip / CF-Connecting-IP / True-Client-IP
// 及 Via、CF-IPCountry 头，绕过基于来源 IP 限流/拦截的 WAF（payload 本身不变）。
// 引擎构建请求时读取 target.headerParams（buildInjectionRequest 会展开为请求头），
// 故本插件通过 ctx 注入头信息；无 ctx 时退化为恒等变换（不改变 payload）。
//
// [2026-10-05] 原本地持有一份 ensureHeaders 副本（与 varnish.js 逐字相同），
// 已删除改调 headerSink.js 单一真源 —— 此前三份实现两种契约，
// 只有带回退的那份在引擎真实 ctx 下生效。详见 tamper/headerSink.js 顶部注释。
import { headerSink } from '../headerSink.js';

/**
 * 该 IP 是否为不可路由/保留段（RFC 6890 意义上不能作为公网来源）。
 * 判据与 core/http/ipBytes.js 的 IPV4_BLOCKS 对齐 —— 同一张段表、同一套语义，
 * 只是这里判的是"能不能当公网源"而不是"该不该放行"。
 */
function isReservedIpv4(ip) {
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return true;
  const [a, b] = o;
  if (a === 0) return true;                                  // 0/8 本网络
  if (a === 10) return true;                                 // 10/8 私网
  if (a === 127) return true;                                // 127/8 回环
  if (a === 169 && b === 254) return true;                   // 169.254/16 链路本地（含云元数据）
  if (a === 172 && b >= 16 && b <= 31) return true;           // 172.16/12 私网
  if (a === 192 && b === 168) return true;                    // 192.168/16 私网
  if (a === 100 && b >= 64 && b <= 127) return true;          // 100.64/10 CGNAT
  if (a >= 224) return true;                                 // ≥224 组播/保留
  return false;
}

function randomOctets() {
  // 1..254：避开 0 与 255（后者常被 WAF 直接当广播/非法源）
  return [0, 1, 2, 3].map(() => Math.floor(Math.random() * 254) + 1);
}

/**
 * 生成一个公网可路由的来源 IP。
 *
 * [2026-10-05 修] 原实现是：
 *   while (octets.length === 0 || octets[0] === 10 || octets[0] === 172 || octets[0] === 192)
 *
 * 只按**首字节**挡私网整段，漏掉 127/8 回环、169.254/16 链路本地（含云元数据
 * 169.254.169.254）、0/8、以及 ≥224 组播/保留。实测 10 万次 × 2 个头：
 *   组播/保留 24637 次、回环 813 次、链路本地 3 次 ⇒ **约 25% 的伪造头不可路由**。
 *
 * 方向是**降低检出能力**：伪造头的用途就是绕过"基于来源 IP"的 WAF，而大量
 * WAF / 云入口看到组播、回环、链路本地来源会直接按非法源**整体拦截**
 * —— 插件不但没帮上忙，反而把请求推进了更严格的分支。
 *
 * 修法要点：必须**有界重试**。写成 `while (不合法) 重新随机` 会在 Math.random
 * 被定住（测试替身、极端实现）时永不返回 —— 守卫 契约-5 就是钉这一条。
 * 32 次仍不合法（概率上不可能发生）就接受最后一次，避免任何死循环。
 */
function randomIP() {
  let octets = randomOctets();
  for (let attempt = 0; attempt < 32 && isReservedIpv4(octets.join('.')); attempt++) {
    octets = randomOctets();
  }
  return octets.join('.');
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
    const headers = headerSink(ctx);
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
