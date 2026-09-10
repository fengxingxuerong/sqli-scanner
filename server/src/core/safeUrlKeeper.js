// ============================================================================
// safeUrlKeeper.js —— 保活客户端包装（对标 sqlmap --safe-url / --safe-freq）
// 语义：每 safeFreq 个扫描请求触发一次对 safeUrl 的 GET（维持目标会话/防应用空闲锁死）。
//   · SSRF 校验不在此处：包装后的请求仍走 HttpClient.request，逐请求 assertSafeHttpTarget。
//   · 继承触发请求的 proxy/auth/wafEvasion，使保活请求与扫描请求走同一通道/会话。
//   · 保活失败静默吞掉（try/catch），绝不影响扫描主流程。
//
// [P0-FIX 2026-09-09] 凭据只在同源时继承：safeUrl 实战里通常是**另一个主机**（网关健康检查、
// LB 心跳页、另一个内网服务）——原实现无条件把目标站的 Cookie/Authorization 发给它，
// 等于把客户系统的凭据抄送给我们并不控制的第三个系统，而且完全静默。
// 跨源时只保留 proxy（出口路径必须一致）与 wafEvasion（无关凭据），剥掉 auth。
// ============================================================================

import { logger } from './logger.js';

/** 判断两个 URL 是否同源（scheme+host+port）；任一非法则按「不同源」处理（fail-closed） */
function sameOrigin(a, b) {
  try {
    return new URL(a).origin === new URL(b).origin;
  } catch {
    return false;
  }
}

const clampFreq = (v) => {
  const n = Math.floor(Number(v));
  return Number.isFinite(n) && n >= 1 ? Math.min(n, 10000) : 1;
};

export function withSafeUrl(client, { safeUrl, safeFreq }) {
  const freq = clampFreq(safeFreq);
  let count = 0;
  return {
    request: async (opts = {}) => {
      count += 1;
      if (count % freq === 0) {
        try {
          const { proxy, auth, wafEvasion } = opts || {};
          const inheritAuth = sameOrigin(safeUrl, opts.url || '');
          if (!inheritAuth && auth) {
            logger.warn(
              `保活 URL 与目标不同源，已剥离 auth（Cookie/Authorization 不随保活请求外发）：` +
                `target=${new URL(opts.url).host} safeUrl=${new URL(safeUrl).host}`
            );
          }
          await client.request({
            method: 'GET',
            url: safeUrl,
            proxy,
            ...(inheritAuth ? { auth } : {}),
            wafEvasion,
          });
        } catch {
          /* 保活失败不影响扫描 */
        }
      }
      return client.request(opts);
    },
  };
}

export default { withSafeUrl };
