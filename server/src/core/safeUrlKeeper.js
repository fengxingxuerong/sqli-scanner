// ============================================================================
// safeUrlKeeper.js —— 保活客户端包装（对标 sqlmap --safe-url / --safe-freq）
// 语义：每 safeFreq 个扫描请求触发一次对 safeUrl 的 GET（维持目标会话/防应用空闲锁死）。
//   · SSRF 校验不在此处：包装后的请求仍走 HttpClient.request，逐请求 assertSafeHttpTarget。
//   · 继承触发请求的 proxy/auth/wafEvasion，使保活请求与扫描请求走同一通道/会话。
//   · 保活失败静默吞掉（try/catch），绝不影响扫描主流程。
//   · [D279] HEAD（--null-connection）与 GET 走同一套保活计数与包装（headRequest 不再被丢）。
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

  // [D279] 保活触发逻辑抽单缝：request 与 headRequest 共用**同一个计数器** ——
  // HEAD（--null-connection）也是扫描请求，以前 HEAD 路径整个不存在（本包装返回
  // { request } 把 headRequest 丢了 ⇒ sendHead 静默回退 GET），null-connection 模式下
  // 保活按构造从不触发；恢复 HEAD 通道后计数语义保持「每 safeFreq 个扫描请求」。
  async function maybeKeepAlive(opts) {
    count += 1;
    if (count % freq !== 0) return;
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

  return {
    ...client,
    request: async (opts = {}) => {
      await maybeKeepAlive(opts);
      return client.request(opts);
    },
    // [D279] 三包装丢 headRequest 的缺陷（D36 撞见、挂账 30 天，收口记录见 CHANGELOG D279 /
    // 仓内待办清单 §10）：本层此前返回 { request } 把 headRequest 整个丢掉 —— 配了 --safe-url
    // 后 --null-connection 的 HEAD 通道在 sendHead 里静默退化成 GET，没有任何东西变红。
    // HEAD 与 request 走同一套保活计数（maybeKeepAlive）；只把方法名透传过去而不加工
    // 等于 HEAD 绕过本层语义 —— 那比「HEAD 不存在」更糟（待办清单 §10 的原话）。
    ...(typeof client.headRequest === 'function'
      ? {
          headRequest: async (url, opts = {}) => {
            await maybeKeepAlive({ ...opts, url });
            return client.headRequest(url, opts);
          },
        }
      : {}),
  };
}

export default { withSafeUrl };
