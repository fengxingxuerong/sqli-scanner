// ============================================================================
// safeUrlKeeper.js —— 保活客户端包装（对标 sqlmap --safe-url / --safe-freq）
// 语义：每 safeFreq 个扫描请求触发一次对 safeUrl 的 GET（维持目标会话/防应用空闲锁死）。
//   · SSRF 校验不在此处：包装后的请求仍走 HttpClient.request，逐请求 assertSafeHttpTarget。
//   · 继承触发请求的 proxy/auth/wafEvasion，使保活请求与扫描请求走同一通道/会话。
//   · 保活失败静默吞掉（try/catch），绝不影响扫描主流程。
// ============================================================================

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
          await client.request({ method: 'GET', url: safeUrl, proxy, auth, wafEvasion });
        } catch {
          /* 保活失败不影响扫描 */
        }
      }
      return client.request(opts);
    },
  };
}

export default { withSafeUrl };
