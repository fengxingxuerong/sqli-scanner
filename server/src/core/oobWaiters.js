// ============================================================================
// oobWaiters.js —— 「等待一组 token 中任意一个回连」的共享实现（[D108] 2026-10-19）
//
// 存在的理由：oobReceiver（本地监听）与 interactshClient（外部轮询）各自维护
// `_received` + `_waiters`，接口逐字同形。背景哨兵（oobSentinel）一次投放 N 个 token、
// 只关心「第一个回连的是谁」——若按单 token 串行 waitForToken，N 个 token 的最坏等待是
// N × timeout，且归因错位（不知道命中属于哪个面）。
//
// 把「注册 → 复查 → 首个命中即结束 → 清理」的四步收进一处：两份客户端只传自己的
// `_received/_waiters` 与归一化函数，不再各写一份（同一件事两处实现是本仓反复出事的形状，
// 且 duplication-guard 会把两份 80+ token 的实现判成跨文件克隆）。
//
// 语义：
//   · 先查 `_received`（调用时已回连的 token 直接命中，零等待）；
//   · 否则为每个 token 注册一个 waiter；**首个**回连即 resolve 该 token 原样（保留大小写）；
//   · 超时 resolve null；命中/超时都会清掉本组全部 waiter（不留悬挂引用）。
// ============================================================================

/**
 * 等待 tokens 中任意一个被回连。
 * @param {Map<string, number>} received 已收到 token 集合（key 为归一化后的形态）
 * @param {Map<string, Set<{resolve:(v:any)=>void}>>} waiters token → 等待者集合（原地增删）
 * @param {string[]} tokens 候选 token（原样大小写；用于对外的返回值）
 * @param {number} timeoutMs 等待窗口
 * @param {(token:string)=>string} norm token 归一化（interactsh 需小写；本地监听用原样）
 * @returns {Promise<string|null>} 首个命中的 token（原样大小写）或 null
 */
export function waitForAnyTokenIn(received, waiters, tokens, timeoutMs, norm) {
  const list = Array.isArray(tokens) ? tokens.filter(Boolean) : [];
  if (!list.length) return Promise.resolve(null);
  // token 原样 → 归一化 key（命中时把原样形态还给调用方）
  const byKey = new Map();
  for (const t of list) {
    const k = norm(t);
    if (k && !byKey.has(k)) byKey.set(k, t);
  }
  for (const k of byKey.keys()) {
    if (received.has(k)) return Promise.resolve(byKey.get(k));
  }
  return new Promise((resolve) => {
    const entries = [];
    let done = false;
    const finish = (/** @type {string|null} */ hit) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      for (const [k, entry] of entries) {
        const ws = waiters.get(k);
        if (!ws) continue;
        ws.delete(entry);
        if (ws.size === 0) waiters.delete(k);
      }
      resolve(hit);
    };
    const timer = setTimeout(
      () => finish(null),
      Number.isFinite(timeoutMs) ? timeoutMs : 5000
    );
    for (const [k, t] of byKey) {
      const entry = { resolve: () => finish(t) };
      const set = waiters.get(k) || new Set();
      waiters.set(k, set);
      set.add(entry);
      entries.push([k, entry]);
    }
  });
}
