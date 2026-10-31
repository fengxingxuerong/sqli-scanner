// ============================================================================
// tests/support/listenSafe.js —— 绑定测试监听端口时避开 undici 的 blocked-port 列表
//                                                                  [D224 2026-10-31]
//
// ── 为什么需要（这是一个真实的偶发红，不是假想）────────────────────────────
// 报错原文（gate:close 的 wiring 步骤，2026-10-31 本机实测遇到一次）：
//   [cause]: Error: bad port
//     at makeNetworkError (node:internal/deps/undici/undici:11898:35)
//     at post (tests/exploitRoutes.guards.test.js:67:21)
//
// 机制：Node 的 fetch 走内置 undici，后者**拒绝连接**一批「不安全端口」（SSRF 防护，
// 与浏览器 fetch 同源的 bad-port 清单）。而测试里普遍用 `listen(0)` 让内核挑随机端口
// —— **挑到哪个端口不受我们控制**。
//
// ── 平台相关性（决定了为什么 CI 从没红、只有本机红）────────────────────────
// blocked-port 全部 ≤ 10080（本机实测 78 项，最大 10080）。而内核临时端口区间：
//   · Linux  32768–60999   ⇒ 永远不可能命中
//   · macOS  49152–65535   ⇒ 永远不可能命中
//   · **Windows 1024–65535** ⇒ 可能命中（本机 `netsh int ipv4 show dynamicport tcp` 实测 1024 起）
// 所以这是**Windows-only 的偶发红**：ubuntu 的 CI 跑一万轮也遇不到，而作者本机随机遇到，
// 更难诊断（「CI 绿、本机红、重跑又绿」）。本机实测命中率 ~0.025%/次 bind
// （随机绑定 2 万次命中 5 次：2049/3659/4045/5060/5061）。
//
// ── 做法 ────────────────────────────────────────────────────────────────────
// 绑定后检查端口是否在清单里，命中就关掉重绑（最多 MAX_ATTEMPTS 次）。
// **语义不变**：仍然是「内核选端口」，只是选到雷区就重来。
//
// ⚠ 为什么不在 CI 上「跳过」了事：Windows 也是 test-matrix 的一条腿（D222 刚修过
//   CRLF 那类平台专属红）；把判据按平台关掉等于把偶发红改成永远不测。
// ============================================================================

import http from 'node:http';

/**
 * undici（= Node 内置 fetch）会拒绝连接的端口。
 * 取值来源：对本机 Node 运行时**逐端口行为实测**（开 server → fetch → 判 `bad port`），
 * 不是抄文档 —— 该清单随 Node/undici 版本变化，实测才有意义。
 * 135 无法实测（本机绑定被 broker 占用），保守起见**列入**（宁可多跳一次，不可漏跳）。
 * @type {ReadonlySet<number>}
 */
export const UNDICI_BLOCKED_PORTS = Object.freeze(new Set([
  1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79, 87, 95,
  101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137, 139, 143, 161,
  179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532, 540, 548, 554, 556, 563,
  587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723, 2049, 3659, 4045, 5060, 5061,
  6000, 6566, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 10080,
]));

const MAX_ATTEMPTS = 40;

/**
 * 该端口是否会被内置 fetch 拒绝。
 * @param {number} port 端口号
 * @returns {boolean} true = undici 会以 `bad port` 拒绝
 */
export function isBlockedPort(port) {
  return UNDICI_BLOCKED_PORTS.has(Number(port));
}

/** 取 server 当前端口（未监听时返回 -1，避免调用方各自判空） */
function portOf(server) {
  const addr = server.address();
  return addr && typeof addr === 'object' ? addr.port : -1;
}

/**
 * 让一个**已经创建但尚未监听**的 http server 绑到一个安全端口上。
 * 命中雷区就关闭重建，保证返回时 `server.address().port` 不在清单里。
 *
 * @param {import('node:http').Server} server 已创建、未 listen 的 server
 * @param {(err: Error) => any} [makeServer] 命中雷区后如何重建一个等价的 server
 *        （http.createServer 的 handler 由调用方持有；不传则抛错，避免静默失败）
 * @returns {Promise<import('node:http').Server>} 绑定成功的 server（可能与入参不同）
 */
export async function bindSafe(server, makeServer) {
  let cur = server;
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    await new Promise((resolve, reject) => {
      cur.once('error', reject);
      cur.listen(0, '127.0.0.1', resolve);
    });
    if (!isBlockedPort(portOf(cur))) return cur;
    await new Promise((r) => cur.close(() => r()));
    if (!makeServer) {
      throw new Error(
        `bindSafe: 端口 ${portOf(cur)} 在 undici blocked-port 清单里，且未提供重建工厂 —— ` +
        '请改用 listenSafe(handler)，或传入 makeServer 回调'
      );
    }
    cur = makeServer();
  }
  throw new Error(`bindSafe: 连续 ${MAX_ATTEMPTS} 次绑到 blocked-port —— 清单可能被改成覆盖了整段临时端口区间`);
}

/**
 * 创建一个监听在安全端口上的 http server（最常用形态）。
 *
 * @param {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => void} [handler]
 *        请求处理函数（缺省回 200 文本，便于「只验连通性」的用例）
 * @returns {Promise<import('node:http').Server>} 已监听的 server（用 `server.address().port` 取端口）
 */
export async function listenSafe(handler) {
  const onRequest = handler ?? ((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('ok');
  });
  return bindSafe(http.createServer(onRequest), () => http.createServer(onRequest));
}

/**
 * 让一个 express 式 app 监听在安全端口上。
 * **返回原始 server 对象**，因此调用方下游的 `server.address().port` / `server.close()`
 * 一行都不用改 —— 这是本 helper 能低风险替换 20 个测试文件的原因。
 *
 * @param {{listen: Function}} app express 实例（或任何兼容 `listen(port, host, cb)` 的对象）
 * @returns {Promise<any>} 已监听的 server
 */
export async function listenAppSafe(app) {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const server = await new Promise((resolve, reject) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
      s.once('error', reject);
    });
    if (!isBlockedPort(portOf(server))) return server;
    await new Promise((r) => server.close(() => r()));
  }
  throw new Error(`listenAppSafe: 连续 ${MAX_ATTEMPTS} 次绑到 blocked-port —— 清单可能被改成覆盖了整段临时端口区间`);
}

/**
 * 让一个**已持有 handler、尚未监听**的 server 绑到安全端口上：命中雷区就 close 后重绑。
 *
 * 关键依据：Node 允许对同一个 Server 在 `close()` 之后**再次 `listen()`**
 * （handler 与事件监听器都保留在对象上），所以这里不需要重建 server，
 * 也就不需要调用方把 createServer 的回调再传一遍 —— 这是它能低成本替换
 * `await new Promise((r) => server.listen(0, '127.0.0.1', r))` 的原因。
 *
 * @param {import('node:http').Server} server 已创建、未 listen 的 server
 * @returns {Promise<import('node:http').Server>} 绑定成功的同一个 server（便于链式/赋值）
 */
export async function bindServerSafe(server) {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    if (!isBlockedPort(portOf(server))) return server;
    await new Promise((r) => server.close(() => r()));
  }
  throw new Error(`bindServerSafe: 连续 ${MAX_ATTEMPTS} 次绑到 blocked-port —— 清单可能被改成覆盖了整段临时端口区间`);
}

export default { UNDICI_BLOCKED_PORTS, isBlockedPort, bindSafe, bindServerSafe, listenSafe, listenAppSafe };
