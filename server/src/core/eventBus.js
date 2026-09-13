// ============================================================================
// eventBus.js —— 扫描事件总线 / SSE 实时推送
// 功能：
//   按 scanId 隔离的事件命名空间 Map（emit / subscribe / dispose）
//   [P3-SSE] 每扫描环形回放缓冲（SSE_REPLAY_MAX，默认 500）+ 全局单调 seq，
//            SSE id 行 + Last-Event-ID/lastEventId 续传 —— 断线重连不再丢事件
//   SSE 推送：跨域策略统一交给全局 cors 中间件（不硬编码 ACAO:*）
//   per-scanId 并发上限（默认 20）+ 全局总上限（SSE_GLOBAL_MAX 默认 100）
//   终态事件主动断开 + 心跳保活 + close/finish 多重清理
// ============================================================================

import { EventEmitter } from 'events';
import { ErrorCode } from './errors.js';

// 按 scanId 隔离的事件命名空间 Map
const emitters = new Map();

// 每 scanId 的 SSE 活跃连接计数（P2-2）
const activeConnections = new Map();
const SSE_MAX_CONNECTIONS = (() => {
  const n = Number(process.env.SSE_MAX_CONNECTIONS);
  return Number.isInteger(n) && n >= 1 ? n : 20;
})();

// 全局 SSE 连接总上限（防跨 scanId 耗尽 FD/内存）
const SSE_GLOBAL_MAX = (() => {
  const n = Number(process.env.SSE_GLOBAL_MAX);
  return Number.isInteger(n) && n >= 1 ? n : 100;
})();
let globalConnectionCount = 0;

// [P3-SSE] 每 scanId 的回放环形缓冲上限：断线重连时按 Last-Event-ID 续传，
// 消除「断线窗口内事件永久丢失」的正确性缺口。100 扫描 × 500 条 × ~300B ≈ 15MB 上界。
const SSE_REPLAY_MAX = (() => {
  const n = Number(process.env.SSE_REPLAY_MAX);
  return Number.isInteger(n) && n >= 1 ? Math.min(n, 5000) : 500;
})();

// 全局单调事件序号：SSE id 行 + 回放续传游标
let seqCounter = 0;

export function create(scanId) {
  if (!emitters.has(scanId)) {
    const em = new EventEmitter();
    em.setMaxListeners(100);
    /** @type {any} */ (em)._replayBuffer = []; // [P3-SSE] 环形回放缓冲，dispose 时随命名空间一起回收
    emitters.set(scanId, em);
  }
  return emitters.get(scanId);
}

export function emit(scanId, type, payload) {
  const em = emitters.get(scanId);
  if (!em) return;
  const evt = { type, scanId, ts: new Date().toISOString(), seq: ++seqCounter, payload };
  // [P3-SSE] 写入回放缓冲（超限丢弃最旧），供重连续传
  // [P2-FIX] 批量裁剪：原实现每次 emit 都 splice(0, n) O(n) 头部移位，
  // 高频 emit 时 5000 上限有开销。改为增长到 1.5× 上限才裁剪一次（摊薄 O(n)）。
  const buf = em._replayBuffer;
  if (buf) {
    buf.push(evt);
    if (buf.length > SSE_REPLAY_MAX * 1.5) buf.splice(0, buf.length - SSE_REPLAY_MAX);
  }
  em.emit('event', evt);
}

// [P3-SSE] 解析重连游标：优先 EventSource 自动携带的 Last-Event-ID 头，
// 回退显式查询参数 lastEventId（手动重开 EventSource 无法设头）
function _lastSeqOf(req) {
  const raw =
    req?.headers?.['last-event-id'] ??
    (typeof req?.query?.lastEventId === 'string' ? req.query.lastEventId : undefined);
  if (raw === undefined || raw === null || raw === '') return null;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

// 将某次扫描的事件转为 SSE 流推送给前端
export function toSSE(scanId, req, res) {
  const em = emitters.get(scanId);

  // [P2-2] 连接数上限：超出直接 503 关闭（不写 SSE 头，避免悬挂连接）
  // 全局总上限 + per-scanId 上限双重检查（Node 单线程，检查与自增之间无 await，天然原子）
  if (globalConnectionCount >= SSE_GLOBAL_MAX) {
    res.status(503).json({ code: 503, data: null, message: '全局 SSE 连接数已达上限' });
    return;
  }
  const cur = activeConnections.get(scanId) || 0;
  if (cur >= SSE_MAX_CONNECTIONS) {
    res.status(503).json({ code: 503, data: null, message: '该扫描的实时连接数已达上限' });
    return;
  }
  globalConnectionCount++;
  activeConnections.set(scanId, cur + 1);

  // 跨域策略统一由全局 cors 中间件负责（P2-2：不再硬编码 ACAO:*）
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
  });
  res.write('retry: 3000\n\n');

  // 若扫描不存在，立即推送一条错误事件通知前端并关闭连接
  if (!em) {
    res.write(
      `data: ${JSON.stringify({
        type: 'scan_error',
        scanId,
        ts: new Date().toISOString(),
        payload: { code: ErrorCode.SCAN_NOT_FOUND, message: '扫描不存在或已结束' },
      })}\n\n`
    );
    if (typeof res.end === 'function') res.end();
    _dec(scanId);
    return;
  }

  const TERMINAL_TYPES = new Set(['scan_completed', 'scan_error', 'scan_stopped']);
  // [MERGED: engine ★FIX-2] 扫描终态后主动结束 SSE（防前端未断开时 ping 定时器悬挂/堆积）
  const terminalListener = (evt) => {
    if (evt && TERMINAL_TYPES.has(evt.type)) {
      try {
        res.write(`id: ${evt.seq}\ndata: ${JSON.stringify(evt)}\n\n`);
        res.end();
      } catch {
        /* 已关闭 */
      }
    }
  };
  const listener = (evt) => {
    // [r2-01 H1] 终态事件由 terminalListener 独写并收尾连接——此处跳过，避免同一终态事件双发
    if (evt && TERMINAL_TYPES.has(evt.type)) return;
    // [MERGED: engine ★FIX-1] res 可能已关闭/已 end（客户端断开竞态），write 失败不得冒泡成未捕获异常
    try {
      // [P3-SSE] 携带 id 行，浏览器 EventSource 重连时自动回传 Last-Event-ID
      res.write(`id: ${evt.seq}\ndata: ${JSON.stringify(evt)}\n\n`);
    } catch {
      /* 连接已关闭，忽略 */
    }
  };
  em.on('event', listener);
  em.on('event', terminalListener);

  // [P3-SSE] 断线重连回放：把游标之后缓冲的事件补发，消除丢失窗口。
  // 回放里若已含终态事件则补发后直接收尾（与终态监听器语义一致）。
  const lastSeq = _lastSeqOf(req);
  if (lastSeq !== null) {
    const TERMINAL_TYPES = new Set(['scan_completed', 'scan_error', 'scan_stopped']);
    let replayed = [];
    try {
      replayed = (em._replayBuffer || []).filter((e) => e.seq > lastSeq);
      for (const evt of replayed) {
        res.write(`id: ${evt.seq}\ndata: ${JSON.stringify(evt)}\n\n`);
      }
    } catch {
      /* 客户端已断开 */
    }
    if (replayed.some((e) => TERMINAL_TYPES.has(e.type))) {
      try {
        if (typeof res.end === 'function') res.end();
      } catch {
        /* 已关闭 */
      }
      // [P0-FIX] 回放含终态 → 直接收尾：此分支 return 时 cleanup（下方 190-193 行）尚未注册，
      // listener/terminalListener 已挂在 emitter 上且永不移除 → 后续 emit 不断 write 已 end 的
      // res（每次重连 +2 监听器，直到 dispose）。此处手动摘除。
      em.off('event', listener);
      em.off('event', terminalListener);
      _dec(scanId);
      return;
    }
  }

  // 心跳保活，避免代理断开空闲连接
  const ping = setInterval(() => {
    try {
      res.write(': ping\n\n');
    } catch {
      /* 连接已关闭，由 cleanup 收尾 */
    }
  }, 15000);

  // ★FIX [P0]：cleanup 注册在 req.close / res.close / res.finish 三个事件上，
  // 连接正常关闭时三者都会触发 → cleanup 被调用 2-3 次 → _dec 多次扣减
  // globalConnectionCount → 计数虚减 → 后续合法 SSE 连接被误 503 拒绝。
  // 幂等闸：确保同一连接的清理只执行一次。
  let cleaned = false;
  const cleanup = () => {
    if (cleaned) return;
    cleaned = true;
    clearInterval(ping);
    em.off('event', listener);
    em.off('event', terminalListener);
    _dec(scanId);
  };
  req.on('close', cleanup);
  // 兜底：连接异常/响应结束也清理（防计数泄漏）
  res.on('close', cleanup);
  res.on('finish', cleanup); // [MERGED: engine ★FIX-1] res 侧 finish 同样触发清理
}

function _dec(scanId) {
  const n = activeConnections.get(scanId) || 0;
  if (n <= 1) activeConnections.delete(scanId);
  else activeConnections.set(scanId, n - 1);
  globalConnectionCount = Math.max(0, globalConnectionCount - 1);
}

// 清理某次扫描的命名空间
export function dispose(scanId) {
  const em = emitters.get(scanId);
  if (em) {
    em.removeAllListeners();
    emitters.delete(scanId);
  }
  activeConnections.delete(scanId);
}

export default { create, emit, toSSE, dispose };
