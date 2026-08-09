import { EventEmitter } from 'events';

// 按 scanId 隔离的事件命名空间 Map
const emitters = new Map();

// 创建（或获取）某次扫描的事件发射器
export function create(scanId) {
  if (!emitters.has(scanId)) {
    const em = new EventEmitter();
    em.setMaxListeners(100);
    emitters.set(scanId, em);
  }
  return emitters.get(scanId);
}

// 发射事件（内部统一包装为 {type, scanId, ts, payload}）
export function emit(scanId, type, payload) {
  const em = emitters.get(scanId);
  if (!em) return;
  em.emit('event', { type, scanId, ts: new Date().toISOString(), payload });
}

// 将某次扫描的事件转为 SSE 流推送给前端
export function toSSE(scanId, req, res) {
  const em = emitters.get(scanId);
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });
  res.write('retry: 3000\n\n');

  // 若扫描不存在，立即推送一条错误事件通知前端
  if (!em) {
    res.write(
      `data: ${JSON.stringify({
        type: 'scan_error',
        scanId,
        ts: new Date().toISOString(),
        payload: { message: '扫描不存在或已结束' },
      })}\n\n`
    );
    return;
  }

  const listener = (evt) => {
    res.write(`data: ${JSON.stringify(evt)}\n\n`);
  };
  if (em) em.on('event', listener);

  // 心跳保活，避免代理断开空闲连接
  const ping = setInterval(() => res.write(': ping\n\n'), 15000);

  const cleanup = () => {
    clearInterval(ping);
    if (em) em.off('event', listener);
  };
  req.on('close', cleanup);
}

// 清理某次扫描的命名空间（可选，避免内存泄漏）
export function dispose(scanId) {
  const em = emitters.get(scanId);
  if (em) {
    em.removeAllListeners();
    emitters.delete(scanId);
  }
}

export default { create, emit, toSSE, dispose };
