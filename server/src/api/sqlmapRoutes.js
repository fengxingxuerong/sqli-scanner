import { Router } from 'express';
import { SqlmapBridge } from '../engines/sqlmapBridge.js';
import * as eventBus from '../core/eventBus.js';
import { ErrorCode, AppError } from '../core/errors.js';
import { logger } from '../core/logger.js';

const bridge = new SqlmapBridge();

export const sqlmapRoutes = Router();

// GET /status —— sqlmap 是否可用（脚本是否存在 / Python 解释器）
sqlmapRoutes.get('/status', (req, res) => {
  res.json({ code: 0, data: bridge.status(), message: 'ok' });
});

// POST /start —— 启动一次 sqlmap 扫描
sqlmapRoutes.post('/start', (req, res) => {
  try {
    const scanId = bridge.start(req.body);
    res.json({ code: 0, data: { scanId }, message: 'ok' });
  } catch (e) {
    const err = e instanceof AppError ? e : new AppError(ErrorCode.UNKNOWN, e.message);
    logger.warn(`启动 sqlmap 扫描失败：${err.message}`);
    res.json({ code: err.code, data: null, message: err.message });
  }
});

// GET /:id/events —— SSE 实时流（复用内置引擎同一套 eventBus）
sqlmapRoutes.get('/:id/events', (req, res) => {
  eventBus.toSSE(req.params.id, req, res);
});

// POST /:id/stop —— 停止扫描（SIGTERM 子进程）
sqlmapRoutes.post('/:id/stop', (req, res) => {
  const ok = bridge.stop(req.params.id);
  res.json({ code: 0, data: { stopped: ok }, message: 'ok' });
});

// GET /:id/report —— 最终报告（日志 + 命中漏洞）
sqlmapRoutes.get('/:id/report', (req, res) => {
  const report = bridge.getReport(req.params.id);
  if (!report) {
    return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '扫描不存在或已结束' });
  }
  res.json({ code: 0, data: report, message: 'ok' });
});
