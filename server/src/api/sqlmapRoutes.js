// ============================================================================
// patch/sqlmapRoutes.js —— 安全加固版 sqlmap 路由
// 基于 server/src/api/sqlmapRoutes.js 修改，修复项：
//   [P0-1] /start 目标 URL 过 SSRF 校验（与内置引擎同一策略）
//   [P2-6] /status 不再返回脚本/解释器绝对路径（bridge.status() 已修复）
// 其余逻辑与原文件一致。
// ============================================================================

import { Router } from 'express';
import crypto from 'crypto';
import { SqlmapBridge } from '../engine/sqlmapBridge.js';
import * as eventBus from '../core/eventBus.js';
import { ErrorCode, AppError } from '../core/errors.js';
import { logger } from '../core/logger.js';
import { assertSafeHttpTarget } from '../core/httpClient.js';

const bridge = new SqlmapBridge();

export const sqlmapRoutes = Router();

// [审查修复] 报告护栏：与 scanRoutes 的 createReportGuard 对齐——全局 token
// （SCAN_API_TOKEN）开启时，stop/report/events 三端点要求有效 token（恒时比较），
// 不再依赖外层全局中间件一层防御；未配置 token 时直接放行（本地开发语义不变）。
function requireReport(req, res, next) {
  const token = process.env.SCAN_API_TOKEN || '';
  if (!token) return next();
  const safeEqual = (a, b) => {
    const ha = crypto.createHash('sha256').update(String(a ?? '')).digest();
    const hb = crypto.createHash('sha256').update(String(b ?? '')).digest();
    return crypto.timingSafeEqual(ha, hb);
  };
  const provided =
    String(req.headers['x-scan-token'] || '') ||
    String(req.headers['x-api-token'] || '') ||
    String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '') ||
    String((req.query && req.query.token) || '').trim();
  if (provided && safeEqual(provided, token)) return next();
  return res.status(401).json({ code: 401, data: null, message: '需要有效的 API Token' });
}

// GET /status —— sqlmap 是否可用（不返回脚本/解释器路径，防信息泄露）
sqlmapRoutes.get('/status', (req, res) => {
  res.json({ code: 0, data: bridge.status(), message: 'ok' });
});

// POST /start —— 启动一次 sqlmap 扫描（[P0-1] 目标 URL 过 SSRF 校验）
sqlmapRoutes.post('/start', async (req, res) => {
  try {
    const t = (req.body && req.body.target) || {};
    if (typeof t.url === 'string' && t.url.trim()) {
      await assertSafeHttpTarget(t.url);
    }
    const scanId = bridge.start(req.body);
    res.json({ code: 0, data: { scanId }, message: 'ok' });
  } catch (e) {
    const err = e instanceof AppError ? e : new AppError(ErrorCode.UNKNOWN, e.message);
    logger.warn(`启动 sqlmap 扫描失败：${err.message}`);
    res.json({ code: err.code, data: null, message: err.message });
  }
});

// GET /:id/events —— SSE 实时流（[审查修复] 挂报告护栏）
sqlmapRoutes.get('/:id/events', requireReport, (req, res) => {
  eventBus.toSSE(req.params.id, req, res);
});

// POST /:id/stop —— 停止扫描（[审查修复] 挂报告护栏）
sqlmapRoutes.post('/:id/stop', requireReport, (req, res) => {
  const ok = bridge.stop(req.params.id);
  res.json({ code: 0, data: { stopped: ok }, message: 'ok' });
});

// GET /:id/report —— 最终报告（[审查修复] 挂报告护栏）
sqlmapRoutes.get('/:id/report', requireReport, (req, res) => {
  const report = bridge.getReport(req.params.id);
  if (!report) {
    return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '扫描不存在或已结束' });
  }
  res.json({ code: 0, data: report, message: 'ok' });
});
