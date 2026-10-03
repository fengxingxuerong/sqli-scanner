// ============================================================================
// patch/sqlmapRoutes.js —— 安全加固版 sqlmap 路由
// 基于 server/src/api/sqlmapRoutes.js 修改，修复项：
//   [P0-1] /start 目标 URL 过 SSRF 校验（与内置引擎同一策略）
//   [P2-6] /status 不再返回脚本/解释器绝对路径（bridge.status() 已修复）
// 其余逻辑与原文件一致。
// ============================================================================

import { Router } from 'express';
import crypto from 'crypto';
import { SqlmapBridge, diffSqlmapVulns, renderSqlmapMarkdown } from '../engine/sqlmapBridge.js';
import * as eventBus from '../core/eventBus.js';
import { ErrorCode, AppError } from '../core/errors.js';
import { logger } from '../core/logger.js';
import { assertSafeHttpTarget } from '../core/httpClient.js';
import { parseScope, assertInScope } from '../core/scopeGuard.js';

const bridge = new SqlmapBridge();
// [F2 2026-10-03] 命名导出：diff/export 的路由级测试需要往**同一个**单例里播种两条
// 真实形状的报告（扫描 Map 是桥的公开面 —— stop 路由本来就在读 bridge.scans）。
export { bridge };

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
    const rawUrl = typeof t.url === 'string' ? t.url.trim() : '';
    if (rawUrl) {
      await assertSafeHttpTarget(rawUrl);
      // [P0-SEC 2026-09-28 接口靶场] 授权范围红线必须与内置引擎同源：
      //   /scan/start 早就按 config.scope 硬拦越界目标，而 sqlmap 入口此前**只看 SSRF**。
      //   两条判据的分工本仓写得很清楚（scopeGuard.js：SSRF 管"别打自己人"，
      //   scope 管"别打没授权的人"）——漏了后一条，等于"配了授权范围仍可借 sqlmap
      //   模式打任意主机"，而这是用户显式配置过范围的情形，出事时最难自证清白。
      const scopeRules = parseScope(req.body?.config?.scope ?? req.body?.scope);
      if (scopeRules.enabled) assertInScope(rawUrl, scopeRules);
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
  // 与内置引擎 /scan/:id/stop 同一口径：未知 id 不能回 code:0。
  // 两个引擎共用一套前端控制面（useScan 按 engine 选路径），一边报成功一边报未找到
  // 会让"点了停止但还在跑"这类问题只在其中一条链路上暴露。
  const known = bridge.scans.has(req.params.id);
  const ok = bridge.stop(req.params.id);
  if (!ok && !known) {
    return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: { stopped: false }, message: 'sqlmap 任务不存在或已结束' });
  }
  res.json({ code: 0, data: { stopped: ok }, message: ok ? 'ok' : '任务已处于终态，无需停止' });
});

// GET /:id/report —— 最终报告（[审查修复] 挂报告护栏）
sqlmapRoutes.get('/:id/report', requireReport, (req, res) => {
  const report = bridge.getReport(req.params.id);
  if (!report) {
    return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '扫描不存在或已结束' });
  }
  res.json({ code: 0, data: report, message: 'ok' });
});

// [F2 2026-10-03 TODO 09-28 #3] GET /sqlmap/:id/diff?base=<sqlmapScanId>
//   对齐内置 /scan/:id/diff 的契约（缺 base / 任一侧不存在 ⇒ 显式错误，不静默空 diff）。
//   sqlmap 桥的 vuln 形状是 { param, technique, raw }，与内置报告的 points/vulns 不同构，
//   故 diff 键 = param::technique（同键视为同一条发现），输出 added/removed/unchanged
//   —— "修好一个点后再扫一遍"的取证语义与内置一致。
sqlmapRoutes.get('/:id/diff', requireReport, (req, res) => {
  const baseId = String(req.query.base || '').trim();
  if (!baseId) {
    return res.json({ code: ErrorCode.INVALID_ARGUMENT ?? 1, data: null, message: '缺少 base 参数（基线扫描 id）：/api/sqlmap/<id>/diff?base=<scanId>' });
  }
  const cur = bridge.getReport(req.params.id);
  const base = bridge.getReport(baseId);
  if (!cur) return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '当前扫描不存在' });
  if (!base) return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '基线扫描不存在' });
  res.json({ code: 0, data: diffSqlmapVulns(base.vulns, cur.vulns), message: 'ok' });
});

// [F2 2026-10-03 TODO 09-28 #3] GET /sqlmap/:id/report/export?format=json|markdown|md
//   对齐内置 /scan/:id/report/export 的契约形态（format 白名单 + attachment 头）。
//   桥的报告是 { engine, status, logs, vulns }，html/csv/sarif 是内置渲染器的交付面，
//   桥侧不假装支持 —— 白名单只放 json/markdown，其余显式 400（不做静默降级成 json）。
sqlmapRoutes.get('/:id/report/export', requireReport, (req, res) => {
  const FORMAT_EXT = { json: 'json', markdown: 'markdown', md: 'markdown' };
  const rawFormat = (req.query.format || 'json').toString().toLowerCase();
  if (!Object.prototype.hasOwnProperty.call(FORMAT_EXT, rawFormat)) {
    return res.status(400).json({
      code: ErrorCode.INVALID_PARAM,
      data: null,
      message: 'format 非法，sqlmap 桥支持 json/markdown/md（html/csv/sarif 是内置引擎报告渲染器的交付面）',
    });
  }
  const report = bridge.getReport(req.params.id);
  if (!report) {
    return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '扫描不存在或已结束' });
  }
  // id 进 Content-Disposition 文件名：与内置 export 同款白名单清洗（防头字段闭合）
  const safeId = String(req.params.id).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 40) || 'report';
  if (FORMAT_EXT[rawFormat] === 'json') {
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.setHeader('content-disposition', `attachment; filename="sqlmap-${safeId}.json"`);
    return res.send(JSON.stringify(report, null, 2));
  }
  res.setHeader('content-type', 'text/markdown; charset=utf-8');
  res.setHeader('content-disposition', `attachment; filename="sqlmap-${safeId}.md"`);
  res.send(renderSqlmapMarkdown(report));
});
