// ============================================================================
// reportAiRoutes.js —— LLM 自动漏洞报告生成 API 路由
// POST /api/scan/:id/report/ai  — 用 LLM 生成自然语言安全分析报告
// GET  /api/scan/:id/report/ai/configs — 列出可用 AI 模型组合
// 安全：限速（防 API 被滥用烧配额）+ 环境变量读取 key + 数据脱敏
// ============================================================================

import { Router } from 'express';
import { defaultScanManager } from './scanRoutes.js';
import { generateAiReport, listAiConfigs, isAiReportEnabled } from '../services/ReportAI.js';
import { AppError, ErrorCode } from '../core/errors.js';

const router = Router();

// AI 报告限速：每 IP 每分钟最多 3 次（防滥用烧 LLM 配额 + 防打崩服务端）
const aiRateMap = new Map(); // ip -> { count, resetAt }
const AI_RATE_LIMIT = 3;
const AI_RATE_WINDOW = 60000;

function checkAiRate(req) {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const now = Date.now();
  let entry = aiRateMap.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + AI_RATE_WINDOW };
    aiRateMap.set(ip, entry);
  }
  // P1: 清理过期条目防 Map 无界增长（阈值触发式清理）
  if (aiRateMap.size > 1024) {
    for (const [k, v] of aiRateMap) {
      if (now > v.resetAt) aiRateMap.delete(k);
    }
  }
  if (entry.count >= AI_RATE_LIMIT) {
    throw new AppError(ErrorCode.RATE_LIMITED, `AI 报告生成过于频繁，请每分钟最多 ${AI_RATE_LIMIT} 次`);
  }
  entry.count++;
}

// POST /api/scan/:id/report/ai — 生成 AI 报告
router.post('/:id/report/ai', async (req, res, next) => {
  try {
    // 限速防护：防 API 被滥用烧配额 + 防打崩服务端
    checkAiRate(req);

    // [P2-FIX] 数据外发 opt-in 预检：未显式设置 AI_REPORT_API_BASE 时拒绝生成，
    // 防止用户误以为已在生成而报告实际被静默发送至第三方（或静默失败）。
    // 用 409 Conflict 明确区分“未启用”与“下游不可用(502/503)”。
    if (!isAiReportEnabled()) {
      throw new AppError(ErrorCode.AI_REPORT_DISABLED, 'AI 报告功能未启用：需同时设置 AI_REPORT_API_BASE（信任的 AI 服务端点）与 AI_REPORT_KEY_1 才能外发生成报告');
    }

    const scanId = req.params.id;
    const sm = defaultScanManager;
    const scan = sm.scans.get(scanId);
    if (!scan) {
      throw new AppError(ErrorCode.SCAN_NOT_FOUND, '扫描任务不存在');
    }

    const report = scan.report;
    if (!report) {
      throw new AppError(ErrorCode.SCAN_NOT_FOUND, '扫描报告尚未生成');
    }

    // 安全：key/model 组合仅由服务端环境变量控制，不允许请求方覆盖
    // （防他人通过 API 请求选择不同 key 烧配额）
    const result = await generateAiReport(report, 120000); // 120s 超时（长报告）

    res.json({
      code: 0,
      data: result,
      message: 'ok',
    });
  } catch (e) {
    if (e instanceof AppError) {
      const status = e.code === ErrorCode.RATE_LIMITED ? 429
        : e.code === ErrorCode.SCAN_NOT_FOUND ? 404
        : e.code === ErrorCode.AI_REPORT_DISABLED ? 409
        : e.message.includes('AI 报告功能未配置') ? 503 : 500;
      res.status(status === 500 && (e.message.includes('LLM API') || e.message.includes('LLM 请求超时')) ? 502 : status)
        .json({ code: e.code, message: e.message });
    } else if (e.message?.includes('LLM API 错误') || e.message?.includes('LLM 请求超时') || e.message?.includes('AI 报告功能未配置')) {
      const status = e.message.includes('AI 报告功能未配置') ? 503 : 502;
      res.status(status).json({ code: status === 503 ? 5031 : 5002, message: e.message });
    } else {
      next(e);
    }
  }
});

// GET /api/scan/:id/report/ai/configs — 列出 9 种可用组合
router.get('/:id/report/ai/configs', (req, res) => {
  res.json({
    code: 0,
    data: listAiConfigs(),
    message: 'ok',
  });
});

export { router as reportAiRoutes };
export default router;