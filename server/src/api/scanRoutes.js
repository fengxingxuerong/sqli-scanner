import { Router } from 'express';
import { ScanManager } from '../engine/ScanManager.js';
import * as eventBus from '../core/eventBus.js';
import { ErrorCode, AppError } from '../core/errors.js';
import { PAYLOADS, FINGERPRINT, TECHNIQUE_TYPES } from '../engine/payloads.js';
import { validateRiskGate, MIN_RISK, MAX_RISK } from '../engine/riskGate.js';
import { validateDetectMatch } from '../engine/detectionMatch.js';
import { defaults } from '../config/defaults.js';
import { logger } from '../core/logger.js';

// 校验并收敛 /scan/start 入参，防止非法目标 / 越界配置进入引擎。
// 兼容两种入参形态（向后兼容，双形态均归一化为 createTarget 期望的顶层形状）：
//   ① 文档契约 { target: { url, method, bodyParams, cookieParams, headerParams }, config }
//   ② 前端实际发送 { url, method, bodyParams, cookieParams, headerParams, config }（顶层扁平）
// 归一化结果：{ url, method, bodyParams, cookieParams, headerParams, config }
export function sanitizeStart(body) {
  const b = body || {};
  // 解析目标来源：优先 b.target（文档契约形态），否则回退到顶层扁平形态（前端实际发送）
  const src = b.target && typeof b.target === 'object' ? b.target : b;
  const rawUrl = typeof src.url === 'string' ? src.url : '';
  if (!rawUrl.trim()) {
    throw new AppError(ErrorCode.INVALID_PARAM, '缺少目标 URL');
  }
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new AppError(ErrorCode.INVALID_PARAM, '目标 URL 格式非法');
  }
  if (!/^https?:$/i.test(u.protocol)) {
    throw new AppError(ErrorCode.INVALID_PARAM, '仅支持 http/https 目标');
  }

  const cfg = b.config || {};
  const clamp = (v, def, min, max) => {
    const n = Number(v);
    return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : def;
  };
  const config = {
    ...cfg,
    ratePerSec: clamp(cfg.ratePerSec, defaults.ratePerSec, 1, 20),
    concurrency: clamp(cfg.concurrency, defaults.concurrency, 1, 10),
    retry: clamp(cfg.retry, defaults.retry, 0, 5),
    timeoutMs: clamp(cfg.timeoutMs, defaults.timeoutMs, 1000, 60000),
    enableExtract: !!cfg.enableExtract,
    // 风险分级（--risk 门控依赖）：归一化到 1-3，缺省沿用 defaults.risk（最保守）
    risk: clamp(cfg.risk, defaults.risk, MIN_RISK, MAX_RISK),
    // 检测等级（--level）：1-5，控制测哪些注入位置（URL/Body→+Cookie→+Header/UA/Referer）
    level: clamp(cfg.level, defaults.level, 1, 5),
    // 时间盲注 SLEEP 触发秒数（--time-sec）：1-60
    timeSec: clamp(cfg.timeSec, defaults.timeSec, 1, 60),
    // 固定请求间延时（--delay）：0-60000 ms，0 表示不延时
    requestDelayMs: clamp(cfg.requestDelayMs, defaults.requestDelayMs, 0, 60000),
    // HTTP 参数污染（--hpp）：布尔化
    hpp: !!cfg.hpp,
    // 连接复用（--keep-alive / --no-keep-alive）：默认 true；仅显式 false 才关闭
    keepAlive: cfg.keepAlive !== false,
  };
  // 安全间隔探测（--safe-url/--safe-freq/--safe-order）：url 支持逗号分隔多 URL，
  // 合并去重为 urls；freq 下限 0（0=关闭）；randomize 默认 true（false=顺序轮询）。
  if (cfg.safeProbe) {
    const sp = cfg.safeProbe;
    const urls = [];
    if (sp.url) urls.push(...String(sp.url).split(',').map((s) => s.trim()).filter(Boolean));
    if (Array.isArray(sp.urls)) urls.push(...sp.urls.map(String).map((s) => s.trim()).filter(Boolean));
    const merged = [...new Set(urls)];
    config.safeProbe = {
      url: sp.url || undefined,
      urls: merged.length ? merged : undefined,
      freq: Number(sp.freq) > 0 ? Number(sp.freq) : 0,
      randomize: sp.randomize !== false,
    };
  }
  if (cfg.techniques) {
    if (!Array.isArray(cfg.techniques) || cfg.techniques.some((tech) => !TECHNIQUE_TYPES.includes(tech))) {
      throw new AppError(ErrorCode.INVALID_PARAM, 'techniques 含非法技术类型');
    }
    config.techniques = cfg.techniques;
  }
  if (cfg.proxy) {
    if (typeof cfg.proxy !== 'string' || !/^(https?|socks5?):\/\//i.test(cfg.proxy)) {
      throw new AppError(ErrorCode.INVALID_PARAM, 'proxy 格式非法');
    }
    config.proxy = cfg.proxy;
  }
  // 二阶注入配置（透传并校验）：仅 enabled 布尔 + triggerUrls 为 http(s) 数组；缺省值沿用 defaults。
  if (cfg.secondOrder) {
    const so = cfg.secondOrder;
    config.secondOrder = {
      enabled: !!so.enabled,
      // 仅保留 http/https 的触发页 URL，过滤非法项（防止误把内网/异常地址当作触发页）
      triggerUrls: Array.isArray(so.triggerUrls)
        ? so.triggerUrls.filter((x) => typeof x === 'string' && /^https?:\/\//i.test(x))
        : [],
      autoDiscover: !!so.autoDiscover, // 触发页自动发现（opt-in；默认 false）
      refreshCsrf: so.refreshCsrf !== false, // 默认 true
      negativeControl: so.negativeControl !== false, // 默认 true
      oobTrigger: !!so.oobTrigger,
      // 手动存储点参数名：字符串数组（前端逗号/换行分隔解析），去空白与空项；与启发式 isStorePoint 取并集
      manualStorePoints: Array.isArray(so.manualStorePoints)
        ? so.manualStorePoints.map((x) => String(x).trim()).filter(Boolean)
        : [],
    };
  }
  // OOB 带外通道配置（透传并校验）：enabled 布尔 + callbackBase 字符串 + httpPort 端口 + timeoutMs 范围
  if (cfg.oob) {
    const o = cfg.oob;
    const httpPort = Number(o.httpPort);
    const timeoutMs = Number(o.timeoutMs);
    config.oob = {
      enabled: !!o.enabled,
      callbackBase: typeof o.callbackBase === 'string' && o.callbackBase.trim() ? o.callbackBase.trim() : '127.0.0.1:8899',
      httpPort: Number.isFinite(httpPort) && httpPort >= 1 && httpPort <= 65535 ? httpPort : 8899,
      timeoutMs: Number.isFinite(timeoutMs) && timeoutMs >= 1000 && timeoutMs <= 60000 ? timeoutMs : 5000,
    };
  }
  // tamper 链式配置归一化：仅确保形状正确，不拦截扫描。
  // enabled→布尔；plugins→字符串数组（非数组/含非字符串元素安全降级为 [] 或字符串数组）；
  // intensity∈{low,medium,high} 否则回退 medium。未知插件名不报错（由引擎 TamperRegistry.resolve 跳过）。
  if (cfg.wafEvasion && cfg.wafEvasion.tamper) {
    const t = cfg.wafEvasion.tamper;
    const intensity = ['low', 'medium', 'high'].includes(t.intensity) ? t.intensity : 'medium';
    const plugins = Array.isArray(t.plugins)
      ? t.plugins.filter((p) => typeof p === 'string')
      : [];
    config.wafEvasion = {
      ...config.wafEvasion,
      tamper: {
        enabled: !!t.enabled,
        plugins,
        intensity,
      },
    };
  }
  // --risk 门控：风险不足启用二阶/堆查询/OOB 直接拦截（抛 AppError，由路由 try/catch 转错误响应）
  validateRiskGate(config);
  // 自定义检测锚点：提前拦截非法 --regexp/--code（抛 AppError）
  validateDetectMatch(config);

  // 归一化为 createTarget 期望的顶层形状（含方法/参数透传，兼容前端扁平入参与文档 target 形态）
  return {
    url: u.toString(),
    method: (src.method || 'GET').toUpperCase(),
    bodyParams: src.bodyParams || {},
    cookieParams: src.cookieParams || {},
    headerParams: src.headerParams || {},
    config,
  };
}

const sm = new ScanManager();

export const scanRoutes = Router();

// POST /api/scan/start —— 启动扫描
scanRoutes.post('/scan/start', async (req, res) => {
  try {
    const sanitized = sanitizeStart(req.body);
    const scanId = await sm.start(sanitized);
    res.json({ code: 0, data: { scanId }, message: 'ok' });
  } catch (e) {
    const err = e instanceof AppError ? e : new AppError(ErrorCode.UNKNOWN, e.message);
    logger.warn(`启动扫描失败：${err.message}`);
    res.json({ code: err.code, data: null, message: err.message });
  }
});

// GET /api/scan/:id —— 实时报告快照
scanRoutes.get('/scan/:id', (req, res) => {
  const report = sm.getReport(req.params.id);
  if (!report) {
    return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '扫描不存在或已结束' });
  }
  res.json({ code: 0, data: report, message: 'ok' });
});

// GET /api/scan/:id/events —— SSE 实时进度流
scanRoutes.get('/scan/:id/events', (req, res) => {
  eventBus.toSSE(req.params.id, req, res);
});

// POST /api/scan/:id/stop —— 停止扫描
scanRoutes.post('/scan/:id/stop', (req, res) => {
  const ok = sm.stop(req.params.id);
  res.json({ code: 0, data: { stopped: ok }, message: 'ok' });
});

// GET /api/scan/:id/report —— 完整报告
scanRoutes.get('/scan/:id/report', (req, res) => {
  const report = sm.getReport(req.params.id);
  if (!report) {
    return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '扫描不存在或已结束' });
  }
  res.json({ code: 0, data: report, message: 'ok' });
});

// GET /api/scan/:id/report/export?format=json|html —— 导出报告
scanRoutes.get('/scan/:id/report/export', (req, res) => {
  const format = (req.query.format || 'json').toString().toLowerCase();
  const out = sm.exportReport(req.params.id, format);
  if (out == null) {
    return res.json({ code: ErrorCode.SCAN_NOT_FOUND, data: null, message: '扫描不存在或已结束' });
  }
  if (format === 'html') {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="report_${req.params.id}.html"`);
    return res.send(out);
  }
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="report_${req.params.id}.json"`);
  return res.send(out);
});

// GET /api/payloads?dbms=&technique= —— 只读查看 Payload 模板
scanRoutes.get('/payloads', (req, res) => {
  const dbms = req.query.dbms?.toString();
  const technique = req.query.technique?.toString();
  let data;
  if (dbms && technique) {
    data = (PAYLOADS[dbms] && PAYLOADS[dbms][technique]) || [];
  } else if (dbms) {
    data = PAYLOADS[dbms] || {};
  } else {
    data = { ...PAYLOADS, fingerprint: FINGERPRINT };
  }
  res.json({ code: 0, data, message: 'ok' });
});
