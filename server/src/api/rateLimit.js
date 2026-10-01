// ============================================================================
// rateLimit.js —— API 速率限制（固定窗口 · 进程内 · 零新增依赖）
//
// [全方位优化建议 2026-09-30 §1.2] 审计认定「持有 token 即可无限调 /scan/start、
// /exploit/*、/report/ai」是唯一明显的安全缺口。修法与审计建议的差异（有意为之）：
//   ① 不用 express-rate-limit 依赖——服务端依赖清单刻意极简，且本仓已有
//      core/http/tokenBucket.js 同类先例；固定窗口计数器 ~80 行完全可测。
//   ② 限流挂到**具体路由**上而不是整个 router 前面：scanRoutes 同时承载
//      GET /scan/:id/status（UI 每秒轮询）与 /scan/:id/report 读取，整 router 限流
//      会直接打断前端。只限「贵」端点：POST /scan/start（新建扫描）、
//      POST /exploit/*（利用动作）、POST /scan/:id/report/ai（外发 LLM 烧钱）。
//   ③ 鉴权/CSRF 在中间件链上游（index.js），被 401/403/415 拒绝的请求到不了这里，
//      不消耗配额——未持有 token 的攻击者无法用 429 枯竭受害者的合法配额。
//
// 计额 key：token 前 8 位（x-api-token / x-scan-token / Bearer）|| req.ip。
// 与审计 §1.2 的 keyGenerator 一致；不同 token 独立计额，同一 token 共享配额。
//
// 环境变量：RATE_LIMIT_SCAN_MAX（默认 10 / 分钟）、RATE_LIMIT_EXPLOIT_MAX（默认 30 /
// 分钟）、RATE_LIMIT_AI_MAX（默认 20 / 小时）。显式设 0 = 关闭该档限流（本地压测用）。
// ============================================================================

import { ErrorCode } from '../core/errors.js';
import { logger } from '../core/logger.js';

/**
 * 从请求中提取 token 计额键（与 index.js 鉴权中间件的取值顺序一致：x-api-token 优先，
 * x-scan-token 其次，Authorization Bearer 最后）。取前 8 位做键——既隔离不同持有者，
 * 又避免完整凭据落进内存键与日志；无 token 回落 req.ip（本地/无鉴权部署仍有限流语义）。
 * @param {import('express').Request} req
 * @returns {string}
 */
export function tokenKeyOf(req) {
  const token =
    req.headers['x-api-token'] ||
    req.headers['x-scan-token'] ||
    String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '') ||
    '';
  const prefix = String(token).trim().slice(0, 8);
  return prefix || req.ip || 'anonymous';
}

/**
 * 构造固定窗口限流中间件。
 * @param {object} opts
 * @param {number} opts.windowMs 窗口长度（毫秒）
 * @param {number} opts.max 窗口内允许的最大请求数；<=0 时返回直通中间件（限流关闭）
 * @param {string} opts.name 限流档名（日志与错误文案用，如 'scan-start'）
 * @param {(req: import('express').Request) => string} [opts.keyOf] 计额键（默认 tokenKeyOf）
 */
export function createRateLimiter({ windowMs, max, name, keyOf = tokenKeyOf }) {
  // 关闭档（max<=0）：直通。测试/本地压测可用环境变量显式关掉。
  if (!Number.isFinite(max) || max <= 0) {
    const passthrough = (_req, _res, next) => next();
    passthrough.enabled = false;
    return passthrough;
  }
  /** @type {Map<string, {count:number, windowStart:number}>} */
  const hits = new Map();
  const sweep = (now) => {
    for (const [k, v] of hits) {
      if (v.windowStart + windowMs <= now) hits.delete(k);
    }
  };
  const middleware = (req, res, next) => {
    // CORS 预检不计额（它不代表业务动作）
    if (req.method === 'OPTIONS') return next();
    const now = Date.now();
    // 惰性清扫：窗口翻新过的条目即时回收；表过大时强制全量清一次（防长期驻留膨胀）
    if (hits.size > 10000) sweep(now);
    const key = keyOf(req);
    const entry = hits.get(key);
    if (!entry || entry.windowStart + windowMs <= now) {
      hits.set(key, { count: 1, windowStart: now });
      res.setHeader('RateLimit-Limit', String(max));
      res.setHeader('RateLimit-Remaining', String(max - 1));
      res.setHeader('RateLimit-Reset', String(Math.ceil(windowMs / 1000)));
      return next();
    }
    entry.count += 1;
    const resetSec = Math.max(1, Math.ceil((entry.windowStart + windowMs - now) / 1000));
    res.setHeader('RateLimit-Limit', String(max));
    res.setHeader('RateLimit-Reset', String(resetSec));
    if (entry.count > max) {
      res.setHeader('RateLimit-Remaining', '0');
      res.setHeader('Retry-After', String(resetSec));
      logger.warn(`速率限制触发（${name}）：429，ip=${req.ip}，path=${req.originalUrl || req.url}`);
      return res.status(429).json({
        code: ErrorCode.RATE_LIMITED,
        data: null,
        message: `请求过于频繁（${name}：每 ${Math.round(windowMs / 1000)} 秒最多 ${max} 次），请 ${resetSec} 秒后重试`,
      });
    }
    res.setHeader('RateLimit-Remaining', String(max - entry.count));
    return next();
  };
  middleware.enabled = true;
  return middleware;
}

const envMax = (v, dflt) => {
  const n = Number(process.env[v]);
  return Number.isFinite(n) ? n : dflt;
};

// —— 三个预配置档（审计 §1.2 的阈值；挂载点见各路由文件内的同名标注）——

/** POST /scan/start：每分钟最多 10 次新扫描（并发槽之外的滥用面） */
export const scanStartLimiter = createRateLimiter({
  windowMs: 60_000,
  max: envMax('RATE_LIMIT_SCAN_MAX', 10),
  name: 'scan-start',
});

/** POST /exploit/*：每分钟最多 30 次利用动作 */
export const exploitLimiter = createRateLimiter({
  windowMs: 60_000,
  max: envMax('RATE_LIMIT_EXPLOIT_MAX', 30),
  name: 'exploit',
});

/** POST /scan/:id/report/ai：每小时最多 20 次（外发 LLM 请求直接烧钱） */
export const aiReportLimiter = createRateLimiter({
  windowMs: 3_600_000,
  max: envMax('RATE_LIMIT_AI_MAX', 20),
  name: 'report-ai',
});
