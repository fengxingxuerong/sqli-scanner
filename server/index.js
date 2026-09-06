// ============================================================================
// index.js —— 引擎入口
// 功能：
//   Express 装配：CORS / API Token / SSRF 告警 / 路由 / 前端静态托管 / 兜底错误处理
//   Token 恒时比较（crypto.timingSafeEqual，先 SHA-256 归一长度）
//   PUBLIC_READONLY 精确路径集合（不含通配，防未来路由绕过）
//   HOST 非回环且未设 token 时启动打显著告警
//   优雅关闭：SIGTERM/SIGINT → drainRunningScans → 10s 超时兜底 → exit
//   createApp 导出供测试无副作用 import
// ============================================================================

import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import crypto from 'node:crypto';
import { existsSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { defaults } from './src/config/defaults.js';
import { scanRoutes, defaultScanManager } from './src/api/scanRoutes.js';
import { tamperRoutes } from './src/api/tamperRoutes.js';
import { healthRoutes } from './src/api/healthRoutes.js';
import { sqlmapRoutes } from './src/api/sqlmapRoutes.js';
import { exploitRoutes } from './src/api/exploitRoutes.js';
import { reportAiRoutes } from './src/api/reportAiRoutes.js';
import { logger } from './src/core/logger.js';
import { oobReceiver } from './src/core/oobReceiver.js';
import { httpClient } from './src/core/httpClient.js';

dotenv.config();

// 仅监听本机回环地址（默认 127.0.0.1），避免引擎暴露到公网被当扫描放大器 / 拖库代理滥用。
// 需局域网 / 容器访问时通过 HOST 环境变量显式指定（如 0.0.0.0），但务必同时设置
// ALLOWED_ORIGINS 与 SCAN_API_TOKEN，并开启 SSRF 严格防护（SSRF_STRICT=1）。
const HOST = process.env.HOST || '127.0.0.1';

// 跨域白名单（Vite 开发服、同机 API 直连、Tauri 同源），其余一律拒绝
const ALLOWED_ORIGINS = (
  process.env.ALLOWED_ORIGINS ||
  'http://localhost:5173,http://127.0.0.1:5173,http://localhost:4567,http://127.0.0.1:4567'
)
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

// ── 恒时 token 比较（P2-1）──────────────────────────────────────────────────
// 先对两边做 SHA-256 归一（固定 32 字节），再 timingSafeEqual，消除长度/时序侧信道。
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a ?? '')).digest();
  const hb = crypto.createHash('sha256').update(String(b ?? '')).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// 无需 token 的公开只读路径（精确集合，P2-6）：健康检查 / payload 模板 / tamper 清单 /
// 利用能力清单 / sqlmap 可用性（注意：sqlmap/status 由 sqlmapRoutes 修复后不再返回路径）。
const PUBLIC_READONLY = new Set([
  '/health',
  '/api/health',
  '/payloads',
  '/api/payloads',
  '/tampers',
  '/api/tampers',
  '/exploit/capabilities',
  '/api/exploit/capabilities',
  '/sqlmap/status',
  '/api/sqlmap/status',
]);

/**
 * 装配 Express 应用（P1-A5：装配与启动分离，便于测试注入 / 无副作用 import）。
 */
export function createApp() {
  const app = express();

  app.use(
    cors({
      origin: (origin, cb) => {
        if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
        logger.warn(`CORS 拒绝来自 ${origin} 的请求`);
        // [P0-FIX] cb(null, false) 让 cors 返回 403 而非 cb(new Error) 被 Express 兜底为 500
        return cb(null, false);
      },
      credentials: true,
    })
  );

  app.use(express.json({ limit: '2mb' }));

  // P1: 安全响应头（CSP 收紧 + 防点击劫持 + 防 MIME 嗅探）
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    next();
  });

  // 可选 API Token：设置 SCAN_API_TOKEN 后，除「完全只读的公开元数据」外的端点
  // （含扫描报告/导出/SSE）均需携带 x-api-token 请求头或 Authorization: Bearer <token>。
  const API_TOKEN = process.env.SCAN_API_TOKEN || '';
  if (API_TOKEN) {
    app.use((req, res, next) => {
      if (req.method === 'OPTIONS') return next();
      const isPublicReadonly = req.method === 'GET' && PUBLIC_READONLY.has(req.path);
      if (isPublicReadonly) return next();
      // x-api-token header 优先；Authorization Bearer 其次；query token 为 SSE EventSource 备选
      // （EventSource 无法设置自定义头，只能用 query 参数透传 token）
      const provided =
        req.headers['x-api-token'] ||
        String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '') ||
        String(req.query['token'] || '').trim();
      if (provided && safeEqual(provided, API_TOKEN)) return next(); // P2-1 恒时比较
      return res.status(401).json({ code: 401, data: null, message: '需要有效的 API Token' });
    });
  } else if (HOST !== '127.0.0.1' && HOST !== 'localhost') {
    // P0-1 配套：引擎暴露在非回环接口且未设 token —— 显著告警，防止被当无鉴权扫描代理滥用
    logger.warn(
      `⚠️ 引擎正在监听 ${HOST} 且未设置 SCAN_API_TOKEN：任何可达客户端都能无鉴权调用全部 API（含扫描/拖库/利用）。` +
        `强烈建议设置 SCAN_API_TOKEN，并开启 SSRF_STRICT=1。`
    );
  }

  // 路由挂载：同时挂载在 /api（Web 版，前端 base=/api）与 /（Tauri 版 base=http://127.0.0.1:4567）
  app.use('/api', healthRoutes);
  app.use('/api', scanRoutes);
  app.use('/api', exploitRoutes);
  app.use('/api', tamperRoutes);
  app.use('/', healthRoutes);
  app.use('/', scanRoutes);
  app.use('/', exploitRoutes);
  app.use('/', tamperRoutes);

  // 混合架构：sqlmap 后端（高级模式），与内置引擎共用 SSE/事件契约
  app.use('/api/sqlmap', sqlmapRoutes);
  app.use('/sqlmap', sqlmapRoutes);

  // LLM 自动漏洞报告生成（9 组 key/model 组合）
  app.use('/api/scan', reportAiRoutes);
  app.use('/scan', reportAiRoutes);

  // Docker/单进程部署：Express 托管前端产物（替代 vite preview，砍掉前端 node_modules）
  // 仅当 dist 目录存在时生效；开发模式用 Vite 代理（原 /api 路由不变）
  // [Windows 修复] fileURLToPath 替代 .pathname：URL.pathname 在 Windows 返回 /D:/... 非法路径
  try {
    const indexPath = fileURLToPath(new URL('../dist/index.html', import.meta.url));
    if (existsSync(indexPath)) {
      const distDir = fileURLToPath(new URL('../dist/', import.meta.url));
      app.use(express.static(distDir));
      // SPA fallback：仅非 API 路径返回 index.html；未匹配的 API 路径返回 404 JSON
      // （防止 /api/unknown 落入 fallback 且不发响应 → 请求悬挂）
      app.use((req, res, next) => {
        if (req.path.startsWith('/api') || req.path.startsWith('/sqlmap')) {
          return res.status(404).json({ code: 404, data: null, message: 'Not Found' });
        }
        if (req.method === 'GET') {
          return res.sendFile(indexPath);
        }
        // 非 GET 的非 API 请求兜底（防 next() 后无 handler 悬挂）
        return res.status(404).json({ code: 404, data: null, message: 'Not Found' });
      });
    }
  } catch { /* dist 不存在时跳过（开发模式） */ }

  // 兜底错误处理
  app.use((err, req, res, next) => {
    // [P0-FIX] 打印完整堆栈（生产可脱敏），便于线上排障定位
    logger.error(`未捕获的异常：${err.message}\n${err.stack || ''}`);
    res.status(500).json({ code: 9001, data: null, message: '服务器内部错误' });
  });

  return app;
}

// 等待在途扫描收尾：轮询 defaultScanManager.scans 直到无 running 或超时。
async function drainRunningScans(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    // [P0-FIX] 遗漏 paused 状态：paused 扫描的 _run 循环仍在 300ms 轮询中等待，需一并计入
    const running = [...defaultScanManager.scans.values()].filter(
      (s) => s.status === 'running' || s.status === 'paused'
    );
    if (running.length === 0) return;
    await new Promise((r) => setTimeout(r, 100));
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function start() {
  const app = createApp();
  const PORT = process.env.PORT ? Number(process.env.PORT) : defaults.port;
  const server = app.listen(PORT, HOST, () => {
    logger.info(`SQL 注入检测引擎已启动，监听 ${HOST}:${PORT}`);
  });

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    logger.info(`收到 ${signal}，正在优雅关闭引擎…`);
    // 仅从收到信号起计时 10 秒（不在启动时计时，防「启动 10 秒后自杀」）
    const killTimer = setTimeout(() => {
      logger.warn('优雅关闭超时，强制退出');
      process.exit(1);
    }, 10000);
    server.close();
    await Promise.race([drainRunningScans(5000), sleep(5000)]);
    await oobReceiver.stop();
    httpClient.close();
    clearTimeout(killTimer);
    logger.info('引擎已关闭');
    process.exit(0);
  };
  // [P0-FIX] 全局未捕获 Promise rejection / 异常处理器
  // Node.js 15+ 默认对未处理的 rejection 终止进程，对长驻扫描引擎是致命的。
  process.on('unhandledRejection', (reason) => {
    logger.error(`未处理的 Promise rejection：${reason?.stack || reason}`);
  });
  process.on('uncaughtException', (err) => {
    logger.error(`未捕获的异常：${err.stack || err.message}`);
    // 触发优雅关闭（而非直接 exit，让在途扫描有机会收尾）
    shutdown('uncaughtException');
  });
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  return server;
}

// 作为主模块直接运行时启动；被 import（测试/复用）时不自动监听（P1-A5）。
const isMain =
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  start();
}

export default createApp;
