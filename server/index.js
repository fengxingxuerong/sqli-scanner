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
import { existsSync, readFileSync } from 'node:fs';
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
  // Tauri v2 WebView 的页面 origin 不是 localhost（Windows/Linux 为 http://tauri.localhost，
  // macOS 为 tauri://localhost）。桌面版前端要跨域调用 127.0.0.1:4567，必须显式放行，
  // 否则会被引擎的「跨站变更请求」守卫一律 403（扫描/停止/导出全部不可用）。
  'http://localhost:5173,http://127.0.0.1:5173,http://localhost:4567,http://127.0.0.1:4567,http://tauri.localhost,tauri://localhost'
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

// ── API Token 解析（[P0-SEC 2026-09-17] 默认鉴权）─────────────────────────────
// 背景：本服务能对任意可达目标发起扫描与拖库。旧实现「没配 token 就整个鉴权中间件不装」，
// 而 Dockerfile 是 HOST=0.0.0.0 且未设 token → 直接 `docker run -p 4567:4567` 就是一个
// 无鉴权的扫描/拖库代理（可被当攻击跳板、可被任意读取报告数据）。
// 现有策略（fail-closed + 逃生口）：
//   1. SCAN_API_TOKEN_FILE（Docker/K8s secret 挂载）优先；
//   2. 其次 SCAN_API_TOKEN；
//   3. 都没有时：仅回环监听允许无鉴权（本地开发/桌面 sidecar 体验）；
//      非回环监听 → **拒绝启动**（除非显式 SCAN_API_ALLOW_NO_TOKEN=1 声明接受风险）。
export const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
// 同进程内 generated token 必须幂等：否则每次调用 resolveApiToken 都会换一个随机串，
// 出现「打印给父进程的 token ≠ 鉴权用的 token」这类只在 emit 模式暴露的错配。
let generatedTokenCache = null;
export function resolveApiToken({ host = '127.0.0.1', env = process.env } = {}) {
  const file = String(env.SCAN_API_TOKEN_FILE || '').trim();
  if (file) {
    try {
      const v = readFileSync(file, 'utf8').trim();
      if (v) return { token: v, source: 'file' };
      logger.warn(`SCAN_API_TOKEN_FILE=${file} 内容为空，已忽略`);
    } catch (e) {
      logger.warn(`读取 SCAN_API_TOKEN_FILE=${file} 失败：${e.message}`);
    }
  }
  const direct = String(env.SCAN_API_TOKEN || '').trim();
  if (direct) return { token: direct, source: 'env' };

  // [A3 2026-09-17] 桌面 sidecar 场景：Tauri 需要「引擎自己生成的一次性 token」——
  // Rust 标准库没有 CSPRNG，与其在壳里造弱的随机数，不如让 Node 用 crypto 生成后
  // 打印到 stdout（SCAN_API_TOKEN_EMIT=1），由壳捕获并经 get_engine_info 交给前端。
  if (String(env.SCAN_API_TOKEN_EMIT || '').trim() === '1') {
    if (!generatedTokenCache) generatedTokenCache = crypto.randomBytes(32).toString('hex');
    return { token: generatedTokenCache, source: 'generated' };
  }

  const exposed = !LOOPBACK_HOSTS.has(String(host || '').trim());
  if (!exposed) return { token: '', source: 'none' };
  if (String(env.SCAN_API_ALLOW_NO_TOKEN || '').trim() === '1') {
    return { token: '', source: 'none-explicit' };
  }
  throw new Error(
    `拒绝以无鉴权方式监听 ${host}：本服务可发起扫描/拖库，暴露到非回环接口时必须配置鉴权。\n` +
      '  任选其一： ① 设置 SCAN_API_TOKEN=<强随机串>；② 挂载 secret 后设置 SCAN_API_TOKEN_FILE=/run/secrets/scan_token；' +
      '③ 仅本机使用则设 HOST=127.0.0.1；④ 确知风险并接受无鉴权则设 SCAN_API_ALLOW_NO_TOKEN=1。'
  );
}

// 模块级解析一次：createApp 与 start 共用同一结论，避免「装配时没 token、启动时才生成」的不一致。
// 非回环监听且无 token 时这里直接抛错 → 进程启动失败（fail-closed，见 resolveApiToken 注释）。
const { token: API_TOKEN, source: TOKEN_SOURCE } = resolveApiToken({ host: HOST });

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

  // ── [P0-SEC 2026-09-09] 变更类请求的跨站驱动防护 ────────────────────────────────
  // 为什么必须自己拦而不能靠 cors：`cors` 在 Origin 不在白名单时只是「不发 Access-Control-* 头」，
  // 请求本身照样进 handler —— 浏览器读不到响应，但**写操作已经执行完了**。诱导受害浏览器
  // 「点一下就把扫描器的目标改掉 / 停掉正在跑的扫描 / 触发一次拖库」这条路今天是通的；
  // 现在没炸只是因为 express.json 不解析非 JSON body（侥幸 ≠ 防护）。
  // 同时本服务默认监听 127.0.0.1：浏览器能直接打到回环端口，SSRF 式「借工具打内网」也靠这条路。
  const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
  // [P1 2026-09-09] 统一错误响应可见性（两步走第一步）：所有含数字 code 字段的 JSON 错误响应
  // 自动携带 `X-Error-Code` 响应头。HTTP 状态码暂不变（前端已依赖 200+code 形态），
  // 但监控/网关/代理/curl -f 现在能看到失败率；第二步（灰度切状态码）待前端侧改造后单独做。
  // 必须在一切可能写错误响应的中间件（逆 CSRF/token/路由）之前安装，零业务行为变化。
  app.use((req, res, next) => {
    const origJson = res.json.bind(res);
    res.json = (body) => {
      // 约定：code=0 为成功（health 等）；非 0 整数 code 视为业务/HTTP 错误 → 携带 X-Error-Code。
      // 覆盖「HTTP 200 + code」形态（前端已依赖），并自然覆盖原生 4xx/5xx。
      if (body && typeof body === 'object' && body !== null && Number.isInteger(body.code) && body.code !== 0) {
        res.setHeader('X-Error-Code', String(body.code));
      }
      return origJson(body);
    };
    next();
  });
  app.use((req, res, next) => {
    if (!MUTATING_METHODS.has(req.method)) return next();
    const origin = String(req.headers.origin || '');
    if (origin) {
      const host = String(req.headers.host || '');
      // 同源（含 Tauri/静态托管同 host:port）直接放行：不要求把每个部署端口都写进 ALLOWED_ORIGINS
      const sameOrigin = !!host && (origin === `http://${host}` || origin === `https://${host}`);
      if (!sameOrigin && !ALLOWED_ORIGINS.includes(origin)) {
        logger.warn(`拒绝跨站变更请求：origin=${origin} path=${req.path}`);
        return res
          .status(403)
          .json({ code: 403, data: null, message: 'Origin 不在允许列表内（防止跨站驱动扫描器），如确需请设 ALLOWED_ORIGINS' });
      }
    } else if (String(req.headers['sec-fetch-site'] || '').toLowerCase() === 'cross-site') {
      // 浏览器发跨站请求一定会带 Origin；「无 Origin 却自称 cross-site」只能是刻意剥离，一律拒
      return res
        .status(403)
        .json({ code: 403, data: null, message: 'Sec-Fetch-Site=cross-site 且无 Origin，已拒绝' });
    }
    // 请求体类型守卫：本服务只接受 application/json。带 body 却是别的类型（form / text/plain / multipart）
    // 只可能是浏览器自动发出的简单请求 → 明确 415，而不是留给 express.json 静默丢 body 后报「参数缺失」。
    const ct = String(req.headers['content-type'] || '');
    const mayHaveBody = req.headers['content-length'] !== undefined && Number(req.headers['content-length']) > 0;
    if (mayHaveBody && ct && !/^application\/json\b/i.test(ct)) {
      return res
        .status(415)
        .json({ code: 415, data: null, message: `仅接受 application/json 请求体（收到 ${ct}）` });
    }
    return next();
  });

  app.use(express.json({ limit: '2mb' }));
  // P1: 安全响应头（CSP 收紧 + 防点击劫持 + 防 MIME 嗅探）
  // [P0-FIX 2026-09-17] CSP 必须按「响应类型」分流，不能一刀切：
  // 旧实现对所有响应下发 `default-src 'none'`，连 express.static 托管的 dist/index.html 与
  // /assets/*.js 也被禁 → 浏览器拒绝执行前端脚本 → **Docker 单端口部署（4567）打开即白屏**。
  // 本地开发（Vite 5173）与 Tauri（自有 CSP）都不经过这里，所以这个缺陷在开发期永远测不出来。
  //   · API 响应（/api / /sqlmap）：纯数据，不需要任何资源加载 → default-src 'none'（最严）
  //   · 前端静态资源：允许同源脚本/样式/字体/图片；MUI(emotion) 运行期注入 <style> →
  //     style-src 需 'unsafe-inline'；图标/字体可能为 data: → img-src/font-src 放行 data:
  const CSP_API = "default-src 'none'; frame-ancestors 'none'";
  const CSP_STATIC =
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'";
  const isApiResponse = (p) => p.startsWith('/api') || p.startsWith('/sqlmap');
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', isApiResponse(req.path) ? CSP_API : CSP_STATIC);
    next();
  });

  // 可选 API Token：设置后，除「完全只读的公开元数据」外的端点
  // （含扫描报告/导出/SSE）均需携带 x-api-token 请求头或 Authorization: Bearer <token>。
  // [P0-SEC 2026-09-17] 鉴权状态在装配时显式播报一次（token 由模块级 resolveApiToken 统一解析，
  // 这里只读不解析——避免"装配一处、启动一处"各生成一份随机 token 的错配）。
  if (API_TOKEN) {
    logger.info(`API 鉴权已启用（来源 ${TOKEN_SOURCE}）`);
  } else if (TOKEN_SOURCE === 'none-explicit') {
    logger.warn(
      '⚠️ 已显式声明无鉴权（SCAN_API_ALLOW_NO_TOKEN=1）：任何可达客户端都能调用全部 API（含扫描/拖库）。仅应在隔离网络中使用。'
    );
  } else {
    logger.warn('未设置 SCAN_API_TOKEN：仅回环监听，本机任意进程可调用全部 API（含扫描/拖库）。生产部署请设置 Token。');
  }
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
    // [交付缺口修复 2026-09-16] body-parser 错误分流：客户端输入问题按 400/413 语义化返回，
    // 不再落入 9001「服务器内部错误」（系统本就不崩，但状态码与提示误导排障方向）。
    if (err && (err.type === 'entity.parse.failed' || (err instanceof SyntaxError && err.status === 400 && 'body' in err))) {
      return res.status(400).json({ code: 1002, data: null, message: `请求体不是合法 JSON：${String(err.message).slice(0, 120)}` });
    }
    if (err && err.type === 'entity.too.large') {
      return res.status(413).json({ code: 1004, data: null, message: '请求体超出大小限制（2mb）' });
    }
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
  // [A3] 桌面 sidecar：把一次性 token 以固定格式打到 stdout，供 Tauri 壳捕获后交给前端。
  // 仅 SCAN_API_TOKEN_EMIT=1（壳显式要求）时输出，普通 CLI/服务端启动不打印任何额外内容。
  if (TOKEN_SOURCE === 'generated' && API_TOKEN) {
    process.stdout.write(`ENGINE_TOKEN=${API_TOKEN}\n`);
  }
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
