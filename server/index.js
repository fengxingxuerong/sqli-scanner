import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { defaults } from './src/config/defaults.js';
import { scanRoutes } from './src/api/scanRoutes.js';
import { tamperRoutes } from './src/api/tamperRoutes.js';
import { healthRoutes } from './src/api/healthRoutes.js';
import { sqlmapRoutes } from './src/api/sqlmapRoutes.js';
import { exploitRoutes } from './src/api/exploitRoutes.js';
import { logger } from './src/core/logger.js';

dotenv.config();

const app = express();

// 仅监听本机回环地址（默认 127.0.0.1），避免引擎暴露到公网被当扫描放大器 / 拖库代理滥用。
// 需局域网 / 容器访问时通过 HOST 环境变量显式指定（如 0.0.0.0），但务必同时设置 ALLOWED_ORIGINS 与 SCAN_API_TOKEN。
const HOST = process.env.HOST || '127.0.0.1';

// 跨域：仅放行可信前端源（Vite 开发服、同机 API 直连、Tauri 同源），其余一律拒绝
const ALLOWED_ORIGINS = (
  process.env.ALLOWED_ORIGINS ||
  'http://localhost:5173,http://127.0.0.1:5173,http://localhost:4567,http://127.0.0.1:4567'
)
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      // 允许同源 / 无 origin（Tauri webview、服务端调用、curl）以及白名单内源
      if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      logger.warn(`CORS 拒绝来自 ${origin} 的请求`);
      return cb(new Error('CORS: 源不被允许'));
    },
    credentials: true,
  })
);

app.use(express.json({ limit: '2mb' }));

// 可选 API Token：设置 SCAN_API_TOKEN 后，所有非只读端点需携带
// x-api-token 请求头或 Authorization: Bearer <token>（纵深防御，默认不开启，保持开箱即用）。
const API_TOKEN = process.env.SCAN_API_TOKEN || '';
if (API_TOKEN) {
  app.use((req, res, next) => {
    if (req.method === 'OPTIONS' || req.method === 'GET') return next();
    const provided =
      req.headers['x-api-token'] ||
      String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
    if (provided && provided === API_TOKEN) return next();
    return res.status(401).json({ code: 401, data: null, message: '需要有效的 API Token' });
  });
}

// 路由挂载：同时挂载在 /api（Web 版，前端 base=/api）与 /（Tauri 版 base=http://127.0.0.1:4567）
// 保证两种形态均能用同一套端点契约访问引擎
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

// 兜底错误处理
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  logger.error(`未捕获的异常：${err.message}`);
  res.status(500).json({ code: 9001, data: null, message: '服务器内部错误' });
});

// 端口支持 process.env.PORT 覆盖（便于 CI/容器自定义），缺省回退到 defaults.port
const PORT = process.env.PORT ? Number(process.env.PORT) : defaults.port;
app.listen(PORT, HOST, () => {
  logger.info(`SQL 注入检测引擎已启动，监听 ${HOST}:${PORT}`);
});

export default app;
