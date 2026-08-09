import { Router } from 'express';
import { tamperRegistry } from '../core/tamper/index.js';

// tamper 清单路由：只读暴露既有 TamperRegistry 的插件清单，作为前端多选的单一事实源
// （避免前端硬编码 62 项导致前后端漂移）。挂载于 /api 与 / 双前缀（兼容 Web / Tauri）。
export const tamperRoutes = Router();

// GET /api/tampers —— 返回全部已注册 tamper 插件元信息 [{ name, description }]
// 与 tamperRegistry.list() 完全一致；新增插件后此端点自动同步，无需前端改动。
tamperRoutes.get('/tampers', (req, res) => {
  res.json({ code: 0, data: tamperRegistry.list(), message: 'ok' });
});

export default tamperRoutes;
