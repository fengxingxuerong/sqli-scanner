import { Router } from 'express';

export const healthRoutes = Router();

// GET /api/health —— 健康检查
healthRoutes.get('/health', (req, res) => {
  res.json({ code: 0, data: { status: 'up', version: '1.0.0' }, message: 'ok' });
});
