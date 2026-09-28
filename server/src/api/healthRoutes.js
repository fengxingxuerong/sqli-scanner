import { Router } from 'express';
import { ENGINE_VERSION, VERSION_SOURCE } from '../core/version.js';
import { isAuthEnabled } from '../core/apiAuthState.js';
import { defaults } from '../config/defaults.js';

export const healthRoutes = Router();

// GET /api/health —— 健康检查
// 字段口径：只放**布尔/计数**，不放绝对路径/命令行/环境变量原文（历史上 /sqlmap/status
// 就因回显脚本绝对路径被列为信息泄露 P2-6，同一个坑不在公开只读端点上重踩一次）。
// 这些字段是运维真正要看的：桌面 sidecar 起没起、鉴权开没开、利用能力开没开、有没有扫描在跑。
healthRoutes.get('/health', (req, res) => {
  res.json({
    code: 0,
    data: {
      status: 'up',
      version: ENGINE_VERSION,
      versionSource: VERSION_SOURCE,
      node: process.versions.node,
      authEnabled: isAuthEnabled(),
      exploitEnabled: process.env.EXPLOIT_ENABLED === '1' || process.env.EXPLOIT_ENABLED === 'true',
      ratePerSec: defaults.ratePerSec,
    },
    message: 'ok',
  });
});
