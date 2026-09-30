import { Router } from 'express';
import { ENGINE_VERSION, VERSION_SOURCE } from '../core/version.js';
import { isAuthEnabled } from '../core/apiAuthState.js';
import { defaults } from '../config/defaults.js';
// [P1-1 收口 2026-09-29] 利用能力开关的判据必须**唯一**：本文件曾自己写
// `process.env.EXPLOIT_ENABLED === '1' || === 'true'`，而 `bin/cli.js` 写 `!== '1'`
// —— 于是 `EXPLOIT_ENABLED=true`（.env.example 之外的常见写法）会出现
// 「REST 可用 / CLI 拒绝 / 这里回显 false」三方不一致；而 /health 是给监控看的，
// 它回显的状态与真实能力不符，等于把排障引向错误方向。
import { isExploitEnabled } from '../core/exploitFlag.js';

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
      // 每次请求现读（见 core/exploitFlag.js 的取值时机说明）：运维改完 env 不必重启，
      // 且回显的就是**此刻**的真实能力，与 /exploit/* 的实际判定同源。
      exploitEnabled: isExploitEnabled(),
      ratePerSec: defaults.ratePerSec,
    },
    message: 'ok',
  });
});
