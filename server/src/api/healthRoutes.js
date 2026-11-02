import { Router } from 'express';
import { ENGINE_VERSION, VERSION_SOURCE } from '../core/version.js';
import { isAuthEnabled } from '../core/apiAuthState.js';
import { getEventLoopStats } from '../core/eventLoopWatch.js';
import { defaults } from '../config/defaults.js';
// [P1-1 收口 2026-09-29] 利用能力开关的判据必须**唯一**：本文件曾自己写
// `process.env.EXPLOIT_ENABLED === '1' || === 'true'`，而 `bin/cli.js` 写 `!== '1'`
// —— 于是 `EXPLOIT_ENABLED=true`（.env.example 之外的常见写法）会出现
// 「REST 可用 / CLI 拒绝 / 这里回显 false」三方不一致；而 /health 是给监控看的，
// 它回显的状态与真实能力不符，等于把排障引向错误方向。
import { isExploitEnabled } from '../core/exploitFlag.js';
// [D-SSRF-IPV6-CIDR 2026-10-12] 出站策略态可观测（spec 5.4.1 规则 5）：
// 配置了内网放行 → 暴露"策略放宽"信号，运维一眼看出 SSRF 严格层被打开。
import { getEgressPolicy } from '../core/http/egressGuard.js';

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
      // 出站策略态：strict=基础层+严格层全开；relaxed=SSRF_ALLOW_PRIVATE 或 allowCidrs 非空。
      // cloudMetadataBlocked 恒 true（云元数据属基础层，不可被任何配置豁免）。
      egressPolicy: getEgressPolicy(),
      // [D236] 事件循环滞后观测（最近一个采样窗口的 p99/max/采样数，毫秒）：超阈值时
      // 服务端已有节流 warn 日志，这里是同源指标——运维不用翻日志就能看到卡顿水位。
      // CLI/MCP 未启动观测时全零（形状恒定）。仍属「布尔/计数」字段口径。
      eventLoop: getEventLoopStats(),
    },
    message: 'ok',
  });
});
