// --risk 分级门控（对标 sqlmap --risk）：把「高风险/高影响」技术类别绑定到最低 risk 级别，
// 低于阈值强行启用即被拦截并给出可读错误，避免对目标意外发起写请求 / 多语句 / 出站带外。
//
// 门控仅作用在「用户入口」（CLI cli.js + HTTP API scanRoutes.js），不进入 ScanManager.start——
// 引擎内部单测（二阶/堆查询/OOB 检测器）直接构造 config 调用，不应被操作员安全策略拦截。
import { ErrorCode, AppError } from '../core/errors.js';

export const MIN_RISK = 1;
export const MAX_RISK = 3;

// 各高风险技术类别所需的最低 --risk 级别。
//   second_order: 二阶注入——对目标发起真实写请求（存储点 + 触发页），有状态、可能留痕。
//   stacked:      堆查询——多语句执行（;` 续句），可能改写/破坏数据，破坏性最强之一。
//   oob:          带外——依赖外部接收端（DNS/SMB/HTTP 回连），出站噪声最大、易被监测。
export const RISK_MIN = {
  second_order: 2,
  stacked: 2,
  oob: 3,
};

// 校验 config 中的高风险技术是否被 --risk 门控允许。不允许则抛清晰 AppError。
// config.risk 缺省按 MIN_RISK（最保守）处理；取值范围校验 1-3。
// 返回 true 表示放行。
export function validateRiskGate(config) {
  const cfg = config || {};
  const risk = Number.isFinite(Number(cfg.risk)) ? Number(cfg.risk) : MIN_RISK;
  if (risk < MIN_RISK || risk > MAX_RISK) {
    throw new AppError(ErrorCode.INVALID_PARAM, `--risk 必须在 ${MIN_RISK}-${MAX_RISK} 之间（当前 ${cfg.risk}）`);
  }

  const violations = [];

  const so = cfg.secondOrder || {};
  if (so.enabled && risk < RISK_MIN.second_order) {
    violations.push(`二阶注入(second_order) 需 --risk >= ${RISK_MIN.second_order}`);
  }

  const techs = Array.isArray(cfg.techniques) ? cfg.techniques : [];
  if (techs.includes('stacked') && risk < RISK_MIN.stacked) {
    violations.push(`堆查询(stacked) 需 --risk >= ${RISK_MIN.stacked}`);
  }
  if (techs.includes('oob') && risk < RISK_MIN.oob) {
    violations.push(`带外(oob) 需 --risk >= ${RISK_MIN.oob}`);
  }

  if (violations.length) {
    throw new AppError(
      ErrorCode.INVALID_PARAM,
      `当前 --risk=${risk} 不足以启用以下高风险技术：\n  - ${violations.join('\n  - ')}\n` +
        `请提升 --risk 级别后重试（二阶/堆查询需 ${RISK_MIN.second_order}，带外需 ${RISK_MIN.oob}）。`
    );
  }
  return true;
}
