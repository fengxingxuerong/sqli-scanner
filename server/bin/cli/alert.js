// ============================================================================
// alert.js —— [D199 2026-11-04 对标 sqlmap --alert] 命中联动宿主命令
//
// 安全边界（底账 NOTES 原文要求「显式授权与命令白名单，不能静默执行」）：
//   · 命令只认 **CLI 命令行字面量**：不进 --config 档案（configFile 的 KNOWN_ARG_KEYS
//     刻意不登记 alert）、不进 REST 白名单 —— 本机宿主动作不能由一份外来配置/远端请求触发。
//   · 命令**不插值任何目标可控数据**（URL / 响应 / 漏洞详情），只通过环境变量传命中条数
//     与风险等级两个内部枚举值 ⇒ 目标无法通过响应内容把字符拼进命令行。
//   · 仅在报告确有命中时执行；执行失败只告警，不改扫描退出码、不阻塞交付。
//   · 单次命令长度上限 512，禁止换行/NUL；启动期 validateAlertCommand 硬拒。
// ============================================================================
import { spawn } from 'node:child_process';
import { logger } from '../../src/core/logger.js';

export const MAX_ALERT_CMD = 512;

/**
 * 启动期校验：`--alert` 缺值/非法形态直接拒启（「收参数不生效」是红线）。
 * @param {unknown} v args.alert
 * @returns {string|null} 合法命令，或 null（未配置）
 */
export function validateAlertCommand(v) {
  if (v === undefined || v === null) return null;
  if (v === true || typeof v !== 'string' || !v.trim()) {
    throw new Error('--alert 需要值：命中时执行的宿主命令（仅命令行字面量；--config/REST 不可达）');
  }
  if (v.length > MAX_ALERT_CMD) throw new Error(`--alert 命令过长（>${MAX_ALERT_CMD} 字符）`);
  if (/[\r\n\0]/.test(v)) throw new Error('--alert 命令不得含换行或空字节');
  return v;
}

/**
 * 命中即执行宿主命令（fire-and-forget，不等子进程结束）。
 * @param {object} report 扫描报告（读 vulns.length / riskLevel）
 * @param {object} args CLI 参数（读 alert）
 * @param {{spawn?: Function, env?: NodeJS.ProcessEnv}} [deps] 测试注入
 * @returns {{fired: boolean, reason?: string, findings?: number}}
 */
export function runAlert(report, args, deps = {}) {
  let cmd;
  try {
    cmd = validateAlertCommand(args && args.alert);
  } catch (e) {
    logger.warn(`[D199] --alert 未执行：${e.message}`);
    return { fired: false, reason: 'invalid-command' };
  }
  if (!cmd) return { fired: false, reason: 'no-alert' };
  const findings = Array.isArray(report && report.vulns) ? report.vulns.length : 0;
  if (!findings) return { fired: false, reason: 'no-findings' };
  const spawnFn = deps.spawn || spawn;
  const env = {
    ...(deps.env || process.env),
    SQLI_ALERT_FINDINGS: String(findings),
    SQLI_ALERT_RISK: String((report && report.riskLevel) || ''),
  };
  try {
    const child = spawnFn(cmd, { shell: true, stdio: 'ignore', windowsHide: true, env });
    if (child && typeof child.unref === 'function') child.unref();
    logger.info(`[D199] --alert 已触发（命中 ${findings} 条）`);
    return { fired: true, findings };
  } catch (e) {
    logger.warn(`[D199] --alert 执行失败：${e.message}`);
    return { fired: false, reason: 'spawn-failed' };
  }
}
