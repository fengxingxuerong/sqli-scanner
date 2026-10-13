// ============================================================================
// services/authAudit.js —— 授权审计事件写入器（spec 5.2.1 规则 2）
//
// 解决什么：scanLedger 记录扫描产物，但不记录授权声明与拒绝事件。本模块 append-only
// 写入 ledger/auth.jsonl，记录授权声明、操作类型、目标、结果与拒绝原因。
//
// 审计 sink 不可写时按策略拒绝执行（不静默放行，spec 异常场景 4）：
//   AUDIT_SINK_FAIL_MODE=strict  → 不可写时拒绝执行（默认）
//   AUDIT_SINK_FAIL_MODE=lenient → 不可写时告警但放行（仅用于本地开发）
// ============================================================================
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { logger } from '../core/logger.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LEDGER_DIR = path.resolve(HERE, '../../data/ledger');
const AUTH_AUDIT_PATH = path.join(LEDGER_DIR, 'auth.jsonl');

function failMode() {
  return process.env.AUDIT_SINK_FAIL_MODE === 'lenient' ? 'lenient' : 'strict';
}

/**
 * 记录一条授权审计事件。
 * @param {{declaration?:object, operation:string, target?:string, result:'allowed'|'denied', reason?:string, operator?:string}} event
 * @returns {{ok:boolean, error?:string}} ok=false 表示写入失败；strict 模式下调用方应拒绝执行
 */
export function recordAuthEvent(event) {
  const entry = {
    eventId: randomUUID(),
    operator: event.operator || event.declaration?.operator || 'unknown',
    operation: event.operation,
    target: event.target || null,
    result: event.result, // allowed / denied
    reason: event.reason || null,
    declaration: event.declaration ? {
      operator: event.declaration.operator,
      scope: event.declaration.scope,
      timestamp: event.declaration.timestamp,
    } : null,
    recordedAt: new Date().toISOString(),
  };
  try {
    fs.mkdirSync(LEDGER_DIR, { recursive: true });
    fs.appendFileSync(AUTH_AUDIT_PATH, JSON.stringify(entry) + '\n', 'utf8');
    return { ok: true };
  } catch (err) {
    logger.warn(`authAudit 写入失败: ${err.message}`);
    if (failMode() === 'strict') {
      return { ok: false, error: `审计 sink 不可写: ${err.message}` };
    }
    // lenient: 告警但放行 —— 审计行的丢失只体现在上面的 logger.warn 里。
    // ⚠ 曾在此返回 `{ ok: true, warned: true }`，但全仓没有任何调用方或测试读 warned
    //   （调用方只看 ok），留着就等于「用字段声明一个没人执行的关注点」。要真做
    //   「审计不完整要在响应里可见」，得同时改 exploitRoutes 的出口与判据，别只加字段。
    return { ok: true };
  }
}

/** 读取审计日志（供测试/审计查看） */
export function readAuthEvents(maxLines = 1000) {
  try {
    const content = fs.readFileSync(AUTH_AUDIT_PATH, 'utf8');
    return content.trim().split('\n').slice(-maxLines).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

/** 清空审计日志（仅测试用） */
export function _clearForTest() {
  try { fs.writeFileSync(AUTH_AUDIT_PATH, '', 'utf8'); } catch { /* noop */ }
}

export { AUTH_AUDIT_PATH };