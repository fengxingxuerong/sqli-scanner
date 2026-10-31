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
 *
 * [D224 2026-10-31] 返回值**额外带 `eventId`**：`auth.jsonl` 是全进程共享文件，
 * 并发测试（`node --test` 多文件并行）不能靠「最后一行」认领自己写的事件。
 * 调用点若需要确认「我这条落盘了」，就拿这个 id 去 `findAuthEvents({ eventId })`。
 * 对既有调用方向后兼容：`ok` / `error` 两个字段的语义与取值不变。
 *
 * @param {{declaration?:object, operation:string, target?:string, result:'allowed'|'denied', reason?:string, operator?:string}} event
 * @returns {{ok:boolean, error?:string, eventId:string}} ok=false 表示写入失败；strict 模式下调用方应拒绝执行
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
    return { ok: true, eventId: entry.eventId };
  } catch (err) {
    logger.warn(`authAudit 写入失败: ${err.message}`);
    if (failMode() === 'strict') {
      return { ok: false, error: `审计 sink 不可写: ${err.message}`, eventId: entry.eventId };
    }
    // lenient: 告警但放行 —— 审计行的丢失只体现在上面的 logger.warn 里。
    // ⚠ 曾在此返回 `{ ok: true, warned: true }`，但全仓没有任何调用方或测试读 warned
    //   （调用方只看 ok），留着就等于「用字段声明一个没人执行的关注点」。要真做
    //   「审计不完整要在响应里可见」，得同时改 exploitRoutes 的出口与判据，别只加字段。
    return { ok: true, eventId: entry.eventId };
  }
}

/**
 * 读取审计日志（供测试/审计查看）。
 *
 * [D224 2026-10-31] 并发安全：`auth.jsonl` 是**全进程共享的单一文件**（不按 scanId 分文件），
 * 而 `node --test` 默认多文件并发。于是「读最后一行 = 我刚写的那个事件」这个假设在并发下
 * **不成立** —— 别的测试文件可能刚追加了 `result:'allowed'`，本文件断言 `denied` 就红。
 * 实测（HEAD 上 10 轮 × 21 文件）：失败 1 轮，报 `actual: 'allowed' expected: 'denied'`，
 * 与任何代码改动无关，纯粹是断言依赖了共享文件的时序。
 *
 * 因此调用方**不得**用「最后一行」定位自己的事件。正确姿势：
 *   ① 写之前记下返回的 eventId（`recordAuthEvent` 的返回值已带，见其调用点）；
 *   ② 用 `findAuthEvents({ eventId })` 精确取回。
 * 本函数保留原语义（返回最近 maxLines 条）以兼容审计查看场景，但**测试请用 findAuthEvents**。
 *
 * @param {number} [maxLines] 最多返回多少条（默认 1000，取最近的）
 * @returns {Array<object>} 审计事件（解析失败的坏行被丢弃）
 */
export function readAuthEvents(maxLines = 1000) {
  try {
    const content = fs.readFileSync(AUTH_AUDIT_PATH, 'utf8');
    return content.trim().split('\n').slice(-maxLines)
      .flatMap((l) => { try { return [JSON.parse(l)]; } catch { return []; } });
  } catch {
    return [];
  }
}

/**
 * 按条件精确查审计事件（并发安全的读法）。
 *
 * 为什么单独一个函数而不给 readAuthEvents 加过滤参数：`readAuthEvents` 的语义是
 * 「看最近的审计流」，而这里要的是「确认我这条事件落盘了」——两者用途不同，
 * 混成一个带可选参数的函数会让调用点看不出自己在用哪种语义。
 *
 * @param {{eventId?:string, operation?:string, result?:'allowed'|'denied', target?:string}} [where]
 *        全部字段为 AND 关系；不传 = 返回全部
 * @returns {Array<object>} 命中的事件（按落盘顺序）
 */
export function findAuthEvents(where = {}) {
  const all = readAuthEvents(Number.MAX_SAFE_INTEGER);
  const keys = Object.keys(where).filter((k) => where[k] !== undefined);
  if (!keys.length) return all;
  return all.filter((e) => keys.every((k) => e && e[k] === where[k]));
}

/** 清空审计日志（仅测试用） */
export function _clearForTest() {
  try { fs.writeFileSync(AUTH_AUDIT_PATH, '', 'utf8'); } catch { /* noop */ }
}

export { AUTH_AUDIT_PATH };