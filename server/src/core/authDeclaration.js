// ============================================================================
// core/authDeclaration.js —— 授权声明校验器（spec 5.2.1 规则 1/7）
//
// 解决什么：exploitFlag 此前仅检查 `authorized === true` 布尔自证 —— 无操作者标识、
// 目标范围、授权时间等可追溯字段。本模块要求结构化 AuthorizationDeclaration：
//   { operator: string, scope: { hosts?, domains? }, timestamp: number, validWindowMs?: number }
// 仅布尔 authorized=true 而无有效声明 → 拒绝（规则 7）。
//
// 异常映射（spec 5.2.1 规则 1）：
//   AUTH_DECLARATION_MISSING  —— 声明缺失
//   AUTH_DECLARATION_INVALID  —— 字段非法
//   AUTH_SCOPE_MISMATCH       —— scope 不覆盖目标
//   AUTH_DECLARATION_EXPIRED  —— 声明过期
// ============================================================================
import { URL } from 'node:url';

const DEFAULT_VALID_WINDOW_MS = 60 * 60 * 1000; // 1 小时

/**
 * 判定目标 host 是否在授权 scope 内。
 * @param {string|URL|object} target 目标（URL 串、URL 对象或 request target）
 * @param {string[]|string} scope 授权 scope（域名清单或逗号分隔串）
 * @returns {boolean} 在 scope 内（或 host 不可提取的宽放情形）为 true
 */
function isTargetInScope(target, scope) {
  let host;
  if (typeof target === 'string') {
    try { host = new URL(target).hostname; } catch { host = target; }
  } else if (target?.hostname) {
    host = target.hostname;
  } else if (target?.host) {
    host = String(target.host).split(':')[0];
  } else {
    return true; // 无法提取 host → 不因 scope 拒绝（scope 校验是增强，不是唯一闸门）
  }
  if (!host) return true;
  const hosts = Array.isArray(scope.hosts) ? scope.hosts : [];
  const domains = Array.isArray(scope.domains) ? scope.domains : [];
  if (hosts.includes(host)) return true;
  for (const d of domains) {
    if (host === d || host.endsWith('.' + d)) return true;
  }
  // scope 为空 = 不限制目标（仅校验操作者+时间窗）
  if (hosts.length === 0 && domains.length === 0) return true;
  return false;
}

/**
 * 校验授权声明完整性。
 * @param {object} decl AuthorizationDeclaration
 * @param {string|URL|object} [target] 目标（URL 字符串 / URL 对象 / {hostname}）
 * @returns {{valid:boolean, code?:string, message?:string, declaration?:object}}
 */
export function validateDeclaration(decl, target) {
  if (!decl || typeof decl !== 'object') {
    return { valid: false, code: 'AUTH_DECLARATION_MISSING', message: '缺少授权声明（仅布尔 authorized 不构成充分条件）' };
  }
  const { operator, scope, timestamp, validWindowMs = DEFAULT_VALID_WINDOW_MS } = decl;
  if (!operator || typeof operator !== 'string' || operator.trim() === '') {
    return { valid: false, code: 'AUTH_DECLARATION_INVALID', message: '授权声明缺少 operator（操作者标识）' };
  }
  if (scope !== undefined && scope !== null && (typeof scope !== 'object' || Array.isArray(scope))) {
    return { valid: false, code: 'AUTH_DECLARATION_INVALID', message: '授权声明 scope 必须是对象' };
  }
  if (!Number.isFinite(timestamp)) {
    return { valid: false, code: 'AUTH_DECLARATION_INVALID', message: '授权声明缺少有效 timestamp' };
  }
  if (!Number.isFinite(validWindowMs) || validWindowMs <= 0) {
    return { valid: false, code: 'AUTH_DECLARATION_INVALID', message: 'validWindowMs 必须是正数' };
  }
  // 时间窗校验
  const now = Date.now();
  if (now < timestamp - 5000 || now > timestamp + validWindowMs) {
    return { valid: false, code: 'AUTH_DECLARATION_EXPIRED', message: `授权声明已过期（timestamp=${new Date(timestamp).toISOString()}, window=${validWindowMs}ms）` };
  }
  // scope 覆盖校验
  if (target && scope && !isTargetInScope(target, scope)) {
    return { valid: false, code: 'AUTH_SCOPE_MISMATCH', message: '授权声明 scope 不覆盖目标' };
  }
  return { valid: true, declaration: { ...decl, validWindowMs } };
}

/** 从请求体提取授权声明（兼容 body.authDeclaration / body.declaration） */
export function extractDeclaration(body) {
  if (!body || typeof body !== 'object') return null;
  return body.authDeclaration || body.declaration || null;
}