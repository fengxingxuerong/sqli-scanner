// ============================================================================
// api/directTarget.js —— 直连模式（对标 sqlmap -d）的入参照面
//
// 从 scanRoutes.js 抽出来的原因有两个，第二个是主要的：
//   ① 它是"第二条入口"（HTTP 目标之外的直连目标），把它的校验放在同一处，才谈得上
//      与 HTTP 分支各自演进时不互相漏掉；
//   ② `scanRoutes.js` 已经顶到 arch-guard 的单文件行数上限（1200），而这块逻辑本身
//      是纯函数（无 IO、无 Express），没有理由留在路由文件里。
//
// 为什么直连必须单独判 scope（2026-09-25 实测出来的洞）：
//   路由里那句"直连不发起 HTTP 请求，跳过 SSRF 校验（无 SSRF 面）"**只对 SSRF 成立**，
//   但它当时把 scope 也一起免了 ⇒ 配了授权范围照样能连任意数据库主机。本仓自己把两条
//   分得很清（scopeGuard.js：SSRF 管"别打自己人"，scope 管"别打没授权的人"）。
//   这里只补 scope，SSRF 那半保留原判：直连是操作者明示意图，不构成服务端被诱导的内网访问。
// ============================================================================
import { AppError, ErrorCode } from '../core/errors.js';
// assertDirectDbInScope 的本体在 core/scopeGuard.js：REST 的 mode:direct 与 CLI 的 -d 共用一份判据
import { parseScope, assertDirectDbInScope } from '../core/scopeGuard.js';
// 与 HTTP 分支共用同一个配置守卫（clamp / 形状校验 / 白名单键落地）。
// 这里曾经是 `{...defaults, ...cfg}` 直接透传 —— 那等于"第二条入口没设防"：
// concurrency:9999 / timeoutMs:99999999 / 带分号的 dumpWhere 会原样进引擎。
import { buildGuardedConfig } from './scanConfigGuard.js';


/**
 * 校验并规范化直连入参。返回的字段形状与 sanitizeStart 的 HTTP 分支**不同**
 * （没有 url，多 mode/db/sqlTemplate），所以调用方要按 mode 分支处理。
 *
 * @param {object} b   请求体
 * @param {object} cfg b.config
 */
export function buildDirectTarget(b, cfg) {
  if (!b.db && !b.connectionString) {
    throw new AppError(ErrorCode.INVALID_TARGET, '直连模式需要提供 db 连接信息或 connectionString');
  }
  if (!b.sqlTemplate || !String(b.sqlTemplate).includes('{INJECT}')) {
    throw new AppError(ErrorCode.INVALID_TARGET, '直连模式需要提供含 {INJECT} 注入标记的 sqlTemplate');
  }
  const db = b.db || {
    connectionString: String(b.connectionString),
    driverType: String(b.driverType || 'memory'),
  };
  const scopeRules = parseScope(cfg.scope);
  // 判据本体在 core/scopeGuard.js（REST 的 mode:direct 与 CLI 的 -d 共用一份），此处只接线
  assertDirectDbInScope({ db, connectionString: b.connectionString }, scopeRules);
  return {
    mode: 'direct',
    db,
    sqlTemplate: b.sqlTemplate,
    originalValue: b.originalValue != null ? String(b.originalValue) : '1',
    // 与 HTTP 分支**同一个**守卫：scope 原文也照旧进 config（下游按同一口径取）。
    // 注意 config 不再是"defaults 的浅拷贝 + 任意键"，而是白名单键 + clamp 后的值 ——
    // 引擎侧本就按 defaults 取值（ScanManager 合并 defaults），所以少掉的键只是
    // "不再由入口层重复写一遍默认值"。
    config: buildGuardedConfig(cfg, scopeRules),
  };
}
