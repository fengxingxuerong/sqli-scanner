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
import { parseScope, assertInScope } from '../core/scopeGuard.js';

/** 不出网的内嵌驱动：没有"主机"可言，不得被 scope 误杀。 */
const EMBEDDED_DRIVERS = /^(sqljs|sqlite|sqlite3|memory|pglite)$/i;

/**
 * 从 db 配置 / connectionString 里取数据库主机。
 * 返回 '' 表示拿不到（内嵌驱动或连接串里没有主机名）。
 */
export function directDbHost(db = {}, connectionString = '') {
  if (db.host) return String(db.host);
  const conn = String(db.connectionString || connectionString || '');
  return (conn.match(/^[a-z0-9+.-]+:\/\/(?:[^/?#@]*@)?([^/?#:]+)/i) || [])[1] || '';
}

/**
 * 校验并规范化直连入参。返回的字段形状与 sanitizeStart 的 HTTP 分支**不同**
 * （没有 url，多 mode/db/sqlTemplate），所以调用方要按 mode 分支处理。
 *
 * @param {object} b      请求体
 * @param {object} cfg    b.config
 * @param {object} defaults 引擎默认 config（由调用方注入，避免这里依赖 defaults 模块）
 */
export function buildDirectTarget(b, cfg, defaults) {
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
  const scope = parseScope(cfg.scope);
  if (scope.enabled) {
    const host = directDbHost(db, b.connectionString);
    if (!host && !EMBEDDED_DRIVERS.test(String(db.driverType || ''))) {
      // fail closed：配了 scope 就是期待"未知目标不放行"，而不是"换个入口就不管"
      throw new AppError(ErrorCode.SCOPE_VIOLATION,
        '直连模式无法确定数据库主机，不能确认授权范围，已拒绝（scope 已配置时不放行未知目标）');
    }
    if (host) {
      // assertInScope 只取 hostname；scheme 是占位（数据库地址没有 HTTP scheme）
      assertInScope(`db://${host}`, scope);
    }
  }
  return {
    mode: 'direct',
    db,
    sqlTemplate: b.sqlTemplate,
    originalValue: b.originalValue != null ? String(b.originalValue) : '1',
    // ⚠ 这里 config 是 `{...defaults, ...cfg}` **未经 clamp**（HTTP 分支那套守卫在
    //   sanitizeStart 的后半段）。这是已知的下一项工作：把 config 守卫抽成两条分支共用，
    //   而不是在这里手挑几个键 clamp。实测越界值（concurrency:9999 / timeoutMs:99999999 /
    //   ratePerSec:"20" / 带分号的 dumpWhere）会原样进引擎 —— 见 CHANGELOG 与本文件头。
    config: { ...defaults, ...(cfg || {}) },
  };
}
