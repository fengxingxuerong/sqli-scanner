// ============================================================================
// core/scopeGuard.js —— 授权范围（engagement scope）硬约束
//
// 为什么需要（渗透实战视角）：
//   授权书写的范围通常是「*.corp.example.com 的 3 个业务系统」，而扫描器只要拿到 URL 就会打。
//   真实项目里最容易出的重大事故不是漏检，而是**手滑把同 C 段的另一个系统 / 客户的预发环境 /
//   第三方 SaaS（支付、客服、短信网关）当成授权目标打了进去**——那是违法行为，且会直接触发
//   对方 SOC 告警。任何「目标校验」都替代不了范围校验：SSRF 防护管的是「别打自己人」，
//   scope 管的是「别打没授权的人」。
//
//   另一个必须覆盖的口子是**重定向**：目标 302 到未授权主机（很常见：统一登录、CDN 回源、
//   灰度切换）时，扫描器会跟着跳并把后续全部注入请求打到新主机上——人根本不会察觉。
//   因此 scope 校验必须与 SSRF 校验一样在每一跳执行（见 httpClient 侧 getScopeForScan）。
//
//   第三个口子是**直连模式（对标 sqlmap -d）**：它不发 HTTP 包，但会**连一个数据库主机**——
//   那同样是"打谁"的决定。2026-09-25 起 scope 对直连的 DB 主机生效（`api/scanRoutes.js`
//   直连分支）。过去那边只写着"直连不发起 HTTP 请求，跳过 SSRF 校验（无 SSRF 面）"，
//   一句话把两条约束一起免掉了；而直连能力本身是 scope 落地之后才加的，所以那不是既定取舍，
//   是清单没跟着更新。SSRF 对直连确实不适用（DB 连接是操作者明示意图），scope 适用。
//
// 设计约束：
//   - 纯函数、无 IO、无副作用：可被 sanitizeStart（同步）与逐跳校验（异步）共用。
//   - 未配置 scope 时**不启用**（零行为变化，保持既有部署语义）；配置了就是硬约束，
//     不提供「警告模式」（警告模式等于没有）。
//   - 匹配只认 host（含端口可选）与路径前缀，不做大小写敏感的 DNS 变形；IP 目标支持 CIDR。
// ============================================================================

import { AppError, ErrorCode } from './errors.js';
// [2026-09-29] IP 解析与前缀比较的唯一真源（core/http/ipBytes.js）。
// 本文件原先自带 ipv6ToBytes / bitsMatch，与 egressGuard 各一份 ⇒ 两份必然分叉：
// 实测 egressGuard 那份的 `::` 展开对 `::ffff:127.0.0.1` 会把点分四段**静默丢弃**
// （解析出 ::ffff:0:0），而 scopeGuard 这份的 `filter(Boolean)` 对 `fe80::` 会误判。
// duplicateSymbol.guard.test.js 已钉住「不得再开第二份」。
import { ipv4ToBytes as bytesIpv4, ipv6ToBytes as bytesIpv6, bytesInPrefix } from './http/ipBytes.js';

/**
 * parseScope 的规则集（一条 scope 配置解析后的完整形态）。
 * 显式 typedef 而不是靠推断：portRules / paths[].port 是新加的字段，
 * 消费方（isHostInScope / assertInScope / HttpClient 的逐跳校验）都按这份形状取用，
 * 没有具名类型时 TS 会在 JSDoc 里退回旧形状，字段一多就说不清谁负责哪一段。
 * @typedef {Object} ScopeRules
 * @property {boolean} enabled 是否启用了范围约束（空列表 = 不启用，行为与历史一致）
 * @property {Set<string>} hosts 精确主机名/IP
 * @property {string[]} domains 域（含子域）
 * @property {Array<{net:number[],bits:number,v6:boolean}>} cidrs IP 段
 * @property {Array<{host:string, prefix:string, port:(number|null)}>} paths 主机+路径前缀（可带端口）
 * @property {Array<{host:string, port:number, secureDefault:boolean}>} portRules 主机+端口（不含路径）
 * @property {string[]} raw 原始条目（报错回显用）
 */

/**
 * 把用户输入（数组 / 逗号分隔串 / 单条）规整成规则集。
 * 支持形态：
 *   example.com            精确主机名（含其裸域）
 *   *.example.com          该域及其所有子域（等价 .example.com）
 *   .example.com           同上
 *   10.0.0.0/8             IPv4 CIDR
 *   192.168.1.50           精确 IP
 *   2001:db8::/32          IPv6 前缀（按前缀比特比较）
 *   https://a.example.com/ 主机 + 路径前缀（仅该路径下）
 *   127.0.0.1:8140         主机 + 端口（端口必须相等；开发者描述本地靶站的自然写法）
 * @param {string|string[]|null|undefined} entries
 * @returns {ScopeRules}
 */
export function parseScope(entries) {
  const list = (Array.isArray(entries) ? entries : String(entries ?? '').split(','))
    .map((s) => String(s ?? '').trim())
    .filter(Boolean);
  /** @type {ScopeRules} */
  const scope = { enabled: list.length > 0, hosts: new Set(), domains: [], cidrs: [], paths: [], portRules: [], raw: list };
  for (const item0 of list) {
    // CIDR 先判（否则 `10.0.0.0/8` 会被下面的“host/path”切分误当成路径前缀）
    const cidrItem = /^\[?([0-9a-fA-F:.]+)\]?\/(\d{1,3})$/.exec(item0);
    if (cidrItem && (cidrItem[1].includes('.') || cidrItem[1].includes(':'))) {
      const cidr = parseCidr(`${cidrItem[1]}/${cidrItem[2]}`);
      if (cidr) {
        scope.cidrs.push(cidr);
        continue;
      }
    }
    const item = item0;
    let host = item;
    let path = '';
    // 规则里的端口（`127.0.0.1:8140` / `http://h:8443/` / `[::1]:8080`）。
    // 为什么必须支持：授权时开发者就是这么描述自己的目标的（localhost:3000、内网靶站带端口），
    // 而旧实现把整串当主机名收进 scope.hosts ⇒ 永远匹配不上，报错 yet 回显同一串，
    // 看上去像判据坏了（2026-09-28 接口靶场实测）。带端口的规则按"主机名相等 + 端口相等"匹配，
    // 只会比无端口规则**更严**，不会放宽授权面。
    let rulePort = null;
    let ruleSecureDefault = false;
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(item)) {
      // 带 scheme 的整段 URL：取 host + pathname 前缀
      try {
        const u = new URL(item);
        host = u.hostname;
        path = u.pathname || '';
        if (u.port) rulePort = Number(u.port);
        ruleSecureDefault = u.protocol === 'https:';
      } catch {
        continue; // 非法 URL 条目直接忽略（宁可少放行也不误放行）
      }
    } else if (item.includes('/')) {
      const i = item.indexOf('/');
      host = item.slice(0, i);
      path = item.slice(i);
      const m = /^([^:\[\]]+):(\d{1,5})$/.exec(host);
      if (m) {
        host = m[1];
        rulePort = Number(m[2]);
      }
    } else {
      const m = /^([^:\[\]]+):(\d{1,5})$/.exec(host) || /^\[([^\]]+)\]:(\d{1,5})$/.exec(host);
      if (m) {
        host = m[1];
        rulePort = Number(m[2]);
      }
    }
    host = host.replace(/^\[|\]$/g, '').toLowerCase();
    if (!host) continue;
    // 严格裸域写法：`=example.com`（只匹配该主机名，不含子域）
    const exact = host.startsWith('=');
    if (exact) host = host.slice(1);
    if (host.startsWith('*.')) host = host.slice(2);
    if (host.startsWith('.')) host = host.slice(1);
    if (path && path !== '/') {
      scope.paths.push({ host, prefix: path.replace(/\/$/, ''), port: rulePort });
      continue;
    }
    if (rulePort) {
      scope.portRules.push({ host, port: rulePort, secureDefault: ruleSecureDefault });
      continue;
    }
    const cidr = parseCidr(host);
    if (cidr) {
      scope.cidrs.push(cidr);
      continue;
    }
    if (isIpLiteral(host)) {
      scope.hosts.add(host);
      continue;
    }
    // 域名条目：默认按「域 + 子域」匹配（授权书写习惯里 example.com 通常涵盖子域）。
    if (exact) {
      scope.hosts.add(host.toLowerCase());
    } else {
      scope.domains.push(host.toLowerCase());
    }
  }
  return scope;
}

function isIpLiteral(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

function parseCidr(host) {
  const m = /^(.+)\/(\d{1,3})$/.exec(host);
  if (!m) return null;
  const base = m[1];
  const bits = Number(m[2]);
  const v6 = base.includes(':');
  const net = v6 ? bytesIpv6(base) : ipv4ToBytes(base);
  if (!net) return null;
  const max = v6 ? 128 : 32;
  if (!Number.isFinite(bits) || bits < 0 || bits > max) return null;
  return { net, bits, v6 };
}

function ipv4ToBytes(ip) {
  return bytesIpv4(ip);
}

/**
 * 主机名/IP 是否落在 scope 内。scope 未启用时恒为 true。
 * @param {string} host 主机名或 IP（不含端口）
 * @param {ReturnType<typeof parseScope>} scope
 * @param {string} [pathname] 请求路径（用于带路径前缀的规则）
 * @param {number|string} [port] 目标端口；只有带端口的规则（host:port / scheme://host:port）会用到它
 */
export function isHostInScope(host, scope, pathname = '', port = undefined) {
  if (!scope || scope.enabled !== true) return true;
  const h = String(host ?? '').replace(/^\[|\]$/g, '').toLowerCase();
  if (!h) return false;
  if (scope.hosts.has(h)) return true;
  for (const d of scope.domains) {
    if (h === d || h.endsWith(`.${d}`)) return true;
  }
  for (const p of scope.paths) {
    if ((h === p.host || h.endsWith(`.${p.host}`)) && String(pathname || '/').startsWith(p.prefix)) {
      // 路径规则也可能带端口（http://h:8443/portal）：带端口时必须端口相等才算命中
      if (!p.port) return true;
      if (Number(port) === p.port) return true;
    }
  }
  // 带端口的规则：主机名匹配 **且**端口相等才算在范围内（比无端口规则更严，不会放宽授权）。
  // 调用方没给端口时按"不匹配"处理（fail-closed）—— 带端口的规则本来就是要把范围收到一个端口上。
  for (const r of scope.portRules || []) {
    if (h !== r.host && !h.endsWith(`.${r.host}`)) continue;
    if (Number(port) === r.port) return true;
  }
  if (scope.cidrs.length && isIpLiteral(h)) {
    const v6 = h.includes(':');
    const target = v6 ? bytesIpv6(h) : ipv4ToBytes(h);
    if (target) {
      for (const c of scope.cidrs) {
        if (c.v6 !== v6) continue;
        if (bytesInPrefix(target, c.net, c.bits)) return true;
      }
    }
  }
  return false;
}

/**
 * 校验一个 URL 是否在授权范围内；越界抛 AppError（SCOPE_VIOLATION）。
 * @param {string} urlString
 * @param {ReturnType<typeof parseScope>} scope
 */
export function assertInScope(urlString, scope) {
  if (!scope || scope.enabled !== true) return;
  let u;
  try {
    u = new URL(urlString);
  } catch {
    throw new AppError(ErrorCode.SCOPE_VIOLATION, `目标 URL 无法解析，无法确认授权范围，已拒绝：${urlString}`);
  }
  const port = u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80;
  if (!isHostInScope(u.hostname, scope, u.pathname, port)) {
    // 报错必须能指下一步。旧写法只回显 raw 列表，遇到 `127.0.0.1:8140` 这类**带端口**的规则
    // 时会打印出一句自相矛盾的话（"目标 127.0.0.1:59320 不在范围，当前范围：127.0.0.1:59320"），
    // 使用者只会怀疑判据坏了。主机相同、端口不同时，直接把"差在端口"说出来。
    const sameHostRule = (scope.portRules || []).find((r) => u.hostname.toLowerCase() === r.host || u.hostname.toLowerCase().endsWith(`.${r.host}`));
    const why = sameHostRule
      ? `（主机 ${sameHostRule.host} 已授权，但仅限端口 ${sameHostRule.port}，本次目标端口 ${port}）`
      : '';
    throw new AppError(
      ErrorCode.SCOPE_VIOLATION,
      `目标 ${u.host} 不在授权范围（scope）内，已拒绝扫描。当前范围：${scope.raw.join(', ')}${why}`
    );
  }
}

/**
 * 过滤出 scope 内的 URL（用于二阶触发页这类「剔除非法项而非整体拒绝」的场景）。
 * @returns {{allowed: string[], rejected: string[]}}
 */
export function filterInScope(urls, scope) {
  const allowed = [];
  const rejected = [];
  for (const u of urls || []) {
    try {
      assertInScope(u, scope);
      allowed.push(u);
    } catch {
      rejected.push(u);
    }
  }
  return { allowed, rejected };
}

// ── 扫描级 scope 注册表 ──────────────────────────────────────────────────────
// 为什么用模块级 Map 而不是逐层透传 opts：scope 必须在「每一跳重定向」都生效，而重定向跟随
// 发生在 HttpClient 内部；把 scope 塞进每个调用方（9 个检测器 + Extractor + Exploiter + 爬虫）
// 既易漏又难维护。HttpClient 已按 scanId 走桶，这里复用同一个键做登记/回收即可。
// TTL 与 ScanManager 的扫描生命周期解耦：2 小时后自动清理，避免异常退出残留。
const SCAN_SCOPE_TTL_MS = 2 * 60 * 60 * 1000;
const scanScopes = new Map(); // scanId -> { scope, ts }

export function registerScanScope(scanId, scope) {
  if (!scanId) return;
  if (!scope || scope.enabled !== true) {
    scanScopes.delete(scanId);
    return;
  }
  scanScopes.set(scanId, { scope, ts: Date.now() });
  if (scanScopes.size > 512) {
    for (const [k, v] of scanScopes) {
      if (Date.now() - v.ts > SCAN_SCOPE_TTL_MS) scanScopes.delete(k);
      if (scanScopes.size <= 256) break;
    }
  }
}

export function releaseScanScope(scanId) {
  if (scanId) scanScopes.delete(scanId);
}

/**
 * 取某次扫描登记的 scope（无登记返回 null，调用方按「不校验」处理）。
 * 过期条目顺手删除（惰性清理，无定时器）。
 */
export function getScopeForScan(scanId) {
  if (!scanId) return null;
  const hit = scanScopes.get(scanId);
  if (!hit) return null;
  if (Date.now() - hit.ts > SCAN_SCOPE_TTL_MS) {
    scanScopes.delete(scanId);
    return null;
  }
  return hit.scope;
}


// ── 直连（-d）目标的授权范围 ────────────────────────────────────────────────
// 为什么放在 scopeGuard 而不是 api 层：这条红线有**两条入口**要共享 ——
// `api/directTarget.js`（REST 的 mode:direct）与 `bin/cli.js`（`-d <dsn>`）。
// CLI 侧原先写着"直连不参与 scope 判定"，于是同一个 DSN 从 REST 进要过红线、从 CLI 进
// 完全不过 —— 判据若长在其中一条入口的文件里，另一条就必然漏。
/** 不出网的内嵌驱动：没有"主机"可言，不得被 scope 误杀。 */
const EMBEDDED_DB_DRIVERS = /^(sqljs|sqlite|sqlite3|memory|pglite)$/i;

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
 * 直连目标是否落在授权范围内。**HTTP 与 CLI 两条直连入口共用这一份判据**
 * （两条入口原先各写一套：REST 有、CLI 完全没有 —— 见下）。
 *
 * 为什么不能有第二套：`scope` 管的是"别打没授权的人"，与"这条连接走不走 HTTP"无关。
 * CLI（`bin/cli.js` 的 runSingleScan）曾经写着"直连模式不参与 scope 判定"，
 * 而同一段注释又称自己"与 scanRoutes sanitizeStart 同步拦截同构" —— 后者在
 * 2026-09-25 之后已经不成立（REST 直连那时开始按 DB 主机判 scope），
 * 于是同一个 `-d` 从 REST 进要过红线、从 CLI 进完全不过。
 *
 * @param {{db?:object, connectionString?:string, driverType?:string}} t 直连描述（三选一即可）
 * @param {object} scopeRules parseScope() 的结果；未启用时直接返回
 */
export function assertDirectDbInScope({ db = {}, connectionString = '', driverType = '' }, scopeRules) {
  if (!scopeRules?.enabled) return;
  const host = directDbHost(db, connectionString);
  // 内嵌/不出网的驱动没有"主机"可言，不该被 scope 误杀。判据取**连接串自己的 scheme** 优先，
  // 再退回调用方声明的 driverType —— 否则 CLI 那句 `driverType || 'memory'` 的默认值
  // 会把一个解析不出主机的远端 DSN 也当成内嵌，红线就白设了。
  const scheme = (/^([a-z0-9+.-]+):\/\//i.exec(String(connectionString || '')) || [])[1] || '';
  const effDriver = scheme || String(db.driverType || driverType || '');
  if (!host) {
    if (!EMBEDDED_DB_DRIVERS.test(effDriver)) {
      // fail closed：配了 scope 就是期待"未知目标不放行"，而不是"换个入口就不管"
      throw new AppError(
        ErrorCode.SCOPE_VIOLATION,
        `直连目标无法确定数据库主机（driver/DSN：${effDriver || '未声明'}），` +
          '不能确认授权范围，已拒绝（scope 已配置时不放行未知目标；如为内嵌库请显式声明 --driver）'
      );
    }
    return;
  }
  // assertInScope 只取 hostname；scheme 是占位（数据库地址没有 HTTP scheme）
  assertInScope(`db://${host}`, scopeRules);
}
export default {
  parseScope,
  isHostInScope,
  assertInScope,
  filterInScope,
  registerScanScope,
  releaseScanScope,
  getScopeForScan,
  directDbHost,
  assertDirectDbInScope,
};
