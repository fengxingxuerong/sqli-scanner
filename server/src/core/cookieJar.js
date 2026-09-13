// 轻量 Cookie Jar —— [P1-FIX 2026-09-05] 对标 sqlmap 自动会话保持（RFC 6265 简化实现）
//
// 背景：原实现仅静态透传用户 --cookie，服务端 Set-Cookie 一律丢弃 → 登录态目标
// 扫描中途 session 失效、登录后扫描 403。sqlmap 默认解析并回发 Set-Cookie。
//
// 设计：
//   - 存储键 domain|path|name；Domain 属性支持后缀匹配（host-only 缺省不共享子域）
//   - Path 前缀匹配；Expires/Max-Age 惰性过期；Secure 仅 https 回发
//   - 回发顺序按 path 长度降序（RFC 6265 §5.4）
//   - 每扫描一个 jar 实例（httpClient.forScan 持有），扫描退役随 _scanClients 一并清理
//
// 已知简化（V1，对标 sqlmap --drop-set-cookie 语义）：
//   - 不处理 cookie 名冲突的 Domian 精确优先级细节、不处理 public suffix
export class CookieJar {
  constructor() {
    this._cookies = new Map(); // key `${domain}|${path}|${name}` -> { name, value, domain, path, expiresAt, secure, hostOnly }
  }

  /** 从响应的 set-cookie 头数组解析并入库；返回入库条数 */
  setFromResponse(url, setCookieHeaders) {
    if (!Array.isArray(setCookieHeaders) || setCookieHeaders.length === 0) return 0;
    let host;
    let path;
    let isHttps;
    try {
      const u = new URL(url);
      host = u.hostname.toLowerCase();
      path = u.pathname || '/';
      isHttps = u.protocol === 'https:';
    } catch {
      return 0;
    }
    let count = 0;
    for (const raw of setCookieHeaders) {
      const c = this._parseSetCookie(String(raw), host, path, isHttps);
      if (!c) continue;
      this._cookies.set(`${c.domain}|${c.path}|${c.name}`, c);
      count++;
    }
    this._evictExpired();
    return count;
  }

  /** 生成该 URL 应携带的 Cookie 头值（无匹配返回 null） */
  headerFor(url) {
    let host;
    let path;
    let isHttps;
    try {
      const u = new URL(url);
      host = u.hostname.toLowerCase();
      path = u.pathname || '/';
      isHttps = u.protocol === 'https:';
    } catch {
      return null;
    }
    this._evictExpired();
    const matches = [];
    for (const c of this._cookies.values()) {
      if (c.secure && !isHttps) continue;
      if (c.hostOnly ? host !== c.domain : !this._domainMatch(host, c.domain)) continue;
      if (!this._pathMatch(path, c.path)) continue;
      matches.push(c);
    }
    if (matches.length === 0) return null;
    // path 长度降序；同长按名字典序（保证输出稳定可测）
    matches.sort((a, b) => (b.path.length - a.path.length) || (a.name < b.name ? -1 : 1));
    return matches.map((c) => `${c.name}=${c.value}`).join('; ');
  }

  /** 将 jar 中 cookie 合并进请求头：用户显式 Cookie 优先（同名不覆盖），jar 补充其余 */
  mergeInto(headers, url) {
    const jarValue = this.headerFor(url);
    if (!jarValue) return headers;
    const existing = headers['Cookie'] ?? headers['cookie'];
    if (!existing) {
      headers['Cookie'] = jarValue;
      return headers;
    }
    // 解析用户显式 cookie 名集合，仅追加 jar 中不重名的项
    const existingNames = new Set(
      String(existing).split(';').map((s) => s.split('=')[0].trim()).filter(Boolean)
    );
    const additions = jarValue.split('; ').filter((kv) => !existingNames.has(kv.split('=')[0].trim()));
    if (additions.length > 0) {
      headers['Cookie'] = `${existing}; ${additions.join('; ')}`;
    }
    return headers;
  }

  clear() {
    this._cookies.clear();
  }

  get size() {
    this._evictExpired();
    return this._cookies.size;
  }

  // —— 内部 ——

  _parseSetCookie(raw, defaultHost, defaultPath, isHttps) {
    const parts = raw.split(';');
    const [nv, ...attrs] = parts.map((s) => s.trim());
    const eq = nv.indexOf('=');
    if (eq <= 0) return null; // 无名或空名（含 RFC 6265 空值 "name=" 允许：eq=0 排除空名）
    const name = nv.slice(0, eq).trim();
    const value = nv.slice(eq + 1).trim();
    if (!name) return null;
    /** @type {{ name: string, value: string, domain: string, path: string, expiresAt: number|null, secure: boolean, hostOnly: boolean }} */
    const c = { name, value, domain: defaultHost, path: this._defaultPath(defaultPath), expiresAt: null, secure: false, hostOnly: true };
    for (const attr of attrs) {
      const [kRaw, vRaw] = attr.split('=');
      const k = kRaw.trim().toLowerCase();
      const v = (vRaw || '').trim();
      if (k === 'domain') {
        const d = v.replace(/^\./, '').toLowerCase();
        if (d && this._domainMatch(defaultHost, d)) {
          c.domain = d;
          c.hostOnly = false;
        }
      } else if (k === 'path') {
        if (v.startsWith('/')) c.path = v;
      } else if (k === 'max-age') {
        const sec = Number(v);
        if (Number.isFinite(sec)) c.expiresAt = sec <= 0 ? 0 : Date.now() + sec * 1000;
      } else if (k === 'expires') {
        const t = Date.parse(v);
        if (!Number.isNaN(t)) c.expiresAt = t;
      } else if (k === 'secure') {
        c.secure = true;
      }
    }
    if (c.secure && !isHttps) {
      // 非 https 响应下发的 Secure cookie 仍入库（服务器行为），但仅 https 回发——headerFor 已过滤
    }
    return c;
  }

  // RFC 6265 §5.1.4 默认 path：取请求 path 最后一个 '/' 之前（含根）
  _defaultPath(reqPath) {
    if (!reqPath || !reqPath.startsWith('/')) return '/';
    const idx = reqPath.lastIndexOf('/');
    return idx <= 0 ? '/' : reqPath.slice(0, idx);
  }

  _domainMatch(host, domain) {
    return host === domain || host.endsWith(`.${domain}`);
  }

  _pathMatch(reqPath, cookiePath) {
    if (reqPath === cookiePath) return true;
    if (reqPath.startsWith(cookiePath)) {
      return cookiePath.endsWith('/') || reqPath[cookiePath.length] === '/';
    }
    return false;
  }

  _evictExpired() {
    const now = Date.now();
    for (const [k, c] of this._cookies) {
      if (c.expiresAt !== null && c.expiresAt <= now) this._cookies.delete(k);
    }
  }
}

export default CookieJar;
