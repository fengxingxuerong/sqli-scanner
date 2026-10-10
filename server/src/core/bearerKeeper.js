// ============================================================================
// bearerKeeper.js —— Bearer/Token 会话续期编排（实战 P0-2，批次 D36）
//
// 解决什么问题：`loginFlow` 明确只覆盖「标准 HTML 表单登录」，而现代 API 的主流认证是
//   `Authorization: Bearer <access>` + 一个 refresh 端点。access token 通常 15 分钟到 1 小时过期，
//   而一次扫描动辄几千条请求、跑几十分钟 —— 于是"前 10 分钟的结果是真的，后面全 401"。
//   那半程在检测层看到的是"响应没有差异"，报告落成「未检出」。
//   认证此前只有两条路：静态注入（cookie/header 一次带上，过期即废）+ 会话失效**检测**
//   （scanValidityGuard 判 authLost 后建议人工重取）。本模块补的是**自动续期**。
//
// 与 loginFlow 的分工（刻意不合并成一个模块）：
//   · loginFlow：拿用户名密码换会话 cookie（表单语义：取页、探测字段、hidden 透传）；
//   · bearerKeeper：拿 refresh token 换新 access token（API 语义：一个 POST + JSON 里取字段）。
//   两者的"挑战"判定也不同：表单认证失效常表现为 302 跳登录页，Bearer 失效就是 401/403。
//   合并会让两边的启发式互相污染（跳登录页对 Bearer 目标毫无意义）。
//
// 四条口径：
//  1. **拿到新 token 之前不动用户的 Authorization**。调用方常从抓包里带来一个还没过期的 token；
//     若一上来就用"续期结果"覆盖它，而续期端点其实配错了，那就是把一个能用的会话换成不能用的。
//     ⇒ 只在 ① 首次遇到 401/403 之后，或 ② 显式配 `eager: true` 时，才注入。
//  2. **一次挑战只重试一次**（与 loginFlow 同一条纪律）：续期后仍 401 ⇒ 放行原响应，
//     绝不循环打续期端点（那会对客户认证服务造成 DoS 式压力，也会把扫描拖死）。
//  3. **并发去重**：同一时刻几十条请求都 401 时只发一次续期请求（in-flight 共享）。
//  4. **失败必须显形**：续期端点自己 4xx/5xx/网络异常时，把"为什么"回传给可信度守卫
//     （`observeRefresh`），让 `session_expired` 的文案指向"你配的续期端点没拿到 token"，
//     而不是笼统的"重新登录并携带有效 Cookie"。没有这条，配错续期 = 又一次静默假阴性。
//
// 诚实边界（刻意不做）：不实现 OAuth2 授权码流程、不做验证码/SSO 跳转、不解析 JWT 的 exp
//   提前续期（配 `eager: true` 就"每条前置一个有效 token"，更省事的形态是按需续期）。
// ============================================================================
import { logger } from './logger.js';
import { AppError, ErrorCode } from './errors.js';

/** 未显式指定 tokenField 时按顺序尝试的常见字段（点路径） */
const TOKEN_FIELD_FALLBACKS = [
  'access_token', 'accessToken', 'token', 'id_token',
  'data.access_token', 'data.token', 'result.accessToken', 'result.access_token',
];

/** 视为「会话失效」的状态码：Bearer 语义下就是这两个（不含 302 跳登录页） */
export function isAuthChallenge(res) {
  const status = Number(res?.status);
  return status === 401 || status === 403;
}

/** 按点路径取字段（支持 `data.token`；数字段走数组下标） */
export function pickField(obj, pathStr) {
  const segs = String(pathStr || '').split('.').filter(Boolean);
  let cur = obj;
  for (const seg of segs) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = Array.isArray(cur) ? cur[Number(seg)] : cur[seg];
  }
  return cur;
}

/**
 * 从续期端点的响应里取新 token。
 * @returns {{token: string|null, why: string}} why 非空 = 没拿到，且带可诊断的原因
 */
export function extractToken(payloadText, tokenField) {
  let obj = null;
  try {
    obj = JSON.parse(String(payloadText ?? ''));
  } catch {
    return { token: null, why: '续期响应不是 JSON（无法取 token）' };
  }
  if (!obj || typeof obj !== 'object') return { token: null, why: '续期响应不是对象' };
  const candidates = tokenField ? [String(tokenField)] : TOKEN_FIELD_FALLBACKS;
  for (const c of candidates) {
    const v = pickField(obj, c);
    if (typeof v === 'string' && v.trim()) return { token: v.trim(), why: '' };
  }
  // 报出顶层键名：配错字段是这类配置最常见的错，让人一眼看出该填什么
  return {
    token: null,
    why: `续期响应里没有可用 token（试过 ${candidates.join('/')}；响应顶层键=${Object.keys(obj).slice(0, 8).join(',') || '无'}）`,
  };
}

/** 组装续期请求（refreshToken 放哪个字段、要不要带） */
// ⚠ 这里的形参一律叫 `spec`（续期子配置），不叫 `cfg`：本仓 `cfg`/`config` 指**顶层扫描配置**，
//   tests/configOrphanKeys.guard.test.js 的读取点判据按 `cfg.X` 匹配，叫 cfg 会把组内子键
//   误报成"没有入口的顶层旋钮"。子键可达性由 configWhitelist.passthrough.test.js 逐键钉。
export function buildRefreshRequest(spec) {
  const method = String(spec.method || 'POST').toUpperCase();
  const headers = { ...(spec.headers || {}) };
  const bodyCfg = spec.body === undefined ? {} : spec.body;
  if (spec.refreshToken) {
    const field = String(spec.bodyField || 'refreshToken');
    if (spec.bodyFormat === 'form') {
      const sp = new URLSearchParams({ [field]: String(spec.refreshToken) });
      for (const [k, v] of Object.entries(bodyCfg)) sp.set(k, String(v));
      headers['Content-Type'] = headers['Content-Type'] || 'application/x-www-form-urlencoded';
      return { method, url: spec.url, data: sp.toString(), headers };
    }
    const json = { [field]: String(spec.refreshToken), ...bodyCfg };
    headers['Content-Type'] = headers['Content-Type'] || 'application/json';
    return { method, url: spec.url, data: JSON.stringify(json), headers };
  }
  // 不带 refreshToken：多数实现是从 Cookie 里取（会话 jar 会自动带上），此时 body 可为空
  if (Object.keys(bodyCfg).length === 0) return { method, url: spec.url, headers };
  headers['Content-Type'] = headers['Content-Type'] || 'application/json';
  return { method, url: spec.url, data: JSON.stringify(bodyCfg), headers };
}

/**
 * 入口校验（REST/CLI 的 config.bearerRefresh）：形状非法 ⇒ 抛错，扫描不启动。
 * 空/未给 ⇒ 返回 null（未启用，零行为变化）。
 */
export function normalizeRefreshConfig(raw) {
  if (raw === undefined || raw === null) return null;
  if (typeof raw === 'string') {
    // CLI 只给一个 URL 的便捷写法
    const url = raw.trim();
    return url ? normalizeRefreshConfig({ url }) : null;
  }
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new AppError(ErrorCode.INVALID_PARAM, 'bearerRefresh 须为对象（至少含 url）');
  }
  const url = typeof raw.url === 'string' ? raw.url.trim() : '';
  if (!/^https?:\/\//i.test(url)) {
    // ⚠ 空 url 一律判非法而不是"当作未启用"：requestScript 的教训是默认值语义要一致，
    //   而这里 defaults.bearerRefresh = null（不是 {}），所以出现 {} 说明是人为传错。
    throw new AppError(ErrorCode.INVALID_PARAM, 'bearerRefresh.url 必须是 http(s) 地址');
  }
  const out = { url };
  if (raw.method) out.method = String(raw.method);
  if (typeof raw.refreshToken === 'string' && raw.refreshToken.trim()) out.refreshToken = raw.refreshToken.trim();
  if (typeof raw.bodyField === 'string' && raw.bodyField.trim()) out.bodyField = raw.bodyField.trim();
  if (raw.bodyFormat === 'form' || raw.bodyFormat === 'json') out.bodyFormat = raw.bodyFormat;
  if (raw.body && typeof raw.body === 'object') out.body = { ...raw.body };
  if (typeof raw.tokenField === 'string' && raw.tokenField.trim()) out.tokenField = raw.tokenField.trim();
  if (typeof raw.headerTemplate === 'string' && raw.headerTemplate.includes('{token}')) {
    out.headerTemplate = raw.headerTemplate;
  }
  if (typeof raw.headerName === 'string' && raw.headerName.trim()) out.headerName = raw.headerName.trim();
  if (raw.eager === true) out.eager = true;
  if (raw.headers && typeof raw.headers === 'object') out.headers = { ...raw.headers };
  return out;
}

// ── 按 scanId 的登记表（与 requestTransform 同一形状：视图按 scanId 缓存，状态必须挂 scanId） ──
/** scanId -> { spec, token, inflight, observer, attempts, successes, failures, lastWhy } */
const registry = new Map();

export function registerScanRefresh(scanId, spec) {
  if (!scanId || !spec || !spec.url) return null;
  if (!registry.has(scanId)) registry.set(scanId, { spec, token: null, inflight: null, observer: null, attempts: 0, successes: 0, failures: 0, lastWhy: '' });
  return registry.get(scanId);
}

export function getScanRefresh(scanId) {
  return scanId ? registry.get(scanId) || null : null;
}

export function refreshActiveForScan(scanId) {
  return scanId ? registry.has(scanId) : false;
}

export function releaseScanRefresh(scanId) {
  registry.delete(scanId);
}

/** 挂观察者（scanRunner 用它把续期结果接进可信度守卫）；未登记时返回 false，让接线失败可判 */
export function setRefreshObserver(scanId, observer) {
  const entry = registry.get(scanId);
  if (!entry) return false;
  entry.observer = typeof observer === 'function' ? observer : null;
  return true;
}

function notify(entry, ev) {
  if (typeof entry.observer !== 'function') return;
  try {
    entry.observer(ev);
  } catch { /* 观察者故障绝不影响发包 */ }
}

/**
 * 执行一次续期（并发去重由 withBearerRefresh 负责，这里就是"发一次、取 token"）。
 * 走**内层视图**，因此不会被自己再包一层（不递归），也带上 Cookie Jar（多数实现从 cookie 取刷新凭据）。
 */
export async function refreshOnce(scanId, client) {
  const entry = registry.get(scanId);
  if (!entry) return { ok: false, why: '未登记 bearerRefresh' };
  const spec = entry.spec;
  entry.attempts += 1;
  let res;
  try {
    res = await client.request({ ...buildRefreshRequest(spec), scanId });
  } catch (e) {
    const why = `续期请求发送失败：${e?.message || e}`;
    entry.failures += 1;
    entry.lastWhy = why;
    logger.warn(`[refresh] ${why}`);
    notify(entry, { ok: false, why, status: 0 });
    return { ok: false, why };
  }
  const status = Number(res?.status) || 0;
  if (status >= 400) {
    const why = `续期端点返回 ${status}`;
    entry.failures += 1;
    entry.lastWhy = why;
    logger.warn(`[refresh] ${why}（url=${spec.url}）`);
    notify(entry, { ok: false, why, status });
    return { ok: false, why };
  }
  const { token, why } = extractToken(res?.data, spec.tokenField);
  if (!token) {
    entry.failures += 1;
    entry.lastWhy = why;
    logger.warn(`[refresh] ${why}（url=${spec.url}）`);
    notify(entry, { ok: false, why, status });
    return { ok: false, why };
  }
  entry.token = token;
  entry.successes += 1;
  logger.info(`[refresh] 已取到新 token（长度 ${token.length}，来源字段见配置）`);
  notify(entry, { ok: true, why: '', status });
  return { ok: true, why: '' };
}

/** 把新 token 挂进请求头（模板可换：默认 `Bearer {token}`；也可只填裸 token 或改头名） */
export function applyBearer(opts, spec, token) {
  if (!token) return opts;
  const headerName = spec.headerName || 'Authorization';
  const template = spec.headerTemplate ?? (spec.headerName ? '{token}' : 'Bearer {token}');
  const headers = { ...(opts.headers || {}) };
  headers[headerName] = template.replace('{token}', token);
  const out = { ...opts, headers };
  // ⚠ 出口层的既有合并语义是「auth.headers 覆盖 per-request headers」（mergeAuthHeaders 把
  //   auth.headers 放在最后一步，cli.js 的注入点剔键逻辑就是照它写的）。
  //   于是抓包带来的那一枚 `Authorization: Bearer OLD`（走 config.auth.headers）会在出口
  //   **就地盖掉**续期换来的新令牌 ⇒ 续期成功、日志说"已取到新 token"，线上却还是老令牌，
  //   整轮照样 401 —— 由 e2e/bearer-lab B 场景实测抓到（26 次续期全成功、94 条请求仍被拒）。
  //   修法只在这条请求上摘掉 auth.headers 里的同名键（副本，不动共享的 config.auth）。
  const authHeaders = opts.auth && opts.auth.headers;
  if (authHeaders && typeof authHeaders === 'object') {
    const clash = Object.keys(authHeaders).find((k) => k.toLowerCase() === String(headerName).toLowerCase());
    if (clash) {
      const cleaned = { ...authHeaders };
      delete cleaned[clash];
      out.auth = { ...opts.auth, headers: cleaned };
    }
  }
  return out;
}

/**
 * 包装扫描级视图：401/403 ⇒ 续期一次 ⇒ 重试原请求一次；已拿到 token 后为每条请求挂头。
 * 与 withLoginFlow 同一包装惯例，但**不复制它的那条缺陷**：本层保留并加工 `headRequest`
 * （TODO §10 记着 withSafeUrl/withCsrf/withLoginFlow 三个邻居都把这个方法丢了 ⇒
 *   `--null-connection` 静默退化成 GET。新代码不再复制，见 bearerKeeper.test.js 的 HEAD 用例）。
 * @param {object} client 内层视图
 * @param {string} scanId
 */
export function withBearerRefresh(client, scanId) {
  const entry = registry.get(scanId);
  if (!entry) return client;
  const runRefresh = () => {
    // 并发去重：同一时刻多条请求都 401 时只打一次续期端点
    if (!entry.inflight) entry.inflight = refreshOnce(scanId, client).finally(() => { entry.inflight = null; });
    return entry.inflight;
  };
  const send = async (opts, via) => {
    // ① eager 模式：先确保手里有 token（少数"没 token 直接 403 且不返回可用挑战"的目标）
    if (entry.spec.eager === true && !entry.token) await runRefresh();
    // ② 手里没有新 token 时**绝不动用户带来的 Authorization**：调用方常从抓包里带一个
    //    还没过期的 token，若续期端点配错又拿它去覆盖，等于把能用的会话换成不能用的。
    //    一旦续期成功，覆盖就是应当的 —— 那个被抓包带来的 token 正是"已经过期"的那个。
    let out = entry.token ? applyBearer(opts, entry.spec, entry.token) : opts;
    let res = await via(out);
    if (!isAuthChallenge(res)) return res;
    const ok = (await runRefresh()).ok === true;
    if (!ok) return res;
    res = await via(applyBearer(out, entry.spec, entry.token));
    return res;
  };
  return {
    ...client,
    request: (opts = {}) => send(opts, (o) => client.request(o)),
    // HEAD 走同一套加工：与 TODO §10 的要求一致（新代码不再复制那三个包装的缺陷）
    ...(typeof client.headRequest === 'function'
      ? { headRequest: (url, opts = {}) => send({ ...opts, url }, (o) => {
          const { url: u2, ...rest } = o;
          return client.headRequest(u2, rest);
        }) }
      : {}),
  };
}

export default { normalizeRefreshConfig, refreshOnce, withBearerRefresh, isAuthChallenge, extractToken };
