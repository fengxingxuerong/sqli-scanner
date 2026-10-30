// ============================================================================
// core/liveCookies.js —— 每请求重载的 cookie 文件（[D198] 对标 sqlmap --live-cookies）
//
// 与 --load-cookies 的分工（刻意分成两件事）：
//   · --load-cookies：**开扫时读一次**，把文件里的值并进会话（静态、可预测、CLI 侧解析）；
//   · --live-cookies：**每个请求前重读文件**，拿最新值覆盖同名会话 cookie —— 目标是
//     「令牌半小时过期」「前端每次刷新都换 cookie」这类会话，静态快照扫到后半程全 401，
//     而那些 401 在报告里长得像「这个参数没洞」。
//
// 三个设计约束（都是被本地历史打出来的）：
//   ① **状态挂 scanId**（与 bearerKeeper/requestTransform 同一形状）：视图按 scanId 缓存，
//      全局变量会在批量/并发扫描间串台；
//   ② **设备端文件不重读磁盘打爆 IO**：按 mtime+size 做缓存，文件没变就不重新解析
//      （60~80 探针/点的盲注提取会发上千请求，每请求 readFileSync 是不可接受的）；
//   ③ **读不到文件不静默**：节流告警一次并**不改写**该请求的 cookie（保留原值），
//      于是目标侧会照样 401 → 可信度守卫判 inconclusive —— 而不是拿过期值继续装作在扫。
//
// 与注入点的关系（D101 的同一纪律）：`cookieParams` 里被当作注入点的键**必须排除**在 live
// 覆盖之外，否则每请求重载会把注入 payload 顶回原值 ⇒ cookie 型注入静默假阴性。
// ============================================================================
import { readFileSync, statSync } from 'node:fs';
import { logger } from './logger.js';
import { parseCookieFile, selectCookies, mergeCookieStrings } from './cookieFile.js';

/** scanId -> { file, exclude:Set<string>, cache, warned } */
const registry = new Map();

/**
 * 登记某次扫描的 live cookie 文件（无 scanId / 无文件则返回 null，令接线失败可判）。
 * @param {string} scanId 扫描 id
 * @param {string} file cookie 文件路径
 * @param {string[]} [excludeNames] 不得被覆盖的 cookie 名（注入点）
 * @returns {object|null} 登记项
 */
export function registerLiveCookies(scanId, file, excludeNames = []) {
  if (!scanId || typeof file !== 'string' || !file.trim()) return null;
  const entry = {
    file: file.trim(),
    exclude: new Set((excludeNames || []).map((n) => String(n))),
    cache: null,
    warned: false,
  };
  registry.set(scanId, entry);
  return entry;
}

/** 该扫描是否登记了 live cookie 文件。 */
export function liveCookiesActiveForScan(scanId) {
  return Boolean(scanId) && registry.has(scanId);
}

/** 扫描退役时释放（防 Map 无界增长）。 */
export function releaseLiveCookies(scanId) {
  registry.delete(scanId);
}

/** 测试用：清空登记表。 */
export function resetLiveCookies() {
  registry.clear();
}

/**
 * 读取并解析（带 mtime+size 缓存）。读/解析失败时**节流告警一次**并返回 null。
 * @param {object} entry 登记项
 * @returns {Array<object>|null} 条目
 */
function entriesOf(entry) {
  let st;
  try {
    st = statSync(entry.file);
  } catch (e) {
    if (!entry.warned) {
      entry.warned = true;
      logger.warn(`--live-cookies 读不到文件 ${entry.file}：${e.message}（该请求沿用原 cookie；修复前目标多半 401 ⇒ 结论会是不确定，不是「未检出」）`);
    }
    return null;
  }
  if (entry.cache && entry.cache.mtimeMs === st.mtimeMs && entry.cache.size === st.size) return entry.cache.entries;
  try {
    const { entries } = parseCookieFile(readFileSync(entry.file, 'utf8'));
    entry.cache = { mtimeMs: st.mtimeMs, size: st.size, entries };
    entry.warned = false; // 恢复可读后允许再次告警（下一次失败是新事件）
    return entries;
  } catch (e) {
    if (!entry.warned) {
      entry.warned = true;
      logger.warn(`--live-cookies 解析失败 ${entry.file}：${e.message}（该请求沿用原 cookie）`);
    }
    return null;
  }
}

/**
 * 取该次请求应从 live 文件携带的 cookie 文本（排除注入点键；无内容返回 ''）。
 * @param {string} scanId 扫描 id
 * @param {string} url 目标 URL
 * @param {number} [nowMs] 当前时间（测试注入）
 * @returns {string}
 */
export function liveCookieHeaderForScan(scanId, url, nowMs = Date.now()) {
  const entry = scanId ? registry.get(scanId) : null;
  if (!entry) return '';
  const entries = entriesOf(entry);
  if (!entries) return '';
  const usable = entry.exclude.size ? entries.filter((c) => !entry.exclude.has(c.name)) : entries;
  return selectCookies(usable, url, nowMs).header;
}

/** 在 headers 上写入 Cookie（沿用既有大小写，避免同名头两份 —— D91 的教训）。 */
function putCookieHeader(headers, value) {
  const key = Object.keys(headers).find((k) => k.toLowerCase() === 'cookie') || 'Cookie';
  const existing = headers[key];
  headers[key] = existing ? mergeCookieStrings(value, existing) : value;
  return headers;
}

/**
 * 包装客户端：每请求前用 live 文件的最新值覆盖同名会话 cookie。
 *
 * 优先级（必须只有一处说清）：**live 文件 > 静态 --cookie / 请求头 > cookie jar**
 *   · jar 在 httpClient._prepareHeaders 里合并，且「用户显式 Cookie 优先」，所以本层写进
 *     opts.headers 的值天然赢过 jar（jar 只补不重名的）；
 *   · 注入点键已在登记时排除，故不会把 payload 顶回原值。
 * @param {any} client 客户端视图
 * @param {string} scanId 扫描 id
 * @param {{file:string, excludeNames?:string[]}} spec 文件与不得覆盖的 cookie 名
 * @returns {any} 包装后的视图（同一对象就地改写，与邻居包装器一致）
 */
export function withLiveCookies(client, scanId, spec) {
  const file = spec && typeof spec.file === 'string' ? spec.file.trim() : '';
  if (!file) return client;
  if (!liveCookiesActiveForScan(scanId)) registerLiveCookies(scanId, file, (spec && spec.excludeNames) || []);
  const apply = (opts) => {
    const url = opts && opts.url;
    if (!url) return opts;
    const live = liveCookieHeaderForScan(scanId, url);
    if (!live) return opts;
    return { ...opts, headers: putCookieHeader({ ...(opts.headers || {}) }, live) };
  };
  if (client && typeof client.request === 'function') {
    const req0 = client.request.bind(client);
    client.request = async (opts) => req0(apply(opts));
  }
  if (client && typeof client.headRequest === 'function') {
    const head0 = client.headRequest.bind(client);
    client.headRequest = async (url, opts = {}) => head0(url, apply({ ...opts, url }));
  }
  return client;
}
