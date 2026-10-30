// ============================================================================
// core/cookieFile.js —— cookie 文件解析与主机过滤（[D198] 对标 sqlmap --load-cookies / --live-cookies）
//
// 解决什么问题：真实渗透工作流里拿到会话的**主流方式不是手抄**，而是从浏览器/工具导出
// cookie 文件（Netscape/wget `cookies.txt`、Cookie-Editor/Playwright 的 JSON、或直接一段
// `Cookie:` 头）。以前只能人工把名字值抄成 `--cookie`（几十个键抄错一个就整场 401，
// 而报告写的是「未检出」）。本模块是这两个旗标共用的唯一解析真源。
//
// 支持三种形态（自动识别，识别不了**硬失败**，不猜）：
//   ① netscape —— `domain \t flag \t path \t secure \t expiry \t name \t value`，
//      `#HttpOnly_` 前缀与 `#` 注释按惯例处理（wget/curl/浏览器导出）；
//   ② json     —— `[{name,value,domain?,path?,expires?/expirationDate?,secure?}]`，
//      也接受 `{"cookies":[…]}` 包装（Playwright `context.cookies()` / Cookie-Editor 导出）；
//   ③ header   —— 一段 `Cookie:` 头文本（`a=1; b=2`），没有 domain ⇒ 视为适用所有主机。
//
// 过滤规则（**凭据只发给该给的主机**，与 safeUrlKeeper 的凭据纪律同源）：
//   · domain 为空 ⇒ 任意主机；否则去前导点后做后缀匹配（`.example.com` 命中 www.example.com）；
//   · `secure` 的条目不发给 http 目标；
//   · 过期条目（expiry > 0 且已过）不发送；
//   · 路径不做匹配（本引擎按「整站会话」使用，与 sqlmap 一致）。
// ============================================================================

// [D205 代 D198 收口] 错误形态门禁：core 属「非受限目录但基线只减不增」，新文件不得新增裸 Error
//（解析失败/空文件/格式无法识别都是**调用方输入非法**，统一走 INVALID_PARAM）
import { AppError, ErrorCode } from './errors.js';

/** 秒/毫秒时间戳归一（Netscape 用秒；部分 JSON 导出用毫秒）。 */
function toMs(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n > 1e12 ? n : n * 1000;
}

/** 域名归一：小写、去前导点。 */
function normDomain(d) {
  return String(d || '').trim().toLowerCase().replace(/^\.+/, '');
}

/**
 * 主机是否匹配条目的 domain（空 domain = 任意主机）。
 * @param {string} domain 条目 domain
 * @param {string} host 目标主机名（小写）
 * @returns {boolean}
 */
export function domainMatches(domain, host) {
  const d = normDomain(domain);
  if (!d) return true;
  const h = String(host || '').toLowerCase();
  return h === d || h.endsWith(`.${d}`);
}

/** 从 URL 取主机名（解析失败返回 ''）。 */
export function hostOf(url) {
  try {
    return new URL(String(url)).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/** `a=1; b=2` → 有序键值对（同名后者覆盖前者，保持首次出现顺序）。 */
export function parseCookieHeader(raw) {
  const pairs = [];
  const idx = new Map();
  for (const seg of String(raw || '').split(';')) {
    const eq = seg.indexOf('=');
    if (eq <= 0) continue;
    const name = seg.slice(0, eq).trim();
    const value = seg.slice(eq + 1).trim();
    if (!name) continue;
    if (idx.has(name)) pairs[idx.get(name)].value = value;
    else {
      idx.set(name, pairs.length);
      pairs.push({ name, value });
    }
  }
  return pairs;
}

/**
 * 合并两组 cookie 文本：`primary` 的同名值优先，`secondary` 补齐其余（保序）。
 * 用途：`--cookie` 与 cookie 文件、live 文件与静态头 —— 优先级必须在**一处**说清。
 * @param {string} primary 优先来源
 * @param {string} secondary 补充来源
 * @returns {string}
 */
export function mergeCookieStrings(primary, secondary) {
  const out = parseCookieHeader(primary);
  const seen = new Set(out.map((p) => p.name));
  for (const p of parseCookieHeader(secondary)) {
    if (seen.has(p.name)) continue;
    seen.add(p.name);
    out.push(p);
  }
  return out.map((p) => `${p.name}=${p.value}`).join('; ');
}

/** JSON 形态 → 条目。 */
function jsonEntries(parsed) {
  const arr = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.cookies) ? parsed.cookies : null;
  if (!arr) throw new AppError(ErrorCode.INVALID_PARAM, 'cookie JSON 必须是数组，或含 cookies 数组的对象');
  return arr
    .filter((c) => c && typeof c === 'object' && c.name != null && c.value != null)
    .map((c) => ({
      name: String(c.name),
      value: String(c.value),
      domain: normDomain(c.domain),
      path: typeof c.path === 'string' ? c.path : '/',
      secure: c.secure === true,
      httpOnly: c.httpOnly === true,
      expires: toMs(c.expires ?? c.expirationDate ?? c.expiry ?? 0),
    }));
}

/** Netscape/wget 形态 → 条目。 */
function netscapeEntries(lines) {
  const out = [];
  for (const rawLine of lines) {
    let line = rawLine;
    if (!line.trim()) continue;
    let httpOnly = false;
    if (line.startsWith('#HttpOnly_')) {
      httpOnly = true;
      line = line.slice('#HttpOnly_'.length);
    } else if (line.startsWith('#')) {
      continue; // 注释
    }
    const f = line.split('\t');
    if (f.length < 7) continue; // 不是 cookie 行（表头/残留），跳过而不猜
    out.push({
      name: f[5].trim(),
      value: f[6].replace(/\r?\n$/, ''),
      domain: normDomain(f[0]),
      path: f[2] || '/',
      secure: String(f[3]).toUpperCase() === 'TRUE',
      httpOnly,
      expires: toMs(f[4]),
    });
  }
  return out.filter((c) => c.name);
}

/** `Cookie:` 头文本形态 → 条目（无 domain ⇒ 任意主机）。 */
function headerEntries(text) {
  const firstLine = String(text).split(/\r?\n/).find((l) => l.trim()) || '';
  const body = firstLine.replace(/^\s*cookie\s*:\s*/i, '').trim();
  return parseCookieHeader(body).map((p) => ({
    name: p.name,
    value: p.value,
    domain: '',
    path: '/',
    secure: false,
    httpOnly: false,
    expires: 0,
  }));
}

/**
 * 解析 cookie 文件文本（自动识别三种形态；识别不了抛错，不静默返回空）。
 * @param {string} text 文件内容
 * @returns {{format:'netscape'|'json'|'header', entries:Array<object>}}
 */
export function parseCookieFile(text) {
  const raw = String(text ?? '');
  const trimmed = raw.trim();
  if (!trimmed) throw new AppError(ErrorCode.INVALID_PARAM, 'cookie 文件是空的');
  if (trimmed.startsWith('[') || trimmed.startsWith('{')) {
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (e) {
      // [D205 代 D198 收口] preserve-caught-error：JSON 解析异常挂 cause
      throw new AppError(ErrorCode.INVALID_PARAM, `cookie 文件看起来是 JSON 但解析失败：${e.message}`, { cause: e });
    }
    const entries = jsonEntries(parsed);
    if (!entries.length) throw new AppError(ErrorCode.INVALID_PARAM, 'cookie JSON 里没有任何 {name,value} 条目');
    return { format: 'json', entries };
  }
  const lines = raw.split(/\r?\n/);
  if (lines.some((l) => l.split('\t').length >= 6)) {
    const entries = netscapeEntries(lines);
    if (!entries.length) throw new AppError(ErrorCode.INVALID_PARAM, 'cookie 文件看起来是 Netscape/wget 格式，但解析不出任何条目（检查分隔符是否为制表符）');
    return { format: 'netscape', entries };
  }
  if (/=/.test(trimmed)) {
    const entries = headerEntries(trimmed);
    if (!entries.length) throw new AppError(ErrorCode.INVALID_PARAM, 'cookie 文本里找不到 name=value 对');
    return { format: 'header', entries };
  }
  throw new AppError(ErrorCode.INVALID_PARAM, 'cookie 文件格式无法识别（支持 Netscape/wget cookies.txt、JSON 数组、或一段 Cookie 头文本）');
}

/**
 * 按目标 URL 过滤条目并给出统计（统计用于**如实告警**：不匹配不是静默 0）。
 * @param {Array<object>} entries 全部条目
 * @param {string} url 目标 URL
 * @param {number} [nowMs] 当前时间（可注入，便于测试）
 * @returns {{matched:Array<object>, header:string, total:number, skippedExpired:number, skippedSecure:number, skippedHost:number}}
 */
export function selectCookies(entries, url, nowMs = Date.now()) {
  const host = hostOf(url);
  const https = /^https:/i.test(String(url || ''));
  const matched = [];
  let skippedExpired = 0;
  let skippedSecure = 0;
  let skippedHost = 0;
  for (const e of entries || []) {
    if (e.expires > 0 && e.expires < nowMs) { skippedExpired++; continue; }
    if (e.secure === true && !https) { skippedSecure++; continue; }
    if (host && !domainMatches(e.domain, host)) { skippedHost++; continue; }
    matched.push(e);
  }
  const header = matched.map((e) => `${e.name}=${e.value}`).join('; ');
  return { matched, header, total: (entries || []).length, skippedExpired, skippedSecure, skippedHost };
}
