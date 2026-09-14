// ============================================================================
// csrfKeeper.js —— CSRF token 会话层（对标 sqlmap --csrf-url / --csrf-token）
//
// 语义（sqlmap 对齐）：
//   配置 csrfUrl 后，扫描启动时先 GET 一次 csrfUrl 页面，按 csrfTokenName（或自动探测
//   常见 hidden input 名）提取 token；此后每个扫描请求自动携带 token：
//     · GET/HEAD：token 挂到 URL query（不覆盖已有同名参数）
//     · POST（表单/JSON）：token 并入 data / JSON body（不覆盖注入参数与业务字段）
//     · 兜底：也可配置 csrfMethod 指定取页请求方法（默认 GET）
//   token 刷新：每 refreshFreq（默认 50）个扫描请求重新取页提取一次（对齐实战里
//   token 一次性的现实——无限重放会被应用判定会话异常）。
//
// 安全边界（与 safeUrlKeeper 同款纪律）：
//   · SSRF 不在此层：token 取页请求仍走 HttpClient.request，逐请求 assertSafeHttpTarget。
//   · 取页失败静默降级为「无 token 照扫」（与 sqlmap --csrf-url 失败行为一致），
//     但首次失败打 warn——静默到扫完全无 token 比明确告警更危险。
//   · token 值只进请求参数与日志打码通道，不落报告。
// ============================================================================

import { logger } from './logger.js';

// 常见 anti-CSRF hidden input 名（自动探测用；显式传 csrfTokenName 时跳过探测）
const COMMON_CSRF_NAMES = [
  'csrf_token', 'csrftoken', '_csrf', 'csrf', '_token', 'token',
  'authenticity_token', 'xsrf_token', 'x-xsrf-token', 'antiforgerytoken',
  '__requestverificationtoken', 'requesttoken',
];

const NAME_ATTR_RE = /name\s*=\s*["']([^"']+)["']/i;
const VALUE_ATTR_RE = /value\s*=\s*["']([^"']*)["']/i;
const INPUT_RE = /<input\b[^>]*>/gi;

/** 从 HTML 提取 anti-CSRF token：显式指定名 → 精确匹配；未指定 → 遍历常见名 */
export function extractCsrfToken(html, tokenName) {
  const text = String(html ?? '');
  if (!text) return null;
  const wanted = tokenName ? String(tokenName).toLowerCase() : null;
  for (const m of text.match(INPUT_RE) || []) {
    const nameM = NAME_ATTR_RE.exec(m);
    if (!nameM) continue;
    const name = nameM[1].trim();
    const hit = wanted ? name.toLowerCase() === wanted : COMMON_CSRF_NAMES.includes(name.toLowerCase());
    if (!hit) continue;
    const valueM = VALUE_ATTR_RE.exec(m);
    if (!valueM) continue;
    return { name, value: valueM[1] };
  }
  return null;
}

const clampFreq = (v) => {
  const n = Math.floor(Number(v));
  return Number.isFinite(n) && n >= 1 ? Math.min(n, 10000) : 50;
};

/**
 * 包装扫描级 httpClient 视图：每请求自动携带/定期刷新 CSRF token。
 * @param {object} client 原始 httpClient 视图（request/headRequest）
 * @param {{csrfUrl:string, csrfTokenName?:string, csrfMethod?:string, refreshFreq?:number}} cfg
 */
export function withCsrf(client, { csrfUrl, csrfTokenName, csrfMethod, refreshFreq }) {
  const freq = clampFreq(refreshFreq);
  let token = null;       // { name, value }
  let count = 0;
  let fetched = false;

  async function fetchToken(opts) {
    try {
      const res = await client.request({
        method: String(csrfMethod || 'GET').toUpperCase(),
        url: csrfUrl,
        proxy: opts?.proxy,
        wafEvasion: opts?.wafEvasion,
      });
      const hit = extractCsrfToken(res?.data ?? '', csrfTokenName);
      if (hit) {
        token = hit;
        if (!fetched) {
          fetched = true;
          logger.info(`[csrf] token 已获取（${hit.name}，长度 ${hit.value.length}）`);
        }
      } else if (!fetched) {
        fetched = true;
        logger.warn(`[csrf] csrfUrl 响应中未找到 token（name=${csrfTokenName || '自动探测'}）——将以无 token 继续扫描`);
      }
    } catch (e) {
      if (!fetched) {
        fetched = true;
        logger.warn(`[csrf] csrfUrl 取页失败（${e.message}）——将以无 token 继续扫描`);
      }
    }
  }

  function applyToken(opts) {
    if (!token) return opts;
    const { name, value } = token;
    const method = String(opts.method || 'GET').toUpperCase();
    if (method === 'GET' || method === 'HEAD' || !opts.data) {
      // query 携带：不覆盖已有同名参数（注入参数/业务参数优先）
      const u = new URL(opts.url);
      if (!u.searchParams.has(name)) u.searchParams.set(name, value);
      return { ...opts, url: u.toString() };
    }
    // body 携带：表单对象并入；JSON 字符串体并入 query（避免破坏业务 JSON 结构）
    if (typeof opts.data === 'object' && opts.data !== null && !Array.isArray(opts.data)) {
      if (name in opts.data) return opts; // 业务字段优先，绝不覆盖
      return { ...opts, data: { ...opts.data, [name]: value } };
    }
    const u = new URL(opts.url);
    if (!u.searchParams.has(name)) u.searchParams.set(name, value);
    return { ...opts, url: u.toString() };
  }

  return {
    request: async (opts = {}) => {
      count += 1;
      if (!token || count % freq === 0) await fetchToken(opts);
      return client.request(applyToken(opts));
    },
  };
}

export default { withCsrf, extractCsrfToken };
