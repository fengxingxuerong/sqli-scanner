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
//   · [D279] HEAD（--null-connection）走同一套取页/携带/刷新计数（headRequest 不再被丢）。
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
 * [D279] 从 csrfUrl 取页并提取 token（模块级：取页是独立职责，拆出以控 withCsrf 体量）。
 * 失败静默降级为「无 token 照扫」，但首次失败打 warn——静默到扫完全无 token 比明确告警更危险。
 * @param {object} client 内层视图（取页请求经它发出，走同一条 SSRF/限速链）
 * @param {{csrfUrl:string, csrfTokenName?:string, csrfMethod?:string}} cfg
 * @param {{token:{name:string,value:string}|null, fetched:boolean}} state 会话态（取页计数/告警节流）
 * @param {object} [opts] 触发请求的 opts（继承 proxy/wafEvasion）
 */
async function fetchTokenFrom(client, cfg, state, opts) {
  try {
    const res = await client.request({
      method: String(cfg.csrfMethod || 'GET').toUpperCase(),
      url: cfg.csrfUrl,
      proxy: opts?.proxy,
      wafEvasion: opts?.wafEvasion,
    });
    const hit = extractCsrfToken(res?.data ?? '', cfg.csrfTokenName);
    if (hit) {
      state.token = hit;
      if (!state.fetched) {
        state.fetched = true;
        logger.info(`[csrf] token 已获取（${hit.name}，长度 ${hit.value.length}）`);
      }
    } else if (!state.fetched) {
      state.fetched = true;
      logger.warn(`[csrf] csrfUrl 响应中未找到 token（name=${cfg.csrfTokenName || '自动探测'}）——将以无 token 继续扫描`);
    }
  } catch (e) {
    if (!state.fetched) {
      state.fetched = true;
      logger.warn(`[csrf] csrfUrl 取页失败（${e.message}）——将以无 token 继续扫描`);
    }
  }
}

/**
 * [D279] headRequest 的会话加工缝（模块级）。三包装丢 headRequest 的缺陷（D36 撞见、
 * 挂账 30 天，收口记录见 CHANGELOG D279 / 仓内待办清单 §10）：此前本层返回 { request }
 * 把 headRequest 整个丢掉 ⇒ 配了 --csrf-url 后 --null-connection 的 HEAD 通道在
 * sendHead 里静默回退 GET（回退的 GET 会经本层拿到 token，所以扫描照样出结论，但
 * HEAD 通道的省带宽语义整个失效且无任何告警）。HEAD 走同一套加工：计数与刷新共享
 * （HEAD 也是扫描请求，首次 HEAD 同样先取 token）、token 同样挂 URL query；与 request
 * 变换层同一教训：HttpClient.headRequest(url, opts) 用显式 url 覆盖 opts.url，带 token
 * 的 URL 必须作为**第一个实参**传下去，只改 opts 会被原 URL 顶掉。
 * @param {object} client 内层视图
 * @param {{bump:(opts:object)=>Promise<void>, apply:(opts:object)=>object}} api 计数/取页与挂 token
 * @returns {object} 仅含 headRequest（或空对象——内层无 HEAD 通道时不凭空造）
 */
function makeCsrfHeadView(client, api) {
  if (typeof client.headRequest !== 'function') return {};
  return {
    headRequest: async (url, opts = {}) => {
      await api.bump(opts);
      const merged = api.apply({ ...opts, method: opts.method || 'HEAD', url });
      const { url: nextUrl, ...rest } = merged;
      return client.headRequest(nextUrl, rest);
    },
  };
}

/**
 * 包装扫描级 httpClient 视图：每请求自动携带/定期刷新 CSRF token。
 * @param {object} client 原始 httpClient 视图（request/headRequest）
 * @param {{csrfUrl:string, csrfTokenName?:string, csrfMethod?:string, refreshFreq?:number}} cfg
 */
export function withCsrf(client, cfg) {
  // refreshFreq 是内部形参名：入口键是 csrfRefreshFreq（REST/CLI），scanClient 传入时改名。
  // 刻意用解构而非 cfg.refreshFreq 成员读取 —— configOrphanKeys.guard 的分母是成员读取点，
  // 内部改名参数不该进它的孤儿判定（同名解构与守卫语义一致）。
  const { refreshFreq } = cfg;
  const freq = clampFreq(refreshFreq);
  const state = { token: null, count: 0, fetched: false }; // token: { name, value }

  // [D279] 计数/取页单缝：GET 与 HEAD 每条扫描请求都走这里（HEAD 也是扫描请求）
  async function bump(opts) {
    state.count += 1;
    if (!state.token || state.count % freq === 0) await fetchTokenFrom(client, cfg, state, opts);
  }

  function applyToken(opts) {
    if (!state.token) return opts;
    const { name, value } = state.token;
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
    ...client,
    request: async (opts = {}) => {
      await bump(opts);
      return client.request(applyToken(opts));
    },
    ...makeCsrfHeadView(client, { bump, apply: applyToken }),
  };
}

export default { withCsrf, extractCsrfToken };
