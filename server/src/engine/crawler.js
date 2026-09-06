import { URL } from 'url';
import { httpClient as defaultHttpClient } from '../core/httpClient.js';

// 链接爬虫（对标 sqlmap --crawl=<depth>）：从目标页递归发现站内链接，
// 同域限制 + 去重 + 深度/页数上限，供 TargetParser 生成新增注入点。
// 仅做链接发现与取页（只读 GET），不提交任何写请求。

// 跳过非网页/伪协议链接（点击无服务端语义，不会形成注入面）
const SKIP_PROTOCOLS = /^(javascript|mailto|tel|data|vbscript|about|blob|file|ftp):/i;

// 需提取的属性标签：a/form/script/link/iframe/img（img 可关，避免图片地址噪音）
// P2-11/R12: 预编译标签匹配正则，避免 extractLinks 每调用 new RegExp
const TAG_ATTRS = [
  { tag: 'a', attr: 'href', re: /<a\b([^>]*)>/gi },
  { tag: 'form', attr: 'action', re: /<form\b([^>]*)>/gi },
  { tag: 'script', attr: 'src', re: /<script\b([^>]*)>/gi },
  { tag: 'link', attr: 'href', re: /<link\b([^>]*)>/gi },
  { tag: 'iframe', attr: 'src', re: /<iframe\b([^>]*)>/gi },
  { tag: 'img', attr: 'src', re: /<img\b([^>]*)>/gi },
];

// P2-11/R12: 属性值正则缓存（按属性名复用编译结果，避免每标签 new RegExp）
const _attrReCache = new Map();
function getAttrRegExp(name) {
  let re = _attrReCache.get(name);
  if (!re) {
    re = new RegExp(`${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]*))`, 'i');
    _attrReCache.set(name, re);
  }
  return re;
}

/**
 * 从标签字符串中取某属性值（兼容双引号/单引号/无引号）
 * @param {string} tag 标签内串（不含 < >）
 * @param {string} name 属性名
 * @returns {string} 属性值（未命中返回空串）
 */
export function attrValue(tag, name) {
  const re = getAttrRegExp(name);
  const m = tag.match(re);
  if (!m) return '';
  return m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : '';
}

/**
 * 从 HTML 中提取全部可爬链接（相对/绝对均解析为绝对 URL）
 * @param {string} html 页面 HTML
 * @param {string} baseUrl 基准 URL（解析相对路径）
 * @param {object} [opts] { includeImages } img 是否参与提取（默认 true）
 * @returns {Array<{ url: string, tag: string }>} 绝对 URL + 来源标签
 */
export function extractLinks(html, baseUrl, opts = {}) {
  const includeImages = opts.includeImages !== false;
  const links = [];
  const push = (raw, tag) => {
    if (!raw) return;
    const s = raw.trim();
    if (!s || s.startsWith('#') || SKIP_PROTOCOLS.test(s)) return; // 空/纯锚点/伪协议跳过
    try {
      const abs = new URL(s, baseUrl).toString();
      if (/^https?:/i.test(abs)) links.push({ url: abs, tag });
    } catch {
      /* 非法 URL 忽略 */
    }
  };
  for (const { tag, attr, re } of TAG_ATTRS) {
    if (tag === 'img' && !includeImages) continue;
    re.lastIndex = 0; // 复用预编译正则，重置 lastIndex 防止 g 标志状态残留
    let m;
    while ((m = re.exec(html))) {
      const v = attrValue(m[1], attr);
      if (v) push(v, tag);
    }
  }
  return links;
}

/**
 * 链接爬虫：BFS 深度爬取，同域限制 + 全局去重 + 每深度/总量上限。
 * 单页取页失败（网络/超时/4xx）跳过不阻断整体爬取。
 */
export class LinkCrawler {
  /**
   * @param {object} [options]
   * @param {object} [options.httpClient] 统一 HttpClient（缺省用单例）
   * @param {number} [options.maxPagesPerDepth] 每深度最多取页数（防爆量）
   * @param {number} [options.maxTotalPages] 爬取总页面上限
   * @param {boolean} [options.includeImages] img 链接是否参与提取
   */
  constructor({ httpClient, maxPagesPerDepth = 20, maxTotalPages = 50, includeImages = true } = {}) {
    this.httpClient = httpClient || defaultHttpClient;
    this.maxPagesPerDepth = maxPagesPerDepth;
    this.maxTotalPages = maxTotalPages;
    this.includeImages = includeImages;
  }

  /**
   * 从目标 URL 开始爬取链接
   * @param {object} opts { baseUrl, config, depth }
   *   - baseUrl 目标 URL（注入点发现起点，同域判定以它为准）
   *   - config 扫描配置（透传 timeoutMs/retry/proxy/auth/wafEvasion 至取页请求）
   *   - depth 爬取深度 0-3（0=关闭）
   * @returns {Promise<{ pages: Array<{ url, html }>, links: string[] }>}
   *   - pages：实际抓取到的页面（去重、同域，每深度 ≤maxPagesPerDepth，总量 ≤maxTotalPages）
   *   - links：从各页提取的全部同域去重链接（未抓取页的 query 参数同样构成注入面）
   */
  async crawl({ baseUrl, config = {}, depth = 0 }) {
    const maxDepth = Math.max(0, Math.min(3, Number(depth) || 0));
    if (maxDepth < 1 || !baseUrl) return { pages: [], links: [] };
    let base;
    try {
      base = new URL(baseUrl);
    } catch {
      return { pages: [], links: [] };
    }
    const host = base.host;
    const visited = new Set(); // 已取页（或已入队）的规范化 URL
    const allLinks = new Set(); // 全部发现的同域去重链接（含已抓取页本身）
    const pages = [];
    let frontier = [this._normalize(baseUrl)];
    // 深度语义对标 sqlmap --crawl=<depth>：depth=1 仅目标页，depth=2 目标页+一级链接页，
    // depth=3 再加二级。d 从 0 计，循环 <maxDepth 次 = 恰好抓 maxDepth 层页面。
    for (let d = 0; d < maxDepth && frontier.length > 0 && pages.length < this.maxTotalPages; d++) {
      const next = [];
      let perDepth = 0;
      for (const rawUrl of frontier) {
        if (perDepth >= this.maxPagesPerDepth || pages.length >= this.maxTotalPages) break;
        const url = this._normalize(rawUrl);
        if (!url || visited.has(url)) continue;
        visited.add(url);
        perDepth++;
        allLinks.add(url); // 抓取页本身也是注入面（含 query）
        const html = await this._fetch(url, config);
        if (html == null) continue; // 单页失败跳过，不阻断
        pages.push({ url, html });
        for (const link of extractLinks(html, url, { includeImages: this.includeImages })) {
          const lu = this._normalize(link.url);
          if (!lu || visited.has(lu)) continue;
          try {
            if (new URL(lu).host !== host) continue; // 同域限制：仅爬与目标同 host 的链接
          } catch {
            continue;
          }
          allLinks.add(lu);
          next.push(lu);
        }
      }
      frontier = next;
    }
    return { pages, links: [...allLinks] };
  }

  // 规范化 URL：去 hash（纯锚点变化不构成新页面），解析失败返回 null
  _normalize(url) {
    try {
      const u = new URL(url);
      u.hash = '';
      return u.toString();
    } catch {
      return null;
    }
  }

  // 取页（经统一 HttpClient，失败返回 null 不中断）
  // [HTTP/2] config.http2 === true 时走 undici（ALPN h2 优先）；否则沿用 axios HTTP/1.1
  async _fetch(url, config) {
    try {
      const useHttp2 = config?.http2 === true;
      const res = await this.httpClient.request({
        method: 'GET',
        url,
        timeoutMs: config?.timeoutMs,
        retry: config?.retry,
        proxy: config?.proxy ?? false,
        auth: config?.auth ?? null,
        wafEvasion: config?.wafEvasion ?? null,
        ...(useHttp2 ? { http2: true } : {}),
      });
      return String(res?.data ?? '');
    } catch {
      return null;
    }
  }
}

export default LinkCrawler;
