import { URL } from 'url';
import { createInjectionPoint } from './models.js';
import { httpClient as defaultHttpClient } from '../core/httpClient.js';
import { LinkCrawler, attrValue } from './crawler.js';

// 反 CSRF 字段名正则（命中即记为 csrfTokenName）
const CSRF_RE = /^(csrf|_token|__RequestVerificationToken|authenticity_token)$/i;

// 目标解析器：从 Target 的 URL/Body/Cookie/Header 中发现注入点，
// 并可选地爬取 HTML 表单（复杂表单 / 反 CSRF 自动处理）与站内链接（对标 sqlmap --crawl）。
export class TargetParser {
  /**
   * @param {object} [httpClient] 统一 HttpClient（表单爬取取页经此；缺省用单例）
   * @param {LinkCrawler} [crawler] 链接爬虫（缺省用同一 httpClient 新建）
   */
  constructor(httpClient, crawler) {
    this.httpClient = httpClient || defaultHttpClient;
    this.crawler = crawler || new LinkCrawler({ httpClient: this.httpClient });
  }

  /**
   * 发现注入点（async：表单爬取需经 HttpClient 取页）
   * @param {import('./models.js').Target} target
   * @param {object} [scanClient] 可选 per-scan httpClient 视图（带 scanId 隔离的限速桶），
   *   不传则回退构造函数传入的 httpClient（单例，无 per-scan 限速隔离）。
   * @returns {Promise<import('./models.js').InjectionPoint[]>}
   */
  async discover(target, scanClient) {
    // [P0-FIX] 发现阶段使用 per-scan httpClient（若传入），使爬取/表单探测也走 per-scan 限速桶。
    // 未传入时回退构造器注入的 httpClient（单例，兼容 < 2.0 版本）。
    if (scanClient) {
      this.httpClient = scanClient;
      this.crawler.httpClient = scanClient; // 爬虫同步 per-scan 客户端
    }
    const points = [];

    // 直连模式：注入点来自 sqlTemplate（含 {INJECT} 标记），仅 1 个注入点，无需 HTTP 爬取。
    if (target.mode === 'direct') {
      points.push(
        createInjectionPoint('direct', '__INJECT__', target.originalValue || '1', {
          sqlTemplate: target.sqlTemplate,
        })
      );
      return points;
    }

    // Level 系统（对标 sqlmap --level）：控制注入点发现范围
    //   level 1：URL 查询参数 + POST body 参数（默认，sqlmap 标准）
    //   level 2：+ Cookie 参数
    //   level 3：+ header 参数（非敏感头如 User-Agent/Referer）
    //   level 4：+ 全部 header 参数（含敏感头）
    //   level 5：+ 表单爬取 + 站内链接爬取
    const config = target.config || {};
    const level = config.level || 1;

    // 1) URL 路径注入点（P3）：路径含 * 标记路径段注入位置（如 http://host/api/v1/users/1*/profile）。
    //    优先于「参数值尾 * 精确标记」（P1-U4）——先判断是路径 * 还是参数值 *，命中路径 * 即只返回路径点。
    if (target.baseUrl) {
      try {
        const u = new URL(target.baseUrl);
        if (u.pathname.includes('*')) return this._pathInjectionPoints(u);
      } catch {
        // URL 解析失败则跳过路径点
      }
    }

    // 2) URL 查询参数（level≥1，始终检查）
    if (target.baseUrl) {
      try {
        const u = new URL(target.baseUrl);
        for (const [k, v] of u.searchParams.entries()) {
          points.push(createInjectionPoint('url', k, v));
        }
      } catch {
        // URL 解析失败则跳过
      }
    }

    // 3) Body 参数（level≥1，始终检查，与 sqlmap 默认行为一致）
    for (const [k, v] of Object.entries(target.bodyParams || {})) {
      points.push(createInjectionPoint('body', k, String(v)));
    }

    // 4) Cookie 参数（level≥2）
    if (level >= 2) {
      for (const [k, v] of Object.entries(target.cookieParams || {})) {
        points.push(createInjectionPoint('cookie', k, String(v)));
      }
    }

    // 5) Header 参数（level≥3 检查非敏感头；level≥4 检查全部头）
    if (level >= 3) {
      const SENSITIVE_HEADERS = new Set(['authorization', 'cookie', 'host', 'x-forwarded-for']);
      for (const [k, v] of Object.entries(target.headerParams || {})) {
        if (level >= 4 || !SENSITIVE_HEADERS.has(k.toLowerCase())) {
          points.push(createInjectionPoint('header', k, String(v)));
        }
      }
    }

    // 6) 表单爬取（level≥5，且 opt-in crawlForms 开启）
    if (level >= 5 && config.crawlForms) {
      await this._crawlForms(target, points);
    }

    // 6.5) 站内链接爬取（level≥5，且 crawlDepth>0 开启）
    const crawlDepth = Number(config.crawlDepth) || 0;
    if (level >= 5 && crawlDepth > 0) {
      await this._crawlLinks(target, points, crawlDepth);
    }

    // 7) 精确注入点标记（P1-U4，对标 sqlmap -p / `*`）：任一参数值以 `*` 结尾 → 仅保留该参数。
    // 值尾 `*` 剥离后作为 originalValue；存在多个 `*` 标记时全部保留（多注入点精确指定）。
    const marked = points.filter((p) => typeof p.originalValue === 'string' && p.originalValue.endsWith('*'));
    if (marked.length > 0) {
      for (const p of marked) {
        p.originalValue = p.originalValue.slice(0, -1); // 剥离尾部 *
        p.precisionMarked = true;
      }
      return marked;
    }

    return points;
  }

  // 从已解析 URL 中提取路径段注入点（P3）：路径段中含 `*` 即标记注入位置。
  // 例：`http://host/api/v1/users/1*/profile` → 段 `1*` 被剥离为 originalValue `1`，
  // pathSegment 记录段下标（0-based，含前导空段），供 buildInjectionRequest 精确定位替换。
  // param 取剥离后的段值作为注入参数名（展示用）；存在多个 `*` 段时全部保留。
  _pathInjectionPoints(u) {
    const points = [];
    const segments = u.pathname.split('/');
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i];
      if (seg.includes('*')) {
        const value = seg.replace(/\*+$/g, '');
        points.push(
          createInjectionPoint('path', value || `__SEG${i}__`, value, {
            pathSegment: i,
            precisionMarked: true,
          })
        );
      }
    }
    return points;
  }

  // 取目标页 HTML（经统一 HttpClient，失败返回 null 不中断发现）
  // [HTTP/2] config.http2 === true 时走 undici（ALPN h2 优先）；否则沿用 axios HTTP/1.1
  async _fetchHtml(url, config) {
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

  // 解析 HTML 中的 <form>，返回 { method, action, values, csrfTokenName }[]
  _parseForms(html, baseUrl) {
    const forms = [];
    const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
    let fm;
    while ((fm = formRe.exec(html))) {
      const formTag = fm[1] || '';
      const inner = fm[2] || '';
      const method = (this._attr(formTag, 'method') || 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET';
      const actionRaw = this._attr(formTag, 'action') || '';
      let action;
      try {
        action = actionRaw ? new URL(actionRaw, baseUrl).toString() : baseUrl;
      } catch {
        action = baseUrl;
      }

      const values = {};
      let csrfTokenName = null;
      const inputRe = /<input\b([^>]*)\/?>/gi;
      let im;
      while ((im = inputRe.exec(inner))) {
        const tag = im[1] || '';
        const type = (this._attr(tag, 'type') || 'text').toLowerCase();
        // 跳过提交/按钮类控件（无注入语义）；hidden 仍需采集（含 CSRF token）
        if (['submit', 'button', 'image', 'reset'].includes(type)) continue;
        const name = this._attr(tag, 'name');
        if (!name) continue; // 无 name 的 input 不可作为注入点
        const value = this._attr(tag, 'value') || '';
        values[name] = value;
        if (!csrfTokenName && CSRF_RE.test(name)) csrfTokenName = name;
      }

      forms.push({ method, action, values, csrfTokenName });
    }
    return forms;
  }

  // 从标签字符串中取某属性值（兼容双引号/单引号/无引号）
  // P1-11 收敛：与 crawler.attrValue / SecondOrderDetector 共用单一事实源（含正则缓存），
  // 消除第三份逐字拷贝。行为零变化（委托实现逐字相同）。
  _attr(tag, name) {
    return attrValue(tag, name);
  }

  // 表单爬取：解析页面表单，为每个 named input 生成 body 位置注入点。
  // 同一页面多 action 记为独立点；CSRF token 随 formValues 一并带上。
  async _crawlForms(target, points) {
    const config = target.config || {};
    const html = await this._fetchHtml(target.baseUrl, config);
    if (!html) return;
    const forms = this._parseForms(html, target.baseUrl);
    for (const form of forms) {
      const csrf = form.csrfTokenName || null;
      // 仅 POST 表单点标记为潜在存储点（GET/非表单点保持 false/null，向后兼容一阶）
      const isStore = form.method === 'POST';
      const storeKind = isStore ? this._inferStoreKind(form.values) : null;
      for (const fieldName of Object.keys(form.values)) {
        points.push(
          createInjectionPoint('body', fieldName, form.values[fieldName] || '', {
            formMethod: form.method,
            actionUrl: form.action,
            formValues: form.values,
            csrfTokenName: csrf,
            isStorePoint: isStore,
            storeKind,
          })
        );
      }
    }
  }

  // 注入点去重 key（同 URL+参数不重复加）：
  // url 点按「请求 URL（actionUrl 或目标 baseUrl）+ 参数名」去重；
  // 其它位置点按「位置 + 参数名 + actionUrl」去重（表单点多 action 视为独立点）。
  _pointKey(point, fallbackUrl) {
    if (point.location === 'url') {
      return `url:${point.actionUrl || fallbackUrl}:${point.param}`;
    }
    return `${point.location}:${point.param}:${point.actionUrl || ''}`;
  }

  // 站内链接爬取（对标 sqlmap --crawl=<depth>）：递归发现同域链接，
  // 每个发现的 URL（含未抓取的链接页）的 query 参数生成 url 注入点；
  // crawlForms 开启时一并解析已抓取页的表单。
  // 单页爬取失败跳过不阻断；与既有 points 合并去重（同 URL+参数不重复加）。
  async _crawlLinks(target, points, depth) {
    const config = target.config || {};
    // 既有点的 key 集合，用于合并去重
    const seen = new Set(points.map((p) => this._pointKey(p, target.baseUrl)));
    let result;
    try {
      result = await this.crawler.crawl({ baseUrl: target.baseUrl, config, depth });
    } catch {
      return; // 爬取失败/超时不阻断发现
    }
    const { pages = [], links = [] } = result;
    // 1) 所有发现的同域 URL（含未抓取链接页）的 query 参数 → url 注入点
    for (const rawUrl of links) {
      try {
        const u = new URL(rawUrl);
        for (const [k, v] of u.searchParams.entries()) {
          const key = `url:${rawUrl}:${k}`;
          if (seen.has(key)) continue;
          seen.add(key);
          points.push(createInjectionPoint('url', k, v, { actionUrl: rawUrl, crawledUrl: rawUrl }));
        }
      } catch {
        // URL 解析失败则跳过该链接
      }
    }
    // 2) 已抓取页表单（仅 crawlForms 开启时解析，语义与 _crawlForms 一致）
    if (config.crawlForms) {
      for (const page of pages) {
        const forms = this._parseForms(page.html, page.url);
        for (const form of forms) {
          const csrf = form.csrfTokenName || null;
          const isStore = form.method === 'POST';
          const storeKind = isStore ? this._inferStoreKind(form.values) : null;
          for (const fieldName of Object.keys(form.values)) {
            const key = `body:${fieldName}:${form.action}`;
            if (seen.has(key)) continue;
            seen.add(key);
            points.push(
              createInjectionPoint('body', fieldName, form.values[fieldName] || '', {
                formMethod: form.method,
                actionUrl: form.action,
                formValues: form.values,
                csrfTokenName: csrf,
                isStorePoint: isStore,
                storeKind,
                crawledUrl: page.url,
              })
            );
          }
        }
      }
    }
  }

  // 启发式推断存储点类型（仅作提示，不强制）：依据表单字段名判断注册/资料/评论/其它。
  // 该分类仅用于提示，真正的二阶判定在 SecondOrderDetector。
  _inferStoreKind(values) {
    const keys = Object.keys(values || {}).map((k) => k.toLowerCase());
    const has = (...subs) => subs.some((s) => keys.some((k) => k.includes(s)));
    if (has('username', 'password', 'email', 'register', 'signup', 'sign_up')) return 'registration';
    if (has('comment', 'content', 'body', 'message', 'reply', 'note', 'post', 'feedback')) return 'comment';
    if (has('displayname', 'bio', 'avatar', 'nickname', 'profile', 'firstname', 'lastname')) return 'profile';
    return 'unknown';
  }
}

export default TargetParser;
