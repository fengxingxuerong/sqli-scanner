import { URL } from 'url';
import { createInjectionPoint } from './models.js';
import { httpClient as defaultHttpClient } from '../core/httpClient.js';

// 反 CSRF 字段名正则（命中即记为 csrfTokenName）
const CSRF_RE = /^(csrf|_token|__RequestVerificationToken|authenticity_token)$/i;

// 目标解析器：从 Target 的 URL/Body/Cookie/Header 中发现注入点，
// 并可选地爬取 HTML 表单（复杂表单 / 反 CSRF 自动处理）。
export class TargetParser {
  /**
   * @param {object} [httpClient] 统一 HttpClient（表单爬取取页经此；缺省用单例）
   */
  constructor(httpClient) {
    this.httpClient = httpClient || defaultHttpClient;
  }

  /**
   * 发现注入点（async：表单爬取需经 HttpClient 取页）
   * @param {import('./models.js').Target} target
   * @returns {Promise<import('./models.js').InjectionPoint[]>}
   */
  async discover(target) {
    const points = [];
    // --level（对标 sqlmap）：控制「测哪些位置」的参数注入点扩展。
    //   1=仅 URL/Body（默认）；2=+Cookie；3=+显式 Header 与自动 User-Agent/Referer 头。
    const level = Number.isFinite(Number(target?.config?.level))
      ? Number(target.config.level)
      : 1;

    // 1) URL 查询参数（GET/POST 均可能带查询串）
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

    // 2) Body 参数（POST 表单/JSON）
    for (const [k, v] of Object.entries(target.bodyParams || {})) {
      points.push(createInjectionPoint('body', k, String(v)));
    }

    // 3) Cookie 参数（sqlmap --level>=2 才测 Cookie；默认 level=1 不测，避免对会话凭据盲目注入）
    if (level >= 2) {
      for (const [k, v] of Object.entries(target.cookieParams || {})) {
        points.push(createInjectionPoint('cookie', k, String(v)));
      }
    }

    // 4) 显式 Header 参数（level>=3 才测；默认不测）
    if (level >= 3) {
      for (const [k, v] of Object.entries(target.headerParams || {})) {
        points.push(createInjectionPoint('header', k, String(v)));
      }
    }

    // 5) 自动注入点（sqlmap --level>=3）：对常见请求头 User-Agent/Referer 生成注入点，
    //     即便调用方未显式列举——这是「测哪里」的核心扩展。跳过调用方已显式提供的头（去重）。
    //     注：故意不含 Host——替换 Host 头会破坏 HTTP 连接，sqlmap 亦以追加而非替换方式处理。
    if (level >= 3) {
      const explicit = new Set(
        Object.keys(target.headerParams || {}).map((k) => k.toLowerCase())
      );
      for (const h of ['User-Agent', 'Referer']) {
        if (!explicit.has(h.toLowerCase())) {
          points.push(createInjectionPoint('header', h, '1'));
        }
      }
    }

    // 6) 表单爬取（opt-in：默认关闭，避免误触发提交副作用）
    const config = target.config || {};
    if (config.crawlForms) {
      await this._crawlForms(target, points);
    }

    return points;
  }

  // 取目标页 HTML（经统一 HttpClient，失败返回 null 不中断发现）
  async _fetchHtml(url, config) {
    try {
      const res = await this.httpClient.request({
        method: 'GET',
        url,
        timeoutMs: config?.timeoutMs,
        retry: config?.retry,
        proxy: config?.proxy ?? false,
        auth: config?.auth ?? null,
        wafEvasion: config?.wafEvasion ?? null,
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
  _attr(tag, name) {
    const re = new RegExp(`${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]*))`, 'i');
    const m = tag.match(re);
    if (!m) return '';
    return m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : '';
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
