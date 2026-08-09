import { URL } from 'url';
import { SecondOrderDetector } from './detectors/SecondOrderDetector.js';
import { httpClient as defaultHttpClient } from '../core/httpClient.js';

// 二阶触发页自动发现器（方向 1 核心）
// ─────────────────────────────────────────────────────────────────
// 现状缺口：后端 TargetParser 已能经 crawlForms 标记 isStorePoint（存储点自动发现就绪），
// 但**没有链接爬虫**——候选触发页只能由用户在 UI 手填（config.secondOrder.triggerUrls）。
// 本模块补齐"触发页自动发现"：从目标页 HTML 提取 <a href> 绝对链接作为候选触发页，
// 再用 SecondOrderDetector 的"存哨兵→读触发页→断言回显"链路验证做确认（证明该页确实
// 读出存储点写入的值并拼入响应），避免把无关页当触发页导致误报。
//
// 设计要点：
//   - extractLinks 为纯函数（可单测，不依赖网络）。
//   - discoverLinks 抓 baseUrl 取候选；confirmTriggers 复用 detector._store/_trigger 做哨兵回显确认。
//   - 全程受 secondOrder.enabled 门控（已在 ScanManager._runSecondOrder 把关），opt-in 默认关，
//     不阻断既有手填 triggerUrls 流程；为最小写代价，哨兵仅存一次、逐候选 GET 验证（1 POST + N GET）。
export class SecondOrderDiscovery {
  /**
   * @param {object} [httpClient] 统一 HttpClient（发现取页/验证经此；缺省用单例）
   */
  constructor(httpClient) {
    this.httpClient = httpClient || defaultHttpClient;
    // 复用 SecondOrderDetector 的 _store/_trigger（写存储点 / 读触发页），无需重写网络逻辑
    this.detector = new SecondOrderDetector();
  }

  /**
   * 纯函数：从 HTML 提取所有 <a href> 并解析为绝对 URL。
   * 去重；过滤非 http(s)（mailto/tel/javascript/锚点#/data:）、相对锚点、空 href。
   * @param {string} html 目标页 HTML
   * @param {string} baseUrl 用于解析相对链接的基准 URL（页面自身地址）
   * @returns {string[]} 去重后的绝对 http(s) URL 列表
   */
  extractLinks(html, baseUrl) {
    const out = new Set();
    if (!html || typeof html !== 'string') return [];
    const aRe = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
    let m;
    while ((m = aRe.exec(html))) {
      const tag = m[1] || '';
      const href = this._attr(tag, 'href');
      if (!href) continue;
      // 过滤明显非页面链接
      if (/^(mailto:|tel:|javascript:|#|data:)/i.test(href.trim())) continue;
      let abs;
      try {
        abs = new URL(href, baseUrl).toString();
      } catch {
        continue; // 无法解析为合法 URL 则跳过
      }
      if (!/^https?:\/\//i.test(abs)) continue; // 仅保留 http/https
      out.add(abs);
    }
    return [...out];
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

  /**
   * 发现候选触发页：抓 baseUrl 页面，提取 <a href> 绝对链接。
   * @param {import('./models.js').Target} target
   * @returns {Promise<string[]>} 候选触发页 URL 列表（去重、http(s)）
   */
  async discoverLinks(target) {
    const html = await this._fetchHtml(target.baseUrl, target.config);
    if (!html) return [];
    return this.extractLinks(html, target.baseUrl);
  }

  /**
   * 确认候选触发页是否真回显存储值（复用品二阶哨兵链路验证）。
   * 取首个存储点，存唯一哨兵一次，逐候选 GET 触发页断言回显；命中即确认为有效触发页。
   * 需至少一个 isStorePoint 点；否则返回空（理论上编排层已门控保证有存储点）。
   * @param {object} args { target, config, storePoints, candidates }
   * @returns {Promise<string[]>} 确认会回显存储值的触发页 URL 列表
   */
  async confirmTriggers({ target, config, storePoints, candidates }) {
    const storePoint = Array.isArray(storePoints) ? storePoints.find((p) => p && p.isStorePoint) : null;
    if (!storePoint || !Array.isArray(candidates) || candidates.length === 0) return [];
    const sentinel = `__so_disc_${Math.random().toString(36).slice(2, 10)}__`;
    const ctxBase = { httpClient: this.httpClient, target, config };
    const ctx = { ...ctxBase, point: storePoint, dbms: storePoint.dbms, triggerUrl: '' };
    // 仅存一次哨兵（最小写代价）；后续逐候选 GET 验证该哨兵是否被读出回显
    try {
      await this.detector._store(this.httpClient, ctx, sentinel);
    } catch {
      return []; // 存储失败（如 CSRF/提交异常）→ 无法确认，返回空不误判
    }
    const confirmed = [];
    for (const url of candidates) {
      try {
        const body = await this.detector._trigger(this.httpClient, ctx, url);
        if (String(body).includes(sentinel)) confirmed.push(url);
      } catch {
        /* 单个候选失败不影响其余候选确认 */
      }
    }
    return confirmed;
  }

  /**
   * 端到端发现：候选链接 + 哨兵回显确认。
   * @param {object} args { target, config, storePoints }
   * @returns {Promise<{ candidates: string[]; confirmed: string[] }>}
   */
  async run({ target, config, storePoints }) {
    const candidates = await this.discoverLinks(target);
    const confirmed = await this.confirmTriggers({ target, config, storePoints, candidates });
    return { candidates, confirmed };
  }

  // 从标签字符串中取某属性值（兼容双引号/单引号/无引号）
  _attr(tag, name) {
    const re = new RegExp(`${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]*))`, 'i');
    const m = tag.match(re);
    if (!m) return '';
    return m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : '';
  }
}

export default SecondOrderDiscovery;
