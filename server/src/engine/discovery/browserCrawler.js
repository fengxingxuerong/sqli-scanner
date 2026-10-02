// ============================================================================
// browserCrawler.js — headless 浏览器爬取（opt-in crawlBrowser，实战分析 P1-4）
//
// 解决什么问题：crawler.js 是纯正则 HTML 爬虫（6 组标签属性），对 React/Vue/Angular
// 的 SPA 目标基本抓瞎——路由在前端、数据接口靠 XHR/fetch，静态 HTML 里只有空壳
// index.html，/api/* 全丢。本模块用 Playwright 渲染页面后收集三类发现：
//   ① 渲染后的同域链接（a[href]，含 JS 动态插入的）→ 与 HTTP 爬虫同一合并路径成点位
//   ② 页面实际发出的 XHR/fetch 请求 URL（page.on('request')）→ 这是 SPA 的主发现面：
//      接口 URL 的 query 参数直接成为注入点，无需人工抓包导 HAR
//   ③ 渲染后 DOM 的 HTML（供 crawlForms 表单解析复用——JS 渲染出来的表单 HTTP 爬虫看不见）
//
// 依赖与降级：Playwright 在 devDependencies（引擎动态 import，未安装/无浏览器时抛
// BrowserUnavailable，由调用方降级为 HTTP 爬取——不阻断发现阶段）。浏览器探测顺序
// 沿 e2e/fullchain-lab 的既定模式：msedge → chrome → playwright 自带 chromium
//（免下载浏览器：前两者用系统安装的 Edge/Chrome）。
//
// 资源安全：总页数预算 maxPages（默认 10）、每页导航超时 pageTimeoutMs（默认 15s）、
// 只入队同域链接、browser 在 finally 中关闭。所有 URL 处理都是纯函数（pickEndpoints）
// 可独立测试；收集器本身通过依赖注入可被测试替身替换。
// ============================================================================
import { URL } from 'url';

export class BrowserUnavailable extends Error {
  constructor(message) {
    super(message);
    this.name = 'BrowserUnavailable';
  }
}

/** 静态资源扩展名（接口 URL 过滤：XHR 拉的 js/css/图片不是注入面） */
const STATIC_RE = /\.(js|mjs|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|webp|mp4|webm)(\?|$)/i;

/**
 * [纯函数] 静态资源判定（供 pickEndpoints 与 TargetParser 合并层共用——注入式收集器
 * 可能绕过 pickEndpoints，合并层必须自己把关，不信任上游过滤）。
 * @param {URL} u 已解析的 URL 对象
 */
export function isStaticEndpoint(u) {
  return STATIC_RE.test(u.pathname);
}

/**
 * [纯函数] 从浏览器捕获的请求 URL 里挑出「值得生成注入点的接口端点」：
 * 同域 + http(s) + 非静态资源 + 去重（去 hash）+ 排除入口页自身。
 * @param {string[]} requestUrls page.on('request') 收集的 URL 全量
 * @param {string} baseUrl 入口页 URL（同域基准 + 自身排除）
 * @returns {string[]}
 */
export function pickEndpoints(requestUrls, baseUrl) {
  let base;
  try {
    base = new URL(baseUrl);
  } catch {
    return [];
  }
  const seen = new Set();
  const out = [];
  for (const raw of requestUrls || []) {
    let u;
    try {
      u = new URL(raw);
    } catch {
      continue;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
    if (u.host !== base.host) continue; // 只收同域（跨域请求不在授权面内）
    u.hash = '';
    const norm = u.toString();
    if (norm === base.toString()) continue; // 入口页自身
    if (isStaticEndpoint(u)) continue;
    if (seen.has(norm)) continue;
    seen.add(norm);
    out.push(norm);
  }
  return out;
}

/** [纯函数] 同域链接归一（去 hash、去重），供 BFS 入队 */
export function pickSameOriginLinks(hrefUrls, baseUrl) {
  let base;
  try {
    base = new URL(baseUrl);
  } catch {
    return [];
  }
  const seen = new Set();
  const out = [];
  for (const raw of hrefUrls || []) {
    let u;
    try {
      u = new URL(raw, base);
    } catch {
      continue;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
    if (u.host !== base.host) continue;
    u.hash = '';
    const norm = u.toString();
    if (seen.has(norm)) continue;
    seen.add(norm);
    out.push(norm);
  }
  return out;
}

/**
 * 探测并启动浏览器（msedge → chrome → playwright 自带 chromium）。
 * @returns {Promise<{browser: object, name: string}>} 全部不可用抛 BrowserUnavailable
 */
export async function launchBrowser({ headless = true } = {}) {
  let chromium;
  try {
    ({ chromium } = await import('playwright'));
  } catch {
    throw new BrowserUnavailable('playwright 未安装（引擎可选依赖；HTTP 爬虫不受影响）');
  }
  for (const channel of ['msedge', 'chrome']) {
    try {
      const b = await chromium.launch({ channel, headless });
      return { browser: b, name: channel };
    } catch {
      /* 系统未装该浏览器，试下一个 */
    }
  }
  try {
    const b = await chromium.launch({ headless });
    return { browser: b, name: 'chromium' };
  } catch {
    throw new BrowserUnavailable('无可用浏览器（msedge/chrome 均未安装，playwright 自带 chromium 未执行 install）');
  }
}

/**
 * 渲染收集主入口：从 baseUrl 出发 BFS 渲染（深度 depth），收集渲染后链接、
 * XHR/fetch 端点与页面 HTML。
 * @param {object} opts
 * @param {string} opts.baseUrl 入口 URL
 * @param {number} [opts.depth] 链接 BFS 深度（0 = 只渲染入口页；1+ 追进同域链接）
 * @param {number} [opts.maxPages] 总页数预算（含入口页）
 * @param {number} [opts.pageTimeoutMs] 每页导航超时
 * @param {object} [opts.launch] 测试注入：{ browser, name }（跳过真实启动）
 * @param {(msg: string) => void} [opts.log]
 * @returns {Promise<{pages: {url: string, html: string}[], links: string[], endpoints: string[], browser: string}>}
 */
export async function collectRendered(opts) {
  const {
    baseUrl,
    depth = 0,
    maxPages = 10,
    pageTimeoutMs = 15000,
    launch = null,
    log = () => {},
  } = opts;
  const launched = launch ? launch : await launchBrowser({});
  const { browser, name } = launched;
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();

  const pages = [];
  const allRequests = [];
  const queue = [baseUrl];
  const enqueued = new Set(queue);
  try {
    page.on('request', (req) => {
      try {
        allRequests.push(req.url());
      } catch {
        /* 忽略取 URL 失败的请求事件 */
      }
    });
    while (queue.length > 0 && pages.length < maxPages) {
      // 队列非空由 while 条件保证；shift() 的 `| undefined` 只是 TS 看不到该不变式
      const url = /** @type {string} */ (queue.shift());
      try {
        await page.goto(url, { timeout: pageTimeoutMs, waitUntil: 'load' });
        // 等 XHR/fetch 有机会发出：load 之后给网络一小段静默期（networkidle 在长轮询页会卡满，故手动等）
        await page.waitForLoadState('networkidle', { timeout: Math.min(3000, pageTimeoutMs) }).catch(() => {});
        const html = await page.content();
        pages.push({ url, html });
        // 渲染后链接入队（深度预算：pages.length 达 maxPages 自然截断；depth 控制入队层数）
        if (pages.length <= depth * maxPages + 1 || depth > 0) {
          const hrefs = await page.$$eval('a[href]', (as) => as.map((a) => a.getAttribute('href') || ''));
          for (const link of pickSameOriginLinks(hrefs, url)) {
            if (!enqueued.has(link) && pages.length + queue.length < maxPages) {
              enqueued.add(link);
              queue.push(link);
            }
          }
        }
      } catch {
        /* 单页导航失败跳过（超时/网络错误），继续下一页 */
      }
    }
  } finally {
    await context.close().catch(() => {});
    await browser.close().catch(() => {});
  }
  const endpoints = pickEndpoints(allRequests, baseUrl);
  log(`[crawlBrowser] 渲染 ${pages.length} 页（${name}）：链接页 ${pages.length}，捕获同域请求 ${allRequests.length} 个 → 接口端点 ${endpoints.length} 个`);
  return { pages, links: pages.map((p) => p.url), endpoints, browser: name };
}
