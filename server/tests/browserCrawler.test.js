// ============================================================================
// browserCrawler.test.js — headless 浏览器爬取（实战分析 P1-4，批次13）
// ============================================================================
// 四层覆盖：
//   ① pickEndpoints / pickSameOriginLinks 纯函数（同域/静态资源/去重/协议过滤）
//   ② TargetParser.discover 集成（收集器经 _browserCollector 注入替身）：
//      端点 query → url 点（viaBrowser 溯源）、无参数端点不产点、开关关闭零调用
//   ③ 优雅降级：playwright/浏览器不可用（收集器抛 BrowserUnavailable）→ 回落 HTTP 爬虫
//   ④ 真浏览器 smoke：本地 SPA 页 fetch 接口 → collectRendered 捕获端点
//     （浏览器缺失按 SKIP 口径早退，不假绿）
// ============================================================================
import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { pickEndpoints, pickSameOriginLinks, collectRendered, BrowserUnavailable } from '../src/engine/discovery/browserCrawler.js';
import { TargetParser } from '../src/engine/TargetParser.js';
import { LinkCrawler } from '../src/engine/crawler.js';

// ─── ① 纯函数 ───
describe('[browserCrawler] pickEndpoints 纯函数', () => {
  const BASE = 'http://spa.local/app';

  test('同域 XHR 端点保留、跨域/协议/静态资源/自身剔除、去重去 hash', () => {
    const out = pickEndpoints(
      [
        'http://spa.local/api/items?page=1', // 命中
        'http://spa.local/api/items?page=1', // 去重
        'http://spa.local/api/items?page=2#frag', // hash 归一后仍不同 query → 保留
        'http://cdn.example.com/lib.js', // 跨域
        'ftp://spa.local/x', // 协议
        'http://spa.local/assets/app.js?ver=1', // 静态资源
        'http://spa.local/app', // 入口页自身
        'http://spa.local/app#section', // 自身（去 hash）
      ],
      BASE
    );
    assert.deepEqual(out, [
      'http://spa.local/api/items?page=1',
      'http://spa.local/api/items?page=2',
    ]);
  });

  test('非法 URL / 非法 baseUrl 安全返回', () => {
    assert.deepEqual(pickEndpoints(['::::'], 'http://ok.local/'), []);
    assert.deepEqual(pickEndpoints(['http://ok.local/a?b=1'], '::::'), []);
  });

  test('pickSameOriginLinks：相对链接按 base 解析、跨域剔除、去 hash 去重', () => {
    const out = pickSameOriginLinks(
      ['/list?id=7', '/list?id=7#top', 'https://other.local/x', 'mailto:a@b.c'],
      'http://spa.local/app'
    );
    assert.deepEqual(out, ['http://spa.local/list?id=7']);
  });
});

// ─── ② TargetParser 集成（注入收集器替身） ───
describe('[browserCrawler] TargetParser.discover 集成', () => {
  function makeTarget(config) {
    return {
      mode: 'http',
      baseUrl: 'http://spa.local/app',
      method: 'GET',
      bodyParams: {},
      cookieParams: {},
      headerParams: {},
      config,
    };
  }

  test('crawlBrowser=true：端点 query 合成 url 点（viaBrowser 溯源 + actionUrl 指向端点）', async () => {
    const collectorCalls = [];
    const parser = new TargetParser(undefined, new LinkCrawler({}));
    parser._browserCollector = async (opts) => {
      collectorCalls.push(opts);
      return {
        pages: [{ url: 'http://spa.local/app', html: '<html>shell</html>' }],
        links: ['http://spa.local/app'],
        endpoints: ['http://spa.local/api/items?page=1&size=20', 'http://spa.local/assets/app.js?ver=1'],
        browser: 'msedge',
      };
    };
    const points = await parser.discover(makeTarget({ crawlBrowser: true }));
    assert.equal(collectorCalls.length, 1);
    const mined = points.filter((p) => p.viaBrowser === true);
    // 端点 page/size 两个参数成点；静态资源 app.js 被纯函数层剔除
    assert.deepEqual(mined.map((p) => p.param).sort(), ['page', 'size']);
    assert.ok(mined.every((p) => p.location === 'url'));
    assert.ok(mined.every((p) => p.actionUrl === 'http://spa.local/api/items?page=1&size=20'));
  });

  test('无 query 的端点不产点（没有可放注入值的位置）', async () => {
    const parser = new TargetParser(undefined, new LinkCrawler({}));
    parser._browserCollector = async () => ({
      pages: [{ url: 'http://spa.local/app', html: '' }],
      links: [],
      endpoints: ['http://spa.local/api/session'],
      browser: 'msedge',
    });
    const points = await parser.discover(makeTarget({ crawlBrowser: true }));
    assert.equal(points.filter((p) => p.viaBrowser === true).length, 0);
  });

  test('默认关闭：收集器零调用（零行为变化）', async () => {
    let called = 0;
    const parser = new TargetParser(undefined, new LinkCrawler({}));
    parser._browserCollector = async () => {
      called += 1;
      return { pages: [], links: [], endpoints: [] };
    };
    await parser.discover(makeTarget({}));
    await parser.discover(makeTarget({ crawlBrowser: false }));
    assert.equal(called, 0);
  });

  test('onlyPoint / 精确标记（值尾 *）时跳过浏览器爬取（用户显式意图优先）', async () => {
    let called = 0;
    const parser = new TargetParser(undefined, new LinkCrawler({}));
    parser._browserCollector = async () => {
      called += 1;
      return { pages: [], links: [], endpoints: [] };
    };
    // onlyPoint 必须匹配到真实存在的点位（否则 discover 在 _applyOnlyPoint 抛错），
    // 这里直构 target 给带 id=1 的 URL 使 url:id 点位存在
    const mk = (baseUrl, config) => ({
      mode: 'http',
      baseUrl,
      method: 'GET',
      bodyParams: {},
      cookieParams: {},
      headerParams: {},
      config,
    });
    await parser.discover(mk('http://spa.local/app?id=1', { crawlBrowser: true, onlyPoint: { location: 'url', param: 'id' } }));
    await parser.discover(mk('http://spa.local/app?id=1*', { crawlBrowser: true }));
    assert.equal(called, 0);
  });
});

// ─── ③ 优雅降级 ───
describe('[browserCrawler] 优雅降级', () => {
  test('playwright/浏览器不可用 → 回落 HTTP 爬虫（链接点位照常产出）', async () => {
    // HTTP 爬虫替身：返回一个带参数的同域链接
    const fakeCrawler = {
      async crawl({ baseUrl }) {
        return { pages: [], links: [`${baseUrl}?from=crawler=1`.replace('=1', ''), ] };
      },
    };
    const parser = new TargetParser(undefined, /** @type {any} */ (fakeCrawler));
    parser._browserCollector = async () => {
      throw new BrowserUnavailable('playwright 未安装');
    };
    const points = await parser.discover({
      mode: 'http',
      baseUrl: 'http://spa.local/app',
      method: 'GET',
      bodyParams: {},
      cookieParams: {},
      headerParams: {},
      config: { crawlBrowser: true },
    });
    // 降级路径：HTTP 爬虫发现的 from 参数成点（无 viaBrowser 标记）
    const fromPoint = points.find((p) => p.param === 'from');
    assert.ok(fromPoint, '降级后 HTTP 爬虫点位应产出');
    assert.equal(fromPoint.viaBrowser, undefined);
    assert.ok(!points.some((p) => p.viaBrowser === true));
  });
});

// ─── ④ 真浏览器 smoke（浏览器缺失按 SKIP 口径早退，不假绿） ───
describe('[browserCrawler] 真浏览器 smoke', () => {
  let server;
  let baseUrl;
  let apiHits = 0;

  before(async () => {
    server = http.createServer((req, res) => {
      const u = new URL(req.url, 'http://x');
      if (u.pathname === '/app') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        // SPA 形态：静态 HTML 无 /api 链接，接口只能由 JS fetch 触发
        res.end(`<!doctype html><html><body><script>
          fetch('/api/items?page=1').then(r => r.json()).catch(() => {});
        </script><a href="/list?id=7">list</a></body></html>`);
        return;
      }
      if (u.pathname === '/api/items') {
        apiHits += 1;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('[]');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<html><body>list page</body></html>');
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}/app`;
  });

  after(async () => {
    await new Promise((resolve) => server.close(resolve));
  });

  test('渲染入口页：捕获 JS fetch 的接口端点与渲染后链接', async () => {
    // 浏览器不可用 → SKIP（与靶场同口径：缺依赖显式跳过，不假绿）
    let browserName;
    try {
      const { launchBrowser } = await import('../src/engine/discovery/browserCrawler.js');
      const launched = await launchBrowser({});
      await launched.browser.close();
      browserName = launched.name;
    } catch (e) {
      if (e instanceof BrowserUnavailable) {
        console.log(`  [SKIP] 无可用浏览器（${e.message}）`);
        return;
      }
      throw e;
    }
    assert.ok(browserName, `应探测到浏览器：${browserName}`);
    const result = await collectRendered({ baseUrl, depth: 0, maxPages: 3, pageTimeoutMs: 10000 });
    // ① XHR 端点被捕获（SPA 主发现面）
    assert.ok(
      result.endpoints.some((u) => u.includes('/api/items?page=1')),
      `应捕获 /api/items?page=1：${JSON.stringify(result.endpoints)}`
    );
    assert.ok(apiHits >= 1, '目标应真实收到 fetch 请求');
    // ② 渲染后链接被捕获（JS 之外这里恰好是静态 <a>，链接层回归）
    assert.ok(result.links.some((u) => u.includes('/list?id=7')), JSON.stringify(result.links));
  });
});
