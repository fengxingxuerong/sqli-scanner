// 链接爬虫单元测试：mock HttpClient 取页，验证链接提取 / 同域过滤 / 去重 / 深度限制
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LinkCrawler, extractLinks } from '../src/engine/crawler.js';

// —— extractLinks 纯函数 ——

test('extractLinks 提取 a/script/link/iframe/img/form 链接并解析为绝对 URL', () => {
  const html = `<html>
  <a href="/list?id=1">相对</a>
  <a href="https://x.com/abs?p=2">绝对</a>
  <script src="/static/app.js"></script>
  <link href="/style/main.css" rel="stylesheet">
  <iframe src="/embed"></iframe>
  <img src="/img/logo.png">
  <form action="/search"><input name="q"></form>
  </html>`;
  const urls = extractLinks(html, 'https://x.com/').map((l) => l.url);
  assert.deepEqual(
    urls.sort(),
    [
      'https://x.com/abs?p=2',
      'https://x.com/embed',
      'https://x.com/img/logo.png',
      'https://x.com/list?id=1',
      'https://x.com/search',
      'https://x.com/static/app.js',
      'https://x.com/style/main.css',
    ].sort()
  );
});

test('extractLinks 跳过伪协议 / 纯锚点 / 空值', () => {
  const html = `<a href="javascript:void(0)">js</a>
  <a href="#section">锚点</a>
  <a href="mailto:x@y.com">邮件</a>
  <a>无 href</a>
  <a href=""></a>
  <a href="tel:123">电话</a>`;
  assert.deepEqual(extractLinks(html, 'https://x.com/'), []);
});

test('extractLinks 支持单引号 / 无引号属性', () => {
  const html = `<a href='/single?a=1'>单</a><a href=/bare>裸</a>`;
  const urls = extractLinks(html, 'https://x.com/').map((l) => l.url);
  assert.ok(urls.includes('https://x.com/single?a=1'));
  assert.ok(urls.includes('https://x.com/bare'));
});

test('extractLinks includeImages=false 时跳过 img', () => {
  const html = `<img src="/img/a.png"><a href="/page">p</a>`;
  const all = extractLinks(html, 'https://x.com/').map((l) => l.url);
  assert.ok(all.includes('https://x.com/img/a.png'));
  const noImg = extractLinks(html, 'https://x.com/', { includeImages: false }).map((l) => l.url);
  assert.ok(!noImg.includes('https://x.com/img/a.png'));
});

test('extractLinks 返回来源标签 tag', () => {
  const html = `<script src="/s.js"></script><a href="/a">a</a>`;
  const links = extractLinks(html, 'https://x.com/');
  assert.ok(links.some((l) => l.url === 'https://x.com/s.js' && l.tag === 'script'));
  assert.ok(links.some((l) => l.url === 'https://x.com/a' && l.tag === 'a'));
});

// —— LinkCrawler.crawl ——

// mock HttpClient：按 URL 返回预设 HTML；未命中页面抛错（模拟取页失败）
function mockHttp(pages) {
  return {
    async request({ url }) {
      const body = pages[url];
      if (body === undefined) throw new Error('not found: ' + url);
      return { data: body, status: 200 };
    },
  };
}

test('crawl 深度 1：仅抓目标页，links 含发现链接', async () => {
  const http = mockHttp({
    'https://x.com/': '<a href="/list?id=1">l</a>',
    'https://x.com/list?id=1': '<p>ok</p>',
  });
  const crawler = new LinkCrawler({ httpClient: http, maxPagesPerDepth: 10, maxTotalPages: 20 });
  const result = await crawler.crawl({ baseUrl: 'https://x.com/', config: {}, depth: 1 });
  // 深度 1 只取首页；/list 属一层链接页不抓
  assert.deepEqual(result.pages.map((p) => p.url), ['https://x.com/']);
  assert.ok(result.links.includes('https://x.com/list?id=1'));
});

test('crawl 深度 2：抓取目标页 + 一层链接页（item 属三层不抓）', async () => {
  const http = mockHttp({
    'https://x.com/': '<a href="/list?id=1">l</a>',
    'https://x.com/list?id=1': '<a href="/item?id=9">i</a>',
    'https://x.com/item?id=9': '<p>ok</p>',
  });
  const crawler = new LinkCrawler({ httpClient: http, maxPagesPerDepth: 10, maxTotalPages: 20 });
  const result = await crawler.crawl({ baseUrl: 'https://x.com/', config: {}, depth: 2 });
  const urls = result.pages.map((p) => p.url).sort();
  assert.deepEqual(urls, ['https://x.com/', 'https://x.com/list?id=1']);
});

test('crawl 深度 3：递归抓取到二层链接页', async () => {
  const http = mockHttp({
    'https://x.com/': '<a href="/list?id=1">l</a>',
    'https://x.com/list?id=1': '<a href="/item?id=9">i</a>',
    'https://x.com/item?id=9': '<p>ok</p>',
  });
  const crawler = new LinkCrawler({ httpClient: http, maxPagesPerDepth: 10, maxTotalPages: 20 });
  const result = await crawler.crawl({ baseUrl: 'https://x.com/', config: {}, depth: 3 });
  const urls = result.pages.map((p) => p.url).sort();
  assert.deepEqual(urls, ['https://x.com/', 'https://x.com/item?id=9', 'https://x.com/list?id=1']);
});

test('crawl 同域限制：跨域链接不爬取', async () => {
  const http = mockHttp({
    'https://x.com/': '<a href="https://evil.com/phish">外域</a><a href="/local">同域</a>',
    'https://x.com/local': '<p>ok</p>',
  });
  const crawler = new LinkCrawler({ httpClient: http, maxPagesPerDepth: 10, maxTotalPages: 20 });
  const result = await crawler.crawl({ baseUrl: 'https://x.com/', config: {}, depth: 2 });
  const urls = result.pages.map((p) => p.url);
  assert.ok(urls.includes('https://x.com/local'));
  assert.ok(!urls.includes('https://evil.com/phish'));
});

test('crawl 去重：同一链接只爬一次', async () => {
  let hits = 0;
  const http = {
    async request({ url }) {
      hits++;
      if (url === 'https://x.com/') return { data: '<a href="/p?id=1">a</a><a href="/p?id=1">b</a>', status: 200 };
      if (url === 'https://x.com/p?id=1') return { data: '<p>ok</p>', status: 200 };
      throw new Error('not found');
    },
  };
  const crawler = new LinkCrawler({ httpClient: http, maxPagesPerDepth: 10, maxTotalPages: 20 });
  const result = await crawler.crawl({ baseUrl: 'https://x.com/', config: {}, depth: 2 });
  // 首页 + /p?id=1 各一次（重复链接不二次请求）
  assert.equal(hits, 2);
  assert.equal(result.pages.length, 2);
  // links 去重：/p?id=1 只出现一次
  assert.equal(result.links.filter((u) => u === 'https://x.com/p?id=1').length, 1);
});

test('crawl 每深度页数上限：超过 maxPagesPerDepth 不抓', async () => {
  const links = Array.from({ length: 5 }, (_, i) => `<a href="/p${i}">${i}</a>`).join('');
  const pages = {};
  for (let i = 0; i < 5; i++) pages[`https://x.com/p${i}`] = '<p>ok</p>';
  const http = mockHttp({ 'https://x.com/': links, ...pages });
  const crawler = new LinkCrawler({ httpClient: http, maxPagesPerDepth: 2, maxTotalPages: 10 });
  const result = await crawler.crawl({ baseUrl: 'https://x.com/', config: {}, depth: 2 });
  // 深度 1 只取首页；深度 2 最多取 2 个 /p*
  const pCount = result.pages.filter((p) => p.url.startsWith('https://x.com/p')).length;
  assert.ok(pCount <= 2);
});

test('crawl 总页面上限：超过 maxTotalPages 停止', async () => {
  // 构造链条页 a0→a1→a2...（每页只有一个链接，深度大）
  const pages = {};
  for (let i = 0; i < 30; i++) {
    pages[`https://x.com/a${i}`] = i < 29 ? `<a href="/a${i + 1}">next</a>` : '<p>end</p>';
  }
  const http = mockHttp(pages);
  const crawler = new LinkCrawler({ httpClient: http, maxPagesPerDepth: 30, maxTotalPages: 5 });
  const result = await crawler.crawl({ baseUrl: 'https://x.com/a0', config: {}, depth: 30 });
  assert.ok(result.pages.length <= 5);
});

test('crawl 取页失败不阻断：单页抛错跳过，其余页正常', async () => {
  const http = mockHttp({
    'https://x.com/': '<a href="/broken">b</a><a href="/ok">o</a>',
    'https://x.com/ok': '<p>fine</p>',
  }); // /broken 未定义 → 抛错
  const crawler = new LinkCrawler({ httpClient: http, maxPagesPerDepth: 10, maxTotalPages: 20 });
  const result = await crawler.crawl({ baseUrl: 'https://x.com/', config: {}, depth: 3 });
  assert.ok(result.pages.some((p) => p.url === 'https://x.com/ok'));
  assert.ok(!result.pages.some((p) => p.url === 'https://x.com/broken'));
});

test('crawl depth=0 关闭：不发起任何请求', async () => {
  let called = false;
  const http = { async request() { called = true; return { data: '', status: 200 }; } };
  const crawler = new LinkCrawler({ httpClient: http });
  const result = await crawler.crawl({ baseUrl: 'https://x.com/', config: {}, depth: 0 });
  assert.deepEqual(result, { pages: [], links: [] });
  assert.equal(called, false);
});

test('crawl 非法 URL 直接返回空', async () => {
  const crawler = new LinkCrawler({ httpClient: mockHttp({}) });
  const result = await crawler.crawl({ baseUrl: 'not a url', config: {}, depth: 2 });
  assert.deepEqual(result, { pages: [], links: [] });
});
