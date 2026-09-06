// TargetParser 链接爬取集成测试：crawlDepth>0 时产出新增注入点，并与既有 points 合并去重
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import { createTarget } from '../src/engine/models.js';

// mock HttpClient：按 URL 返回预设 HTML；未命中抛错
function mockHttp(pages) {
  return {
    async request({ url }) {
      const body = pages[url];
      if (body === undefined) throw new Error('not found: ' + url);
      return { data: body, status: 200 };
    },
  };
}

test('crawlDepth 默认关闭（0）：不触发链接爬取', async () => {
  const parser = new TargetParser(mockHttp({}));
  const target = createTarget({ url: 'https://x.com/page', method: 'GET' });
  assert.equal(target.config.crawlDepth, 0);
  const points = await parser.discover(target);
  assert.equal(points.length, 0);
});

test('crawlDepth=1：首页发现的链接 URL 的 query 参数并入注入点', async () => {
  const http = mockHttp({
    'https://x.com/page': '<a href="/list?page=2&size=50">下一页</a>',
  });
  const parser = new TargetParser(http);
  const target = createTarget({ url: 'https://x.com/page', method: 'GET', config: { level: 5 } });
  target.config.crawlDepth = 1;
  const points = await parser.discover(target);
  // 首页无 query，但链接 /list?page=2&size=50 的 query 参数成为注入点（对标 sqlmap 不抓链接页也测试其参数）
  const pagePoint = points.find((p) => p.param === 'page');
  const sizePoint = points.find((p) => p.param === 'size');
  assert.ok(pagePoint);
  assert.equal(pagePoint.location, 'url');
  assert.equal(pagePoint.originalValue, '2');
  assert.equal(pagePoint.actionUrl, 'https://x.com/list?page=2&size=50');
  assert.ok(sizePoint);
  assert.equal(sizePoint.originalValue, '50');
});

test('crawlDepth=2：抓取一层链接页并发现更深链接的 query 参数', async () => {
  const http = mockHttp({
    'https://x.com/page': '<a href="/list?page=2&size=50">下一页</a>',
    'https://x.com/list?page=2&size=50': '<a href="/detail?id=9">详情</a>',
  });
  const parser = new TargetParser(http);
  const target = createTarget({ url: 'https://x.com/page', method: 'GET', config: { level: 5 } });
  target.config.crawlDepth = 2;
  const points = await parser.discover(target);
  const pagePoint = points.find((p) => p.param === 'page');
  const idPoint = points.find((p) => p.param === 'id');
  // 一层链接页参数（page/size）与更深链接参数（id）均被发现
  assert.ok(pagePoint);
  assert.equal(pagePoint.actionUrl, 'https://x.com/list?page=2&size=50');
  assert.ok(idPoint);
  assert.equal(idPoint.originalValue, '9');
});

test('与既有 points 合并去重：同 URL+参数不重复加', async () => {
  // 首页自带 ?page=2，爬取到的链接也含同页同参数 → 只保留一个
  const http = mockHttp({
    'https://x.com/page?page=2': '<a href="/page?page=2">自身</a><a href="/other?x=1">其它</a>',
    'https://x.com/other?x=1': '<p>ok</p>',
  });
  const parser = new TargetParser(http);
  const target = createTarget({ url: 'https://x.com/page?page=2', method: 'GET', config: { level: 5 } });
  target.config.crawlDepth = 2;
  const points = await parser.discover(target);
  const pages = points.filter((p) => p.param === 'page');
  assert.equal(pages.length, 1);
  const xPoint = points.find((p) => p.param === 'x');
  assert.ok(xPoint);
  assert.equal(xPoint.location, 'url');
});

test('同域限制：跨域链接的 query 不生成注入点', async () => {
  const http = mockHttp({
    'https://x.com/page': '<a href="https://evil.com/steal?id=1">外域</a>',
  });
  const parser = new TargetParser(http);
  const target = createTarget({ url: 'https://x.com/page', method: 'GET', config: { level: 5 } });
  target.config.crawlDepth = 3;
  const points = await parser.discover(target);
  assert.ok(!points.some((p) => p.param === 'id'));
});

test('爬取失败不阻断：目标页取不到也正常返回既有发现', async () => {
  const parser = new TargetParser(mockHttp({})); // 所有 URL 未命中 → 取页失败
  const target = createTarget({ url: 'https://x.com/page', method: 'GET', bodyParams: { a: '1' }, config: { level: 5 } });
  target.config.crawlDepth = 2;
  const points = await parser.discover(target);
  // 原 body 参数仍被发现
  assert.ok(points.some((p) => p.param === 'a' && p.location === 'body'));
});

test('crawlDepth + crawlForms 同时开启：爬取页表单也被解析为 body 点', async () => {
  const http = mockHttp({
    'https://x.com/page': '<a href="/search">搜</a>',
    'https://x.com/search': '<form method="GET" action="/do-search"><input name="q" value=""></form>',
  });
  const parser = new TargetParser(http);
  const target = createTarget({ url: 'https://x.com/page', method: 'GET', config: { level: 5 } });
  target.config.crawlDepth = 2;
  target.config.crawlForms = true;
  const points = await parser.discover(target);
  const q = points.find((p) => p.param === 'q');
  assert.ok(q);
  assert.equal(q.location, 'body');
  assert.equal(q.formMethod, 'GET');
  assert.equal(q.actionUrl, 'https://x.com/do-search');
});

test('构造签名兼容：crawler 缺省自动创建（不抛）', () => {
  assert.doesNotThrow(() => new TargetParser());
});
