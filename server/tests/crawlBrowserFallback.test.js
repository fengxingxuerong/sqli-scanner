// ============================================================================
// server/tests/crawlBrowserFallback.test.js —— [D124 2026-10-21]
//
// 契约：`--crawl-browser`（config.crawlBrowser=true）在 playwright/浏览器不可用时会**降级**
// 为 HTTP 爬虫（设计如此，不阻断发现阶段），但这个降级事实必须进报告，
// 不能只活在日志里。
//
// 背景（这是本仓「以为开了、其实没开」的第 N 次同形）：
//   playwright 配在根 `package.json` 的 **devDependencies** ⇒ 生产部署
//   （`npm install --omit=dev`）里没有它。SPA 目标用 `--crawl-browser` 时，
//   浏览器渲染从未发生，XHR/fetch 接口面整体丢失，而报告只字不提。
//
// 判据：
//   ① 不可用时 ⇒ report.summary.crawlBrowserFallback 存在且 reason 非空 + hint 有提示；
//   ② 可用时   ⇒ 不得出现该字段（否则正常扫描会被刷上假的「降级」警示）；
//   ③ 未开启   ⇒ 不得出现该字段。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { ScanManager } from '../src/engine/ScanManager.js';
import { BrowserUnavailable } from '../src/engine/discovery/browserCrawler.js';

process.env.SSRF_ALLOW_PRIVATE = '1';

// ⚠ 本机实测：这台开发机上装了 msedge，浏览器爬取**真的能跑起来** ⇒ 无法靠「无浏览器环境」
// 制造降级。必须注入一个必然失败的替身（与 TargetParser 既有测试的 `_browserCollector`
// 注入点同源），否则本用例会变成「绿是因为场景根本没触发」，那是最坏的一种假绿。
// ⚠ 注入点必须是**实例**而非原型：TargetParser 构造函数里有 `this._browserCollector = null`，
// 挂原型会被实例属性遮蔽（本轮实测踩过：替身没生效，日志里 msedge 照常渲染成功，
// 用例红得莫名其妙）。ScanManager 暴露 `this.parser`，直接改实例字段最稳。
function forceBrowserUnavailable(sm) {
  sm.parser._browserCollector = async () => {
    throw new BrowserUnavailable('playwright 未安装（引擎可选依赖；HTTP 爬虫不受影响）');
  };
}

function startShellLab() {
  // 极简 SPA 空壳：静态 HTML 里没有参数、没有链接，XHR 接口也发现不了
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end('<!doctype html><html><body><div id="app"></div></body></html>');
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

async function waitDone(sm, id, timeoutMs = 60000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) return s;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error('scan timeout');
}

const baseCfg = {
  techniques: ['boolean'],
  level: 1,
  risk: 1,
  concurrency: 1,
  ratePerSec: 400,
  prefilter: false,
  skipStatic: false,
  smart: false,
};

test('D124-①: 浏览器不可用降级时，报告显式标注（不只写日志）', async () => {
  const lab = await startShellLab();
  try {
    const { port } = lab.address();
    const sm = new ScanManager();
    forceBrowserUnavailable(sm);
    const id = await sm.start({
      url: `http://127.0.0.1:${port}/?id=1`,
      config: { ...baseCfg, crawlBrowser: true }, // 无浏览器环境下必然降级
    });
    const state = await waitDone(sm, id);
    assert.notEqual(state.status, 'error', state.error || 'scan errored');
    const summary = sm.getReport(id).summary || {};

    assert.ok(
      summary.crawlBrowserFallback,
      `应记录降级事实，实际 summary keys=${Object.keys(summary).join(',')}`
    );
    assert.equal(summary.crawlBrowserFallback.degradedTo, 'http-crawler');
    assert.ok(
      String(summary.crawlBrowserFallback.reason || '').length > 0,
      '降级原因不能为空（要能指路去哪修）'
    );
    assert.match(String(summary.crawlBrowserHint || ''), /降级|HTTP 爬虫/);
    assert.match(
      String(summary.crawlBrowserHint || ''),
      /未检出/,
      '必须点明「未检出」不能读成「这些接口没有注入」'
    );
  } finally {
    lab.close();
  }
});

test('D124-②: 未开启 --crawl-browser 时不出现降级字段（不刷假警示）', async () => {
  const lab = await startShellLab();
  try {
    const { port } = lab.address();
    const sm = new ScanManager();
    const id = await sm.start({
      url: `http://127.0.0.1:${port}/?id=1`,
      config: { ...baseCfg },
    });
    const state = await waitDone(sm, id);
    assert.notEqual(state.status, 'error', state.error || 'scan errored');
    const summary = sm.getReport(id).summary || {};
    assert.equal(
      summary.crawlBrowserFallback,
      undefined,
      `没开浏览器爬取就不该有降级标注，实际=${JSON.stringify(summary.crawlBrowserFallback)}`
    );
  } finally {
    lab.close();
  }
});
