// ============================================================================
// browserEgressGuard.test.js —— [D132 2026-10-23] 渲染进程的 SSRF 闸门
//
// 为什么要单独判这道：`SECURITY.md` 曾写「所有出站请求都过 core/httpClient.js」，
// 而 headless 浏览器一旦 `page.goto()` 就会自行请求页面里的**任意**子资源
// （img/script/fetch），这些请求完全绕开 httpClient。若目标页面（或被注入的内容）
// 引用 `http://169.254.169.254/latest/meta-data/`，扫描器所在机器就会替攻击者发请求。
//
// 判据：
//   · 内网/回环/云元数据 ⇒ 放行？不 —— 必须拦（false）
//   · 非 http(s)（data:/blob:/about:）⇒ 浏览器不出站，放行（true）
//   · 同一 host 只解析一次（子资源动辄几十个，不能每个都做 DNS）
//   · 解析不出 host / 校验抛错 ⇒ fail-closed 拦
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeBrowserEgressGuard } from '../src/engine/discovery/browserCrawler.js';

test('内网/云元数据地址必须被拦，公网地址放行', async () => {
  const blocked = [/169\.254\.169\.254/, /^https?:\/\/127\./, /^https?:\/\/10\./, /^https?:\/\/192\.168\./];
  const assertSafe = async (url) => {
    if (blocked.some((re) => re.test(url))) throw new Error('egress blocked');
    return true;
  };
  const guard = makeBrowserEgressGuard(assertSafe);
  assert.equal(await guard('http://169.254.169.254/latest/meta-data/'), false);
  assert.equal(await guard('http://127.0.0.1:8080/x.png'), false);
  assert.equal(await guard('https://10.0.0.5/secret'), false);
  assert.equal(await guard('https://cdn.example.com/app.js'), true);
  assert.equal(await guard('https://example.com/api/items?id=1'), true);
});

test('非 http(s) 协议不出站：直接放行（data:/blob:/about:）', async () => {
  let called = 0;
  const guard = makeBrowserEgressGuard(async () => {
    called += 1;
    return true;
  });
  assert.equal(await guard('data:text/html,<h1>x</h1>'), true);
  assert.equal(await guard('blob:https://example.com/abc-123'), true);
  assert.equal(await guard('about:blank'), true);
  assert.equal(called, 0, '非网络协议不应触发 DNS/egress 校验');
});

test('按 host 缓存：同一 host 的多个子请求只校验一次', async () => {
  const seen = [];
  const guard = makeBrowserEgressGuard(async (url) => {
    seen.push(url);
    return true;
  });
  await Promise.all([
    guard('https://cdn.example.com/a.js'),
    guard('https://cdn.example.com/b.css'),
    guard('https://cdn.example.com/c.png'),
  ]);
  await guard('https://cdn.example.com/d.woff2');
  assert.equal(seen.length, 1, `同一 host 应只校验一次，实际 ${seen.length} 次：${seen.join(', ')}`);
  // 不同 host 各校验一次
  await guard('https://other.example.com/x.js');
  assert.equal(seen.length, 2);
});

test('校验抛错 / URL 解析失败 ⇒ fail-closed 拦（不静默放行）', async () => {
  const guard = makeBrowserEgressGuard(async () => {
    throw new Error('dns failure');
  });
  assert.equal(await guard('https://boom.example.com/x'), false);
  assert.equal(await guard('http://'), false, '解析不出 host 必须拦');
});

test('并发判定共享同一次校验（不会把一次失败判成多次失败）', async () => {
  let calls = 0;
  const guard = makeBrowserEgressGuard(async () => {
    calls += 1;
    await new Promise((r) => setTimeout(r, 5));
    return true;
  });
  const results = await Promise.all([
    guard('https://h1.example.com/a'),
    guard('https://h1.example.com/b'),
    guard('https://h1.example.com/c'),
  ]);
  assert.deepEqual(results, [true, true, true]);
  assert.equal(calls, 1);
});
