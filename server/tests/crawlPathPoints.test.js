// ============================================================================
// crawlPathPoints.test.js —— [D170] 爬取链接的路径段注入点
// ============================================================================
// 缺陷：爬取原先只从链接里抽 **query 键**。REST 形态的站内链接（`/api/users/5/orders`）
// 没有 query 参数 ⇒ 链接产出 0 个注入点 ⇒ 路径注入面在爬取路径上整体缺失
// （D154 的 --test-path 只作用于主目标 URL）。
// 修法：同一条链接触发 `_discoverPathPoints`（D154 的同一套段分类），整场最多
// CRAWLED_PATH_POINT_MAX 个爬取路径点（每点约 100-300 请求）。
// A/B 实测（e2e/detect-surface-lab 的 /path-links）：把上限改成 0（旧行为）→ 0 检出；
// 恢复后 2 条命中。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';

const parser = new TargetParser();

/** 直接调 _mergeLinkTarget，返回新增的注入点 */
function mergeLinks(links, config = { testPath: true }) {
  const points = [];
  const seen = new Set();
  const budget = { count: 0 };
  for (const rawUrl of links) {
    parser._mergeLinkTarget(rawUrl, points, seen, config, budget);
  }
  return { points, budget };
}

/** 直接调 _mergeEndpointTarget（浏览器捕获的 XHR 端点），返回新增的注入点 */
function mergeEndpoints(endpoints, config = { testPath: true }) {
  const points = [];
  const seen = new Set();
  const budget = { count: 0 };
  for (const rawUrl of endpoints) {
    parser._mergeEndpointTarget(rawUrl, points, seen, config, budget);
  }
  return { points, budget };
}

test('[D170] 爬取的 REST 链接（无 query）生成路径段注入点', () => {
  const { points } = mergeLinks(['http://shop.example.com/api/users/5/orders']);
  const pathPoints = points.filter((p) => p.location === 'path');
  assert.equal(pathPoints.length, 2, `中间数字段 5 与末段 orders 都该建点，实际：${pathPoints.map((p) => p.param)}`);
  assert.deepEqual(pathPoints.map((p) => p.param).sort(), ['5', 'orders']);
  for (const p of pathPoints) {
    assert.equal(p.actionUrl, 'http://shop.example.com/api/users/5/orders', '注入目标必须是链接本身');
    assert.equal(p.crawledUrl, p.actionUrl);
  }
});

test('[D170] 未开 --test-path 时爬取链接只出 query 点（零回归）', () => {
  const { points } = mergeLinks(['http://shop.example.com/api/users/5/orders?id=7'], {});
  assert.equal(points.filter((p) => p.location === 'path').length, 0);
  assert.deepEqual(points.map((p) => p.param), ['id']);
});

test('[D170] 预算封顶：链接很多时爬取路径点有上限', () => {
  const links = Array.from({ length: 10 }, (_, i) => `http://shop.example.com/api/users/${i + 1}/orders`);
  const { points, budget } = mergeLinks(links);
  const pathCount = points.filter((p) => p.location === 'path').length;
  assert.ok(pathCount <= 8, `爬取路径点应 ≤8，实际 ${pathCount}`);
  assert.ok(budget.count <= 8);
});

test('[D170] 去重：同一链接被重复收集不会重复建点', () => {
  const url = 'http://shop.example.com/api/users/5/orders';
  const { points } = mergeLinks([url, url, url]);
  assert.equal(points.filter((p) => p.location === 'path').length, 2, '同链接重复只建一次');
});

// ===== [D172] 浏览器捕获的 XHR 端点（与链接同族，发现来源不同）=====

test('[D172] XHR 端点（REST 形态、无 query）生成路径段点并标记 viaBrowser', () => {
  const { points } = mergeEndpoints(['http://shop.example.com/api/orders/5']);
  const pathPoints = points.filter((p) => p.location === 'path');
  // 段分类与 D154 同一套：末段 `5` 必测；`orders` 是纯路由中间段（不含数字）不测
  assert.equal(pathPoints.length, 1, `只有末段 5 该建点，实际：${pathPoints.map((p) => p.param)}`);
  for (const p of pathPoints) {
    assert.equal(p.param, '5');
    assert.equal(p.actionUrl, 'http://shop.example.com/api/orders/5');
    assert.equal(p.viaBrowser, true, '端点路径点应保留 viaBrowser 来源标记');
  }
});

test('[D172] 静态资源端点整体跳过（不信任上游过滤）', () => {
  const { points } = mergeEndpoints(['http://shop.example.com/app.js', 'http://shop.example.com/logo.png']);
  assert.equal(points.length, 0);
});

test('[D172] 未开 --test-path 时端点只出 query 点（零回归）', () => {
  const { points } = mergeEndpoints(['http://shop.example.com/api/orders/5?page=2'], {});
  assert.equal(points.filter((p) => p.location === 'path').length, 0);
  assert.deepEqual(points.map((p) => p.param), ['page']);
});

test('[D172] 端点与链接共用同一 path 预算（整场封顶）', () => {
  const points = [];
  const seen = new Set();
  const budget = { count: 0 };
  for (let i = 0; i < 5; i += 1) {
    parser._mergeEndpointTarget(`http://shop.example.com/api/orders/${i + 1}`, points, seen, { testPath: true }, budget);
  }
  parser._mergeLinkTarget('http://shop.example.com/api/users/9/orders', points, seen, { testPath: true }, budget);
  const pathCount = points.filter((p) => p.location === 'path').length;
  assert.ok(pathCount <= 8, `爬取路径点总数应 ≤8，实际 ${pathCount}`);
  assert.ok(budget.count <= 8);
});
