// --level 注入点位置扩展（对标 sqlmap --level）分级门控单测
// sqlmap 语义：1=仅 URL/Body；2=+Cookie；3=+显式 Header 与自动 User-Agent/Referer。
// 与 --risk（测多危险）正交。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import { createTarget } from '../src/engine/models.js';

const parser = new TargetParser();

// level 缺省（=1）：即便提供了 Cookie/Header 也不测，避免对会话凭据盲目注入
test('level=1 默认不发现 Cookie/Header 注入点', async () => {
  const target = createTarget({
    url: 'http://example.com',
    config: { level: 1 },
    cookieParams: { sid: '1' },
    headerParams: { 'X-Forwarded-For': '2' },
  });
  const points = await parser.discover(target);
  assert.equal(points.length, 0);
});

// config 缺失 level 字段时退化为默认 level=1
test('level 未配置退化为 1（不测 Cookie/Header）', async () => {
  const target = createTarget({
    url: 'http://example.com',
    cookieParams: { sid: '1' },
  });
  const points = await parser.discover(target);
  assert.equal(points.length, 0);
});

test('level=2 发现 Cookie 但不测 Header', async () => {
  const target = createTarget({
    url: 'http://example.com',
    config: { level: 2 },
    cookieParams: { sid: '1' },
    headerParams: { 'X-Forwarded-For': '2' },
  });
  const points = await parser.discover(target);
  const byLoc = {};
  for (const p of points) byLoc[p.location] = (byLoc[p.location] || 0) + 1;
  assert.equal(byLoc.cookie, 1, 'level=2 发现 Cookie');
  assert.equal(byLoc.header, undefined, 'level=2 不测 Header');
  assert.ok(!points.some((p) => /^user-agent$/i.test(p.param)), 'level=2 不自动注入 UA');
});

test('level=3 显式 Header + 自动 UA/Referer', async () => {
  const target = createTarget({
    url: 'http://example.com',
    config: { level: 3 },
    headerParams: { 'X-Forwarded-For': '2' },
  });
  const points = await parser.discover(target);
  const params = points.map((p) => p.param.toLowerCase());
  assert.ok(params.includes('x-forwarded-for'), '显式 Header 命中');
  assert.ok(params.includes('user-agent'), '自动注入 User-Agent');
  assert.ok(params.includes('referer'), '自动注入 Referer');
});

test('UA/Referer 已显式提供则不去重叠加', async () => {
  const target = createTarget({
    url: 'http://example.com',
    config: { level: 3 },
    headerParams: { 'User-Agent': 'custom', Referer: 'http://x' },
  });
  const points = await parser.discover(target);
  const ua = points.filter((p) => p.param.toLowerCase() === 'user-agent');
  const ref = points.filter((p) => p.param.toLowerCase() === 'referer');
  assert.equal(ua.length, 1, 'User-Agent 仅 1 个（显式，不叠加自动）');
  assert.equal(ref.length, 1, 'Referer 仅 1 个（显式，不叠加自动）');
});

test('不自动注入 Host 头（避免破坏 HTTP 连接）', async () => {
  const target = createTarget({
    url: 'http://example.com',
    config: { level: 3 },
  });
  const points = await parser.discover(target);
  const params = points.map((p) => p.param.toLowerCase());
  assert.ok(!params.includes('host'), 'Host 头不应被自动注入');
});
