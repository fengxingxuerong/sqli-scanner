// 注入请求 URL 编码回归（[P0-FIX 2026-09-06]）
// 背景：charencode 类 tamper 输出已是 URL 编码形态，buildInjectionRequest 的
// searchParams.set 会把 % 再编码为 %25（双重编码）→ 服务器单次解码后 payload
// 仍是编码形态 → SQL 层收到乱码、回显标记失配（waf-lab configB 0 检出根因）。
// 修复：含合法 %XX 且解码后形态改变 → 跳过二次编码（手工拼 query）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildInjectionRequest } from '../src/engine/injection.js';

const target = { url: 'http://t:9/vuln?id=1', baseUrl: 'http://t:9/vuln?id=1', method: 'GET' };
const point = { id: 'p1', location: 'url', param: 'id', originalValue: '1' };
const req = (v) => buildInjectionRequest(target, point, v);

test('已编码 payload：不再二次编码（%XX 原样保留）', () => {
  const r = req("%31%27%20%55%4E%49%4F%4E");
  const m = /[?&]id=([^&]+)/.exec(r.url);
  assert.equal(m[1], "%31%27%20%55%4E%49%4F%4E", 'URL 中应原样保留单次编码形态');
  assert.ok(!r.url.includes('%2531'), '%31 不应被再编码为 %2531');
});

test('已编码 payload 的其它 query 参数保留', () => {
  const t2 = { ...target, baseUrl: 'http://t:9/vuln?id=1&x=2' };
  const r = buildInjectionRequest(t2, point, '%41%42');
  assert.ok(r.url.includes('x=2'), '已有参数应保留');
  assert.ok(r.url.includes('id=%41%42'), '注入参数单次编码');
});

test('明文 payload：正常 URL 编码（默认行为不变）', () => {
  const r = req("1' AND 1=1-- -");
  const m = /[?&]id=([^&]+)/.exec(r.url);
  assert.equal(decodeURIComponent(m[1].replace(/\+/g, " ")), "1' AND 1=1-- -", "明文应正常编码（+ 即空格）");
});

test("LIKE '%a%' 类含裸 % 的值：非法 % 序列不触发 preEncoded（不误判）", () => {
  const r = req("x'%a%");
  const m = /[?&]id=([^&]+)/.exec(r.url);
  // '%a%' 中 %a% 是非法编码序列 → decodeURIComponent 抛错 → 未编码路径
  assert.equal(m[1], "x%27%25a%25".replace('%25a%25', '%25a%25'), '裸 % 应被编码为 %25');
  assert.ok(m[1].includes('%25a%'), `裸 % 应双重转义为 %25a%：${m[1]}`);
});

test('charencode 全编码输出端到端：解码一次即注入明文', () => {
  const r = req('%31%27%20%41%4E%44%20%31%3D%31--%20-');
  const m = /[?&]id=([^&]+)/.exec(r.url);
  assert.equal(decodeURIComponent(m[1]), "1' AND 1=1-- -", '单次解码即明文（真实服务器语义）');
});
