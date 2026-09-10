// JSON body 嵌套注入点测试：发现（TargetParser._discoverJsonLeaves）+ 注入替换（buildInjectionRequest）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTarget } from '../src/engine/models.js';
import { buildInjectionRequest } from '../src/engine/injection.js';

// TargetParser 实例化只用到 _discoverJsonLeaves（纯函数），不必走完整 discover（其会 fetch）
async function discoverPoints(target) {
  const { TargetParser } = await import('../src/engine/TargetParser.js');
  const parser = new TargetParser({});
  const points = [];
  parser._discoverJsonLeaves(target.jsonBody, [], points, 0);
  return points;
}

const JSON_BODY = {
  user: { id: '1', name: 'alice' },
  items: [
    { sku: 'A001', qty: 2 },
    { sku: 'B002', qty: 5 },
  ],
  filter: { q: 'keyboard' },
};

test('JSON 叶子发现：字符串/数值叶子全部成为注入点（点路径）', async () => {
  const target = createTarget({ url: 'http://mock/api', jsonBody: JSON_BODY });
  const points = await discoverPoints(target);
  const names = points.map((p) => p.param).sort();
  assert.deepEqual(names, [
    'filter.q',
    'items.0.qty', 'items.0.sku',
    'items.1.qty', 'items.1.sku',
    'user.id', 'user.name',
  ]);
  assert.ok(points.every((p) => p.location === 'body'));
  const uid = points.find((p) => p.param === 'user.id');
  assert.equal(uid.originalValue, '1');
});

test('JSON 注入替换：点路径叶子替换后整体重序列化为 JSON + Content-Type', async () => {
  const target = createTarget({ url: 'http://mock/api', jsonBody: JSON_BODY });
  const points = await discoverPoints(target);
  const p = points.find((x) => x.param === 'user.id');
  const req = buildInjectionRequest(target, p, "1' AND 1=1-- -");
  // data 为 JSON 字符串
  assert.equal(typeof req.data, 'string');
  const parsed = JSON.parse(req.data);
  // 注入值落到正确叶子，其余字段原样保留
  assert.equal(parsed.user.id, "1' AND 1=1-- -");
  assert.equal(parsed.user.name, 'alice');
  assert.equal(parsed.items[0].sku, 'A001');
  assert.equal(parsed.filter.q, 'keyboard');
  assert.equal(req.headers['Content-Type'], 'application/json');
});

test('JSON 注入替换：数组下标路径（items.1.qty）命中正确元素', async () => {
  const target = createTarget({ url: 'http://mock/api', jsonBody: JSON_BODY });
  const points = await discoverPoints(target);
  const p = points.find((x) => x.param === 'items.1.qty');
  const req = buildInjectionRequest(target, p, '999 UNION SELECT 1-- -');
  const parsed = JSON.parse(req.data);
  assert.equal(parsed.items[1].qty, '999 UNION SELECT 1-- -');
  assert.equal(parsed.items[0].qty, 2); // 其他元素不动
});

test('JSON 防护边界：深度>6 / 点数>50 / 每层>64 子节点 安全截断', async () => {
  // 深度 8 的嵌套：只有前 6 层内的叶子会被发现
  let deep = { leaf: 'deep' };
  for (let i = 0; i < 8; i++) deep = { child: deep };
  const target = createTarget({ url: 'http://mock/api', jsonBody: deep });
  const points = await discoverPoints(target);
  assert.equal(points.length, 0, '超深叶子不发现');

  // 宽对象：总点数上限 50 先于每层 64 截断生效（防护取更严者）
  const wide = {};
  for (let i = 0; i < 100; i++) wide[`k${String(i).padStart(3, '0')}`] = 'v';
  const t2 = createTarget({ url: 'http://mock/api', jsonBody: wide });
  const p2 = await discoverPoints(t2);
  assert.ok(p2.length <= 50, `总点数须 ≤50，实际 ${p2.length}`);
});

test('JSON 键含点号：stringify 形式路径互逆匹配', async () => {
  const body = { 'a.b': { 'c.d': 'v' } };
  const target = createTarget({ url: 'http://mock/api', jsonBody: body });
  const points = await discoverPoints(target);
  // 键含点号 → 段序列化为 "a.b"（带引号）
  const names = points.map((p) => p.param);
  assert.ok(names.some((n) => n.includes('a.b')), `应含点号键路径: ${JSON.stringify(names)}`);
  const p = points[0];
  const req = buildInjectionRequest(target, p, 'INJ');
  const parsed = JSON.parse(req.data);
  assert.equal(parsed['a.b']['c.d'], 'INJ');
});

test('非 JSON 目标（bodyParams 表单）不受影响（回归）', () => {
  const target = createTarget({ url: 'http://mock/api', bodyParams: { uname: '1' } });
  const point = { id: 'p1', location: 'body', param: 'uname', originalValue: '1' };
  const req = buildInjectionRequest(target, point, "1' AND 1=1-- -");
  // 表单语义保持：data 是对象
  assert.equal(typeof req.data, 'object');
  assert.equal(req.data.uname, "1' AND 1=1-- -");
});
