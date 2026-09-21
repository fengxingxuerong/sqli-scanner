// [P1 2026-09-22] 注入请求的 **发送形态**：multipart 目标必须以 multipart 发出。
//
// 为什么单测要钉住这个：`-r` 导入侧（requestCollectionParser）早就能认出 multipart 的
// 字段名，但发送侧只有 urlencoded / JSON 两条路 —— 只吃 multipart 的目标解析不到字段，
// 注入值从未进 SQL，表现为**静默 0 检出**（不是报错）。靶场 e2e/pentest-lab 的 `/mp`
// 负责端到端复现，这里负责钉住序列化契约本身。
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildInjectionRequest } from '../src/engine/injection.js';

const PAYLOAD = "Keyboard%' AND '1'='2";

test('multipart 目标：注入请求以 multipart 报文发送（含注入值与其余字段）', () => {
  const target = {
    method: 'POST',
    baseUrl: 'http://127.0.0.1:8150/mp',
    headerParams: { 'Content-Type': 'multipart/form-data; boundary=----Boundary1' },
  };
  const point = { location: 'body', param: 'name', formValues: { name: 'Keyboard', tag: 'x' } };
  const req = buildInjectionRequest(target, point, PAYLOAD);

  assert.match(req.headers['Content-Type'], /^multipart\/form-data; boundary=----Boundary1$/);
  assert.equal(typeof req.data, 'string', 'multipart 应是字符串报文，不是对象');
  assert.ok(req.data.includes('name="name"'), '注入字段必须出现在报文里');
  assert.ok(req.data.includes(PAYLOAD), '注入值必须原样进入报文（不被 urlencode 破坏）');
  assert.ok(req.data.includes('name="tag"'), '同表单其它字段必须保留（CSRF token 同理）');
  assert.ok(req.data.trimEnd().endsWith('--'), '报文必须以闭合 boundary 结束');
});

test('multipart 目标：header 大小写不敏感（Content-Type / content-type 都认）', () => {
  const target = {
    method: 'POST',
    baseUrl: 'http://127.0.0.1:8150/mp',
    headerParams: { 'content-type': 'multipart/form-data; boundary=abc' },
  };
  const req = buildInjectionRequest(target, { location: 'body', param: 'n', formValues: { n: '1' } }, PAYLOAD);
  assert.match(req.headers['Content-Type'], /^multipart\/form-data/);
});

test('multipart 目标：未给 boundary 时自动补一个', () => {
  const target = {
    method: 'POST',
    baseUrl: 'http://127.0.0.1:8150/mp',
    headerParams: { 'Content-Type': 'multipart/form-data' },
  };
  const req = buildInjectionRequest(target, { location: 'body', param: 'n', formValues: { n: '1' } }, PAYLOAD);
  assert.match(req.headers['Content-Type'], /^multipart\/form-data; boundary=.+/);
  const boundary = /boundary=(.+)$/.exec(req.headers['Content-Type'])[1];
  assert.ok(req.data.includes(`--${boundary}`), '报文里的 boundary 必须与头里一致');
});

test('回归：普通表单点仍是 urlencoded（不得被 multipart 分支误伤）', () => {
  const target = { method: 'POST', baseUrl: 'http://127.0.0.1:8150/login' };
  const req = buildInjectionRequest(target, { location: 'body', param: 'username', formValues: { username: 'alice', password: 'x' } }, PAYLOAD);
  assert.equal(req.headers['Content-Type'], 'application/x-www-form-urlencoded');
  assert.ok(String(req.data).includes('username='), '应是 urlencoded 串');
  assert.ok(!String(req.data).includes('Content-Disposition'), '不应出现 multipart 片段');
});

test('回归：JSON body 目标仍走 JSON 分支', () => {
  const target = {
    method: 'POST',
    baseUrl: 'http://127.0.0.1:8150/api/order',
    jsonBody: { filters: { category: 'electronics' } },
  };
  const req = buildInjectionRequest(target, { location: 'body', param: 'filters.category' }, PAYLOAD);
  assert.equal(req.headers['Content-Type'], 'application/json');
  const parsed = JSON.parse(req.data);
  assert.equal(parsed.filters.category, PAYLOAD, '点路径叶子应被注入值替换');
});
