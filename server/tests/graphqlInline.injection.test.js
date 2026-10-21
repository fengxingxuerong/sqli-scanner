// [D121 2026-10-21] GraphQL 查询串内联值位：发现 + 构造 + 回归边界。
//
// 背景：DVGA 外部裁判（D114）的真值点是 `{ pastes(filter: "x") { … } }`；
// 旧路径把整个 query 字符串替换成 payload，GraphQL 解析层直接 400，真值点 0/1。
// 本组判据钉住「保持骨架、只换值位」这一形态，以及非 GraphQL 的 query 字段零回归。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTarget } from '../src/engine/models.js';
import { TargetParser } from '../src/engine/TargetParser.js';
import { buildInjectionRequest } from '../src/engine/injection.js';
import {
  looksLikeGraphQLQuery,
  findGraphQLInlineLiterals,
  replaceGraphQLStringLiteral,
  encodeGraphQLString,
} from '../src/engine/graphqlInline.js';

function discover(target) {
  const points = [];
  new TargetParser({})._discoverJsonLeaves(target.jsonBody, [], points, 0);
  return points;
}

function targetWith(jsonBody) {
  return createTarget({ url: 'http://mock/graphql', method: 'POST', jsonBody });
}

const DVGA_QUERY = '{ pastes(public: true, filter: "x") { id title } }';

test('D121-①: DVGA 查询串发现内联字面量点（不再是整串 query 点）', () => {
  const points = discover(targetWith({ query: DVGA_QUERY }));
  assert.equal(points.length, 1);
  const p = points[0];
  assert.equal(p.location, 'body');
  assert.equal(p.param, 'query.filter');
  assert.equal(p.carrier, 'graphql');
  assert.equal(p.originalValue, 'x');
  assert.equal(p.graphqlArgName, 'filter');
  assert.equal(p.graphqlPath, 'query');
  assert.ok(!points.some((x) => x.param === 'query'), '不得再生成整串 query 值点');
});

test('D121-②: 注入只换字面量，查询骨架/其它参数逐字保留', () => {
  const target = targetWith({ query: DVGA_QUERY });
  const [p] = discover(target);
  const payload = "x' OR 1=1-- -";
  const req = buildInjectionRequest(target, p, payload);
  assert.equal(req.headers['Content-Type'], 'application/json');
  const parsed = JSON.parse(req.data);
  assert.equal(parsed.query, '{ pastes(public: true, filter: "x\' OR 1=1-- -") { id title } }');
  assert.equal(target.jsonBody.query, DVGA_QUERY, '构造请求不得改动 target 原 body');
});

test('D121-③: 基线请求与用户抓包逐字一致（不重编码字面量）', () => {
  const target = targetWith({ query: DVGA_QUERY });
  const [p] = discover(target);
  const req = buildInjectionRequest(target, p, p.originalValue);
  assert.equal(JSON.parse(req.data).query, DVGA_QUERY);
});

test('D121-④: payload 含双引号/反斜杠时转义后仍是合法 JSON+GraphQL', () => {
  const target = targetWith({ query: DVGA_QUERY });
  const [p] = discover(target);
  const payload = 'a"b\\c\' OR 1=1-- -';
  const req = buildInjectionRequest(target, p, payload);
  const parsed = JSON.parse(req.data);
  assert.equal(parsed.query, `{ pastes(public: true, filter: "${encodeGraphQLString(payload)}") { id title } }`);
  assert.ok(parsed.query.includes('a\\"b'), 'GraphQL 字符串里应是 JSON 转义后的 \\"');
});

test('D121-⑤: 同一查询多个字面量各生成独立点，互不串改', () => {
  const target = targetWith({ query: '{ a(x: "one", y: "two") { id } }' });
  const points = discover(target);
  assert.deepEqual(points.map((p) => p.param), ['query.x', 'query.y']);
  const first = JSON.parse(buildInjectionRequest(target, points[0], 'P1').data).query;
  const second = JSON.parse(buildInjectionRequest(target, points[1], 'P2').data).query;
  assert.equal(first, '{ a(x: "P1", y: "two") { id } }');
  assert.equal(second, '{ a(x: "one", y: "P2") { id } }');
});

test('D121-⑥: 同名字面量（不同字段）参数名不撞车', () => {
  const target = targetWith({ query: '{ a(filter: "x") { id } b(filter: "y") { id } }' });
  const points = discover(target);
  assert.deepEqual(points.map((p) => p.param), ['query.filter', 'query.filter[2]']);
});

test('D121-⑦: variables 走既有 JSON 叶子通道；query 无内联字面量时不生成整串点', () => {
  const query = 'query Search($kw: String) { search(keyword: $kw) { __typename } }';
  const target = targetWith({ query, variables: { kw: 'x' } });
  const points = discover(target);
  assert.deepEqual(points.map((p) => p.param), ['variables.kw']);
  assert.notEqual(points[0].carrier, 'graphql');
  const req = buildInjectionRequest(target, points[0], "x' OR 1=1-- -");
  assert.equal(JSON.parse(req.data).variables.kw, "x' OR 1=1-- -");
  assert.equal(JSON.parse(req.data).query, query);
});

test('D121-⑧: 批量 GraphQL 数组路径（0.query.filter）', () => {
  const target = targetWith([{ query: DVGA_QUERY }]);
  const points = discover(target);
  assert.equal(points.length, 1);
  assert.equal(points[0].param, '0.query.filter');
  assert.equal(points[0].graphqlPath, '0.query');
  const req = buildInjectionRequest(target, points[0], 'P');
  assert.equal(JSON.parse(req.data)[0].query, '{ pastes(public: true, filter: "P") { id title } }');
});

test('D121-⑨: 非 GraphQL 的 query 字段保持旧 JSON 叶子行为', () => {
  const target = targetWith({ filter: { query: 'keyboard' }, page: 1 });
  const points = discover(target);
  assert.deepEqual(points.map((p) => p.param).sort(), ['filter.query', 'page']);
  const q = points.find((p) => p.param === 'filter.query');
  assert.equal(q.carrier, undefined);
  assert.equal(JSON.parse(buildInjectionRequest(target, q, 'P').data).filter.query, 'P');
});

test('D121-⑩: block string / 未闭合字符串不生成点（保守边界）', () => {
  const block = discover(targetWith({ query: '{ a(x: """block""") { id } }' }));
  assert.equal(block.length, 0, 'block string 不在本通道内');
  const broken = discover(targetWith({ query: '{ a(x: "unterminated) { id } }' }));
  assert.equal(broken.length, 0, '未闭合字符串不猜');
});

test('D121-⑪: 扫描器只认参数值位；JSON 对象/数组字面量不误判', () => {
  assert.equal(looksLikeGraphQLQuery('{ "a": 1 }'), false);
  assert.equal(looksLikeGraphQLQuery('{ __typename }'), true);
  assert.equal(looksLikeGraphQLQuery('query Q { __typename }'), true);
  assert.deepEqual(findGraphQLInlineLiterals('{ a(x: "v") { id } }'), [
    { start: 7, end: 10, raw: '"v"', value: 'v', argName: 'x' },
  ]);
});

test('D121-⑫: 区间失效时替换返回 null（构造侧保守降级）', () => {
  const q = '{ a(x: "v") { id } }';
  assert.equal(replaceGraphQLStringLiteral(q, 7, 10, 'P', 'v', '"v"'), '{ a(x: "P") { id } }');
  assert.equal(replaceGraphQLStringLiteral(q, 0, 3, 'P', 'v', '"v"'), null);
  assert.equal(replaceGraphQLStringLiteral(q, 8, 9, 'P', 'v', '"v"'), null);
});
