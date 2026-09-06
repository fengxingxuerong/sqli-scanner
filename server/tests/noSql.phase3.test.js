// P2-3 非 SQL 注入检测深化回归（MongoDB 多操作符 / SSTI 多引擎 / GraphQL 批处理 / 二次确认降误报）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NoSqlInjectionDetector } from '../src/engine/detectors/NoSqlInjectionDetector.js';

// 从请求中提取注入值（与 noSqlInjection.test.js 相同的桩约定）
function extractValue(req) {
  const url = req.url || '';
  try {
    const u = new URL(url);
    const vals = [...u.searchParams.values()];
    if (vals.length) return vals[0];
  } catch {}
  if (req.params && Object.keys(req.params).length) return Object.values(req.params)[0];
  if (req.data && Object.keys(req.data).length) return Object.values(req.data)[0];
  return '';
}

function makeCtx(httpClient, kind, point = { id: 'p1', originalValue: '1', param: 'q', location: 'url' }) {
  return { httpClient, target: { baseUrl: 'http://x/' }, point, config: {}, noSqlKind: kind };
}

test('P2-3: MongoDB $gt/$ne 首轮低成本操作符命中（多操作符矩阵第 1 组）', async () => {
  const d = new NoSqlInjectionDetector();
  const client = {
    async request(req) {
      const body = String(extractValue(req) || '');
      if (body.includes('"$gt"')) return { status: 200, headers: {}, data: 'many-records-matched-by-gt' };
      if (body.includes('"$ne"')) return { status: 200, headers: {}, data: 'no-records' };
      return { status: 200, headers: {}, data: 'constant-page' };
    },
  };
  const r = await d.detect(makeCtx(client, 'nosql'));
  assert.equal(r.vulnerable, true, '$gt/$ne 应命中');
  assert.equal(r.noSqlKind, 'nosql');
  assert.ok(r.evidence.includes('$gt/$ne'), '证据应标注操作符');
});

test('P2-3: MongoDB $gt/$ne 无差异时回退 $where 命中（成本升序遍历）', async () => {
  const d = new NoSqlInjectionDetector();
  const client = {
    async request(req) {
      const body = String(extractValue(req) || '');
      // 仅 $where 后端可区分（$gt/$ne 均无差异），验证探测顺序：未命中再试 $where
      if (body.includes('{"$where": "1"}') || body.includes('{"$where": "1==1"}')) return { status: 200, headers: {}, data: 'where-true-many-rows' };
      if (body.includes('{"$where": "0"}') || body.includes('{"$where": "1==2"}')) return { status: 200, headers: {}, data: 'where-false-none' };
      return { status: 200, headers: {}, data: 'constant-page' };
    },
  };
  const r = await d.detect(makeCtx(client, 'nosql'));
  assert.equal(r.vulnerable, true, '$where 应命中');
  assert.ok(r.evidence.includes('$where'), '证据应标注 $where');
});

test('P2-3: SSTI Jinja2 {{7*7}} 命中', async () => {
  const d = new NoSqlInjectionDetector();
  const client = {
    async request(req) {
      const body = String(extractValue(req) || '');
      if (body.includes('{{7*7}}')) return { status: 200, headers: {}, data: 'computed-result-is-49' };
      return { status: 200, headers: {}, data: 'plain-output' };
    },
  };
  const r = await d.detect(makeCtx(client, 'ssti'));
  assert.equal(r.vulnerable, true, 'Jinja2 应命中');
  assert.equal(r.noSqlKind, 'ssti');
  assert.ok(r.evidence.includes('Jinja2'));
});

test('P2-3: SSTI FreeMarker ${7*7} 命中（Jinja2 未命中后遍历到 FreeMarker）', async () => {
  const d = new NoSqlInjectionDetector();
  const client = {
    async request(req) {
      const body = String(extractValue(req) || '');
      if (body.includes('${7*7}')) return { status: 200, headers: {}, data: 'freemarker-eval-49' };
      return { status: 200, headers: {}, data: 'plain-output' };
    },
  };
  const r = await d.detect(makeCtx(client, 'ssti'));
  assert.equal(r.vulnerable, true, 'FreeMarker 应命中');
  assert.ok(r.evidence.includes('FreeMarker'));
});

test('P2-3: SSTI ERB <%= 7*7 %> 命中（遍历到 ERB）', async () => {
  const d = new NoSqlInjectionDetector();
  const client = {
    async request(req) {
      const body = String(extractValue(req) || '');
      if (body.includes('<%= 7*7 %>')) return { status: 200, headers: {}, data: 'erb-eval-49' };
      return { status: 200, headers: {}, data: 'plain-output' };
    },
  };
  const r = await d.detect(makeCtx(client, 'ssti'));
  assert.equal(r.vulnerable, true, 'ERB 应命中');
  assert.ok(r.evidence.includes('ERB'));
});

test('P2-3: GraphQL 批处理（JSON 数组批量 query）命中', async () => {
  const d = new NoSqlInjectionDetector();
  const client = {
    async request(req) {
      const body = String(extractValue(req) || '');
      // 仅批处理（JSON 数组）回显，内省/别名/循环均不可访问
      if (body.startsWith('[{"query"')) return { status: 200, headers: {}, data: '{"data":{"__typename":"Query"}}' };
      return { status: 200, headers: {}, data: 'graphql-introspection-disabled' };
    },
  };
  const r = await d.detect(makeCtx(client, 'graphql'));
  assert.equal(r.vulnerable, true, '批处理应命中');
  assert.equal(r.noSqlKind, 'graphql');
  assert.ok(r.evidence.includes('批处理'));
});

test('P2-3: 二次确认降误报——primary 单次抖动、confirm 不一致 → 不报', async () => {
  const d = new NoSqlInjectionDetector();
  let gtPrimarySeen = false;
  const client = {
    async request(req) {
      const body = String(extractValue(req) || '');
      // 仅 primary 真（{"$gt": ""}）首次偶发返回差异，confirm（{"$gt": "0"}）与其余均返回基线 → 抖动应被过滤
      if (body.includes('{"$gt": ""}') && !gtPrimarySeen) {
        gtPrimarySeen = true;
        return { status: 200, headers: {}, data: 'one-off-fluke-content-here' };
      }
      return { status: 200, headers: {}, data: 'constant-page' };
    },
  };
  const r = await d.detect(makeCtx(client, 'nosql'));
  assert.equal(r.vulnerable, false, '单次抖动经二次确认应被过滤，不误报');
});

test('P2-3: 无差异/无回显 → 三类均不误报', async () => {
  const d = new NoSqlInjectionDetector();
  const neutral = {
    async request() {
      return { status: 200, headers: {}, data: 'same-constant-response' };
    },
  };
  for (const kind of ['nosql', 'graphql', 'ssti']) {
    const r = await d.detect(makeCtx(neutral, kind));
    assert.equal(r.vulnerable, false, `${kind} 无差异不应误报`);
  }
});
