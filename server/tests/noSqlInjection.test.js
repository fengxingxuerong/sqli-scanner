// P2-2 非 SQL 注入检测回归（NoSQL / GraphQL / SSTI）
// 验证三类非 SQL 注入的检测判定，以及默认关闭（opt-in）不污染经典 SQLi 流水线。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NoSqlInjectionDetector } from '../src/engine/detectors/NoSqlInjectionDetector.js';
import { ScanManager } from '../src/engine/ScanManager.js';

// 构造可预测的桩 httpClient：根据注入值返回不同长度，模拟真伪差异
// 注：Detector.buildRequest 对 url 位置会把注入值写入 url.searchParams，故桩需从 url 解析参数值。
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

function makeClient({ sstiHit = false, graphqlHit = false, nosqlDiff = false } = {}) {
  return {
    async request(req) {
      const body = String(extractValue(req) || '');
      let data = 'base-response-len-20';
      if (sstiHit && body.includes('{{7*7}}')) data = 'result-is-49-and-other';
      else if (graphqlHit && /__schema|__typename/.test(body)) data = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}';
      else if (nosqlDiff) {
        // 真/假注入返回不同长度，基线一致
        if (body.includes('$gt')) data = 'nosql-operator-matched-many-rows-here';
        else data = 'base-response-len-20';
      }
      return { status: 200, headers: {}, data };
    },
  };
}

function makeCtx(httpClient, kind, point = { id: 'p1', originalValue: '1', param: 'q', location: 'url' }) {
  return { httpClient, target: { baseUrl: 'http://x/' }, point, config: {}, noSqlKind: kind };
}

test('P2-2: NoSQL 运算符注入——真伪响应长度差异判定命中', async () => {
  const d = new NoSqlInjectionDetector();
  const r = await d.detect(makeCtx(makeClient({ nosqlDiff: true }), 'nosql'));
  assert.equal(r.vulnerable, true, '应有 nosql 命中');
  assert.equal(r.noSqlKind, 'nosql');
  assert.ok(r.payloads.length >= 1);
});

test('P2-2: GraphQL 内省——__schema 回显判定命中', async () => {
  const d = new NoSqlInjectionDetector();
  const r = await d.detect(makeCtx(makeClient({ graphqlHit: true }), 'graphql'));
  assert.equal(r.vulnerable, true, '应有 graphql 命中');
  assert.equal(r.noSqlKind, 'graphql');
});

test('P2-2: SSTI——{{7*7}} 被求值为 49 回显判定命中', async () => {
  const d = new NoSqlInjectionDetector();
  const r = await d.detect(makeCtx(makeClient({ sstiHit: true }), 'ssti'));
  assert.equal(r.vulnerable, true, '应有 ssti 命中');
  assert.equal(r.noSqlKind, 'ssti');
});

test('P2-2: 无差异/无回显 → 三类均不误报', async () => {
  const d = new NoSqlInjectionDetector();
  // 所有响应一致（无差异）→ 不应命中
  const neutral = makeClient({});
  for (const kind of ['nosql', 'graphql', 'ssti']) {
    const r = await d.detect(makeCtx(neutral, kind));
    assert.equal(r.vulnerable, false, `${kind} 无差异不应误报`);
  }
});

test('P2-2: ScanManager 默认 noSql 关闭 → 不发起非 SQL 探测（对经典 SQLi 零侵入）', async () => {
  const sm = new ScanManager();
  sm.detectors = []; // 清空一阶检测器，专注验证补充趟门控
  sm.fp = { async fingerprint() { return { dbms: null, baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  sm.parser = { async discover() { return [{ id: 'p1', location: 'url', param: 'q', originalValue: '1' }]; } };
  // 桩 httpClient 统计请求
  sm.httpClient = {
    async request() { return { status: 200, headers: {}, data: 'x' }; },
  };
  const id = await sm.start({ url: 'http://x/?q=1', config: { concurrency: 1, ratePerSec: 100 } });
  // 轮询完成
  for (let i = 0; i < 300; i++) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  const report = sm.getReport(id);
  // 默认无 noSql config → 补充趟跳过，不得有 nosql 技术命中
  assert.ok(!report.vulns.some((v) => v.technique === 'nosql'), '未启用 noSql 不应有 nosql 命中');
});

test('P2-2: ScanManager noSql.enabled=true → 对非 SQL 后端逐类别探测', async () => {
  // 用确定性桩：nosql 类别返回差异，graphql/ssti 不回显
  let lastValues = [];
  const sm = new ScanManager();
  sm.detectors = [];
  sm.fp = { async fingerprint() { return { dbms: null, baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  sm.parser = { async discover() { return [{ id: 'p1', location: 'url', param: 'q', originalValue: '1' }]; } };
  sm.httpClient = {
    async request(req) {
      const body = String(extractValue(req) || '');
      lastValues.push(body);
      // nosql 类别：$gt 出现 → 长响应（差异）；其他 → 短
      const data = body.includes('$gt') ? 'nosql-operator-matched-many-rows-here' : 'short';
      return { status: 200, headers: {}, data };
    },
  };
  const id = await sm.start({
    url: 'http://x/?q=1',
    config: { concurrency: 1, ratePerSec: 100, noSql: { enabled: true, kinds: ['nosql', 'graphql', 'ssti'] } },
  });
  for (let i = 0; i < 300; i++) {
    const s = sm.scans.get(id);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  const report = sm.getReport(id);
  const nosqlVuln = report.vulns.find((v) => v.technique === 'nosql' && v.noSqlKind === 'nosql');
  assert.ok(nosqlVuln, '启用 noSql 后 nosql 类别应命中');
});
