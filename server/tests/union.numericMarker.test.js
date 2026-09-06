// 数值型回显列兜底测试（修复对标 sqlmap 差距 D3）
//
// 背景：文本标记 'SQLISCANNER<i>' 落在 INT 回显列上时，MSSQL/Oracle/PG 等严格类型库
// 会因 varchar→int 转换失败使整条 UNION 报错 → 原先完全漏检；MySQL 静默转 0 同样无法命中。
// 修复：文本探测落空后追加两族不同基值的数字标记交叉确认（双族交集防页面固有数字串假命中）。
//
// 用例：
//   1) 严格类型库（INT 列报错、数字正常回显）→ UnionDetector 仍判定 vulnerable（原先漏报）
//   2) 页面固有数字串（时间戳子串恰含 A 族标记）但 B 族不回显 → 不误报（交叉确认生效）
//   3) discoverEchoColumns 旧语义保持：仅返回文本列、单次请求即命中时不发额外探测
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { UnionDetector } from '../src/engine/detectors/UnionDetector.js';
import { discoverEchoColumns } from '../src/engine/injection.js';

function extractInjected(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  return '';
}

function buildCtx(httpClient, overrides = {}) {
  return {
    httpClient,
    target: {
      method: 'GET',
      baseUrl: 'http://mock/?q=1',
      headerParams: {},
      cookieParams: {},
      config: {},
    },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'PostgreSQL',
    config: { timeoutMs: 5000, timeThresholdMs: 800, maxColumnsGuess: 4, unionSkipGate: true },
    ...overrides,
  };
}

// 严格类型库：UNION 里出现任何带引号字面量 → 类型转换报错；纯数字 → 正常回显该行
function makeStrictIntUnionMock(counter) {
  return {
    calls: counter,
    async request(opts) {
      const q = extractInjected(opts);
      if (counter) counter.push(q);
      if (/ORDER BY \d+/.test(q)) {
        const n = Number(q.match(/ORDER BY (\d+)/)[1]);
        return n > 3 ? { data: 'ERR', status: 200 } : { data: 'normal', status: 200 };
      }
      if (/UNION SELECT/.test(q)) {
        if (q.includes("'")) {
          // 模拟 MSSQL「Conversion failed」/ PG「invalid input syntax」类严格转换报错页
          return { data: 'ERROR: invalid input syntax for type integer', status: 200 };
        }
        return { data: `row:${q}`, status: 200 };
      }
      if (/AND 1=2/.test(q)) return { data: 'NO_RESULTS', status: 200 };
      return { data: `echo:${q}`, status: 200 };
    },
  };
}

test('D3 修复：INT 回显列(文本标记报错)时数字标记兜底仍判定 UNION 注入', async () => {
  const calls = [];
  const d = new UnionDetector();
  const ctx = buildCtx(makeStrictIntUnionMock(calls));
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, true, '严格类型库 INT 列不应再漏报');
  assert.equal(res.technique, 'union');
  // 双族交叉确认都应发出（文本探针落空 → A 族 → B 族）
  const unionCalls = calls.filter((q) => /UNION SELECT/.test(q));
  assert.ok(unionCalls.length >= 3, `应至少发出文本+A+B 三次标记探测，实际 ${unionCalls.length}`);
  assert.ok(unionCalls.some((q) => q.includes('733100')), 'A 族数字标记应被发送');
  assert.ok(unionCalls.some((q) => q.includes('518296')), 'B 族数字标记应被发送');
  // 证据应注明数值型回显列；payloads 记录命中的请求
  assert.match(res.evidence, /数值型回显列/);
  assert.equal(ctx.point.confirmed, true);
  // echoCols 保持「可回显文本的列」语义：数值命中时为空（拖库走不了文本列）
  assert.deepEqual(ctx.point.echoCols, []);
  assert.equal(ctx.point.columns >= 3, true);
});

test('D3 防误报：页面固有数字串只含 A 族标记时交叉确认拦截，不判 UNION', async () => {
  // 页面静态内容恰含 "7331002"（模拟毫秒时间戳子串），但不回显注入值 → B 族必然落空
  const httpClient = {
    async request(opts) {
      const q = extractInjected(opts);
      if (/ORDER BY \d+/.test(q)) {
        const n = Number(q.match(/ORDER BY (\d+)/)[1]);
        return n > 3 ? { data: 'ERR', status: 200 } : { data: 'normal', status: 200 };
      }
      return { data: 'page v2 ts=1737331002233 rendered', status: 200 };
    },
  };
  const d = new UnionDetector();
  const ctx = buildCtx(httpClient);
  const res = await d.detect(ctx);
  assert.equal(res.vulnerable, false, '单族假命中必须被双族交叉确认拦下');
});

test('discoverEchoColumns 旧语义保持：文本命中即返回且只发 1 次探测（不发数字兜底）', async () => {
  const calls = [];
  const httpClient = makeStrictIntUnionMock(calls);
  // 改成文本回显目标：UNION 带引号也正常回显（宽松类型库）
  httpClient.request = async (opts) => {
    const q = extractInjected(opts);
    calls.push(q);
    return { data: `echo:${q}`, status: 200 };
  };
  const ctx = buildCtx(httpClient);
  const hits = await discoverEchoColumns(httpClient, ctx, 3);
  assert.deepEqual(hits, [0, 1, 2]);
  const unionCalls = calls.filter((q) => /UNION SELECT/.test(q));
  assert.equal(unionCalls.length, 1, '文本一次命中就不应追加数字兜底请求');
});
