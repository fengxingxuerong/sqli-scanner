// ============================================================================
// callProcName.test.js —— `{call <名>}` / CALL 表达式位（键名进过程名位）判据
// [D284 2026-11-11 立] 补 D116 单列的能力缺口；真机取证见 detectorSupport/callProcName.js 头注
// ============================================================================
// 判据钉住六种形态（假 httpClient 按「注入后的键名」分类响应）：
//   ① echo：随机标记 CONCAT(CHAR..) 求值结果两轮回显 + 对照无 ⇒ 命中（echo 通道）
//   ② eval-err：echo 闭合时 1/0 除零签名 vs 未知标识符对照（不相似）⇒ 命中（eval-err 通道）
//   ③ 固定错误页（所有 SQL 错误渲染同一页，含除零文案）⇒ 不判（防固定页误归因）
//   ④ 盲档同页 ⇒ 不判
//   ⑤ 对照页也含除零签名（签名过松）⇒ 不判
//   ⑥ 复跑不稳（第二轮无标记）⇒ 不判
//   ⑦ 反射目标（把键名原样回显）⇒ 不判（构造性反射安全：载荷关键词全大写，标记 [a-z0-9]）
//   ⑧ 方言变体：dbms='PostgreSQL' 用 CHR()；dbms=null 默认 CHAR()（①的用例隐式钉住）
//   ⑨ XML 载体 / 非参数名点 ⇒ 零请求跳过
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CallProcNameDetector } from '../src/engine/detectorSupport/callProcName.js';
import { createTarget, createInjectionPoint } from '../src/engine/models.js';

const OK_PAGE = (marker) => `<html><body><p>Your results are:<br>${marker}<br></p></body></html>`;
const ERR_DIV = '<pre>java.sql.SQLDataException: data exception: division by zero in statement [ CALL 1/0 ]</pre>';
const ERR_NOTFOUND = '<pre>SQLSyntaxErrorException: user lacks privilege or object not found: SQLI_NOPE</pre>';
const ERR_TOKEN = '<pre>SQLSyntaxErrorException: unexpected token in statement [ CALL ... ]</pre>';

/**
 * 从载荷里解出标记：抓全部 CHAR(n)/CHR(n) 码位 → 字符串（与引擎 echoPayloadFor 同构）。
 * @param {string} payload 注入后的键名
 * @returns {string|null}
 */
function markerOf(payload) {
  const codes = [...String(payload).matchAll(/C(HR|HAR)\((\d+)\)/g)].map((m) => Number(m[2]));
  return codes.length >= 4 ? codes.map((n) => String.fromCharCode(n)).join('') : null;
}

/**
 * 假 httpClient：query 载体取 URL 第一个键名交给 classify。
 * @param {(keyName: string, calls: string[]) => string} classify
 */
function stubClient(classify) {
  const calls = [];
  return {
    client: {
      request: async (opts) => {
        let key = null;
        try {
          const u = new URL(String(opts.url || ''));
          key = [...u.searchParams.keys()][0] ?? null;
        } catch { /* 解析失败按空键名 */ }
        calls.push(key ?? '');
        return { status: 200, data: classify(key ?? '', calls) };
      },
    },
    calls,
  };
}

async function detectWith(classify, { carrier = 'query', dbms = null } = {}) {
  const target = createTarget({
    url: 'http://shop.example.com/api/call-proc?name=alice&go=1',
    method: 'GET',
    bodyParams: {},
    headerParams: {},
    config: { level: 3 },
  });
  const point = createInjectionPoint('paramName', 'name', 'name', { carrier, paramNameValue: 'alice' });
  const detector = new CallProcNameDetector();
  const { client, calls } = stubClient(classify);
  const result = await detector.detect({ httpClient: client, target, point, config: target.config, dbms });
  return { result, calls };
}

/** echo 目标：CONCAT(...) 载体 → 成功页回显求值结果；其余（1/0 / 对照 / 原值）→ 无除零签名错误页 */
const echoTarget = (name) => (name.startsWith('CONCAT(') ? OK_PAGE(markerOf(name)) : ERR_NOTFOUND);

test('[D284] echo 通道：标记两轮稳定回显 + 对照无 ⇒ 判为注入（error 族）', async () => {
  const { result, calls } = await detectWith(echoTarget);
  assert.equal(result.vulnerable, true);
  assert.equal(result.technique, 'error');
  assert.equal(result.trace.channel, 'echo');
  assert.match(result.evidence, /CALL 表达式位/);
  assert.match(result.evidence, /稳定回显/);
  // 请求预算：e1 + e2 + 对照 = 3（echo 命中即收口，不再发 1/0）
  assert.equal(calls.length, 3);
  assert.match(calls[0], /^CONCAT\(CHAR\(/, '默认方言（dbms=null）应使用 CHAR() 变体');
});

test('[D284] eval-err 通道：echo 闭合时 1/0 除零签名 + 对照无此签名且不相似 ⇒ 判为注入', async () => {
  const { result } = await detectWith((name) => {
    if (name.startsWith('CONCAT(')) return ERR_TOKEN; // echo 通道闭合（无 CONCAT 的引擎/回显缺失）
    if (name === '1/0') return ERR_DIV;
    return ERR_NOTFOUND; // 未知标识符对照：不同异常、无除零签名
  });
  assert.equal(result.vulnerable, true);
  assert.equal(result.trace.channel, 'eval-err');
  assert.match(result.evidence, /求值类错误/);
  // 载荷记录 [探针, 对照]：对照载荷一并留痕，复核时能看到「签名不是对照页给的」
  assert.equal(result.payloads.length, 2);
  assert.equal(result.payloads[0], '1/0');
  assert.match(result.payloads[1], /^sqli_nope_/);
});

test('[D284] 固定错误页（所有 SQL 错误渲染同一页）⇒ 不判（防固定页误归因）', async () => {
  const { result } = await detectWith(() => ERR_DIV);
  assert.equal(result.vulnerable, false);
});

test('[D284] 盲档同页（正常页、无标记）⇒ 不判', async () => {
  const { result } = await detectWith(() => '<html><body>ok</body></html>');
  assert.equal(result.vulnerable, false);
});

test('[D284] 对照页也含除零签名（签名过松）⇒ 不判', async () => {
  const { result } = await detectWith((name) => (name.startsWith('CONCAT(') ? ERR_TOKEN : ERR_DIV));
  assert.equal(result.vulnerable, false);
});

test('[D284] 复跑不稳（首轮回显、第二轮无）⇒ 不判', async () => {
  let concatCalls = 0;
  const { result } = await detectWith((name) => {
    if (!name.startsWith('CONCAT(')) return ERR_NOTFOUND;
    concatCalls += 1;
    return concatCalls === 1 ? OK_PAGE(markerOf(name)) : ERR_TOKEN;
  });
  assert.equal(result.vulnerable, false);
});

test('[D284] 反射目标（把键名原样回显进响应）⇒ 不判（构造性反射安全）', async () => {
  const { result } = await detectWith((name) => `<html><body>request echoed: ${name}</body></html>`);
  assert.equal(result.vulnerable, false);
});

test('[D284] 方言变体：dbms=PostgreSQL 用 CHR()', async () => {
  const { result, calls } = await detectWith(echoTarget, { dbms: 'PostgreSQL' });
  assert.equal(result.vulnerable, true);
  assert.match(calls[0], /^CONCAT\(CHR\(/);
});

test('[D284] XML 载体（元素名）不在本判据范围，零请求跳过', async () => {
  const { result, calls } = await detectWith(echoTarget, { carrier: 'xml' });
  assert.equal(result.vulnerable, false);
  assert.equal(calls.length, 0);
});

test('[D284] 非参数名点（值位）不在本判据范围，零请求跳过', async () => {
  const target = createTarget({
    url: 'http://shop.example.com/api/page?id=1',
    method: 'GET',
    bodyParams: {},
    headerParams: {},
    config: { level: 3 },
  });
  const point = createInjectionPoint('query', 'id', '1', {});
  const detector = new CallProcNameDetector();
  const { client, calls } = stubClient(echoTarget);
  const result = await detector.detect({ httpClient: client, target, point, config: target.config, dbms: null });
  assert.equal(result.vulnerable, false);
  assert.equal(calls.length, 0);
});
