// ============================================================================
// cli.batchTargets.test.js —— `-m` 的目标展开（URL 列表 / 请求集合）
//
// 竞品坐标：sqlmap 2.0(WIP) 新增「OpenAPI 目标生成」；ghauri 的 `-m` 仍只吃文本 URL、
// `-r` 只吃单请求。本仓此前同样是断的（集合解析只服务 `-r` 且只取第 1 条）。
// 本文件验的是「接口清单 → N 个可扫目标」这一步，判据全部是外部事实：
// 展开条数、逐条 method/headers/body 是否保住、格式有没有被点名、跳过的有没有计数。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { expandBatchTargets, scanArgsFromRequest } from '../bin/cli/batchTargets.js';

const HAR = JSON.stringify({
  log: {
    entries: [
      {
        request: {
          method: 'GET',
          url: 'http://t.local/num?id=1',
          headers: [{ name: 'Cookie', value: 'sid=a' }, { name: 'X-Trace', value: 't1' }],
        },
      },
      {
        request: {
          method: 'POST',
          url: 'http://t.local/str',
          headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
          postData: { text: 'name=alice' },
        },
      },
    ],
  },
});

const OPENAPI = JSON.stringify({
  openapi: '3.0.0',
  servers: [{ url: 'http://t.local' }],
  paths: {
    '/num': {
      get: {
        parameters: [
          { name: 'id', in: 'query', schema: { type: 'integer' }, example: 1 },
        ],
      },
    },
  },
});

const BURP = `<?xml version="1.0"?><items><item><method>GET</method><url>http://t.local/num?id=1</url>
<request>GET /num?id=1 HTTP/1.1
Host: t.local

</request></item></items>`;

// ① URL 列表：保持既有语义（一行一个），注释与空行不算"被过滤"
test('batchTargets: URL 列表逐行展开，注释与空行不计数', () => {
  const r = expandBatchTargets('http://a/1\n\n# 注释\nhttp://b/2\n');
  assert.equal(r.kind, 'urls');
  assert.deepEqual(r.items, ['http://a/1', 'http://b/2']);
  assert.equal(r.skipped, 0, '注释与空行不该算进 skipped');
});

// ② 非 http(s) 的行必须**被点名**（不静默丢弃）
test('batchTargets: 非 URL 行计入 skipped 并给提示', () => {
  const r = expandBatchTargets('http://a/1\nnot-a-url\n');
  assert.deepEqual(r.items, ['http://a/1']);
  assert.equal(r.skipped, 1);
  assert.ok(r.warnings.some((w) => /忽略 1 行/.test(w)), `未点名被忽略的行：${JSON.stringify(r.warnings)}`);
});

// ③ HAR：展开成集合，method / headers / body 都要保住
test('batchTargets: HAR 展开为集合且保住 method/headers/body', () => {
  const r = expandBatchTargets(HAR);
  assert.equal(r.kind, 'collection');
  assert.equal(r.format, 'har');
  assert.equal(r.items.length, 2);
  assert.equal(r.items[0].method, 'GET');
  assert.equal(r.items[0].url, 'http://t.local/num?id=1');
  assert.equal(r.items[0].headers.Cookie, 'sid=a', 'Cookie 必须保住（丢了 = 需登录的目标扫不到）');
  assert.equal(r.items[1].method, 'POST');
  // urlencoded body 必须在展开期就 JSON 化：留到扫描期再 JSON.parse 会整条崩
  // （真机实测：`Unexpected token 'a', "name=alice" is not valid JSON` ⇒ 该目标整个失败）
  assert.equal(r.items[1].body, '{"name":"alice"}', 'POST body 必须保住且已转成 JSON');
});

// ④ OpenAPI：接口定义 → 样例请求（对标 sqlmap 2.0 的 OpenAPI 目标生成）
test('batchTargets: OpenAPI 展开为样例请求，且 caveat 必须往上传', () => {
  const r = expandBatchTargets(OPENAPI);
  assert.equal(r.kind, 'collection');
  assert.equal(r.format, 'openapi');
  assert.equal(r.items.length, 1);
  assert.match(r.items[0].url, /^http:\/\/t\.local\/num/);
  // ⚠ 「不是抓包、值是 example/default」这条 caveat 绝不能被本层淡化
  assert.ok(
    r.warnings.some((w) => /接口定义|example/.test(w)),
    `OpenAPI 的占位值 caveat 丢失：${JSON.stringify(r.warnings)}`,
  );
});

// ⑤ Burp XML：与 -r 同一解析器展开
test('batchTargets: Burp XML 展开为集合', () => {
  const r = expandBatchTargets(BURP);
  assert.equal(r.kind, 'collection');
  assert.equal(r.format, 'burp-xml');
  assert.equal(r.items.length, 1);
  assert.match(r.items[0].url, /t\.local\/num/);
});

// ⑥ OpenAPI 的 **YAML** 形式现在能展开（零依赖子集解析器）—— 规范绝大多数以 YAML 流通
test('batchTargets: OpenAPI YAML 展开为样例请求', () => {
  const yaml = [
    'openapi: 3.0.0',
    'info:',
    '  title: batch-lab',
    '  version: 1.0.0',
    'servers:',
    '  - url: http://t.local',
    'paths:',
    '  /num:',
    '    get:',
    '      parameters:',
    '        - name: id',
    '          in: query',
    '          required: true',
    '          schema:',
    '            type: integer',
    '          example: 1',
    '  /str:',
    '    get:',
    '      parameters:',
    '        - name: name',
    '          in: query',
    '          schema:',
    '            type: string',
    '          example: alice',
    '',
  ].join('\n');
  const r = expandBatchTargets(yaml);
  assert.equal(r.kind, 'collection');
  assert.equal(r.format, 'openapi-yaml');
  assert.equal(r.items.length, 2, `YAML 应展开出 2 个目标，实得 ${r.items.length}：${JSON.stringify(r.items.map((i) => i.url))}`);
  assert.ok(r.items.some((i) => /\/num/.test(i.url) && /id=1/.test(i.url)), `数值参数没带上 example：${JSON.stringify(r.items)}`);
  assert.ok(r.items.some((i) => /\/str/.test(i.url) && /name=alice/.test(i.url)), `字符串参数没带上 example：${JSON.stringify(r.items)}`);
  assert.ok(r.warnings.some((w) => /YAML/.test(w)), '应说明走的是 YAML 子集解析器');
});

// ⑥b 吃不下的 YAML 必须**如实报原因 + 转 JSON 建议**，绝不半解
test('batchTargets: 含不支持构造的 YAML 拒绝展开并给出原因', () => {
  const r = expandBatchTargets('openapi: 3.0.0\ninfo:\n  title: t\nx: &anchor\n  a: 1\n');
  assert.equal(r.items.length, 0, '半解会展开出**错的**请求，比不展开危险 ⇒ 必须整体拒绝');
  assert.ok(
    r.warnings.some((w) => /锚点/.test(w) && /转 JSON|Convert/.test(w)),
    `缺「原因 + 转 JSON 建议」：${JSON.stringify(r.warnings)}`,
  );
});

// ⑦ 集合里的越界方法/非 http URL 要被过滤且计数（不然批量里会静默少目标）
test('batchTargets: 集合里的条目被过滤时 skipped 有计数', () => {
  const r = expandBatchTargets(JSON.stringify({
    log: { entries: [
      { request: { method: 'GET', url: 'http://ok/1', headers: [] } },
      { request: { method: 'TRACE', url: 'http://bad/2', headers: [] } },
      { request: { method: 'GET', url: 'ftp://bad/3', headers: [] } },
    ] },
  }));
  assert.equal(r.items.length, 1);
  assert.equal(r.skipped, 2);
  assert.ok(r.warnings.some((w) => /2 个请求被跳过/.test(w)), `未点名被跳过的条目：${JSON.stringify(r.warnings)}`);
});

// ⑧ 逐目标派生：cookie 单独成键、host/content-length 不进 headerObj
test('batchTargets: scanArgsFromRequest 的字段映射（与 -l 同口径）', () => {
  const out = scanArgsFromRequest(
    { url: 'http://x/', method: 'GET', ratePerSec: 9 },
    {
      url: 'http://t.local/p?id=1',
      method: 'post',
      body: '{"a":1}',
      headers: { Cookie: 'sid=a', Host: 't.local', 'Content-Length': '9', 'X-Trace': 't1' },
    },
  );
  assert.equal(out.url, 'http://t.local/p?id=1');
  assert.equal(out.method, 'POST', '方法要归一成大写');
  assert.equal(out.body, '{"a":1}');
  assert.equal(out.cookie, 'sid=a');
  assert.deepEqual(out.headerObj, { 'X-Trace': 't1' }, 'host/content-length 不该进 headerObj');
  assert.equal(out.ratePerSec, 9, '未覆盖的字段必须原样透传');
});

// ⑨ 空文件 / 空内容：不抛，且给出原因
test('batchTargets: 空内容不抛且给出原因', () => {
  const r = expandBatchTargets('');
  assert.deepEqual(r.items, []);
  assert.ok(r.warnings.length >= 1);
});

// ⑩ multipart 与不可转 JSON 的 body：**跳过并点名**，而不是带着坏 body 去扫
//   真机教训：urlencoded body 留到扫描期才 JSON.parse ⇒ 整条目标崩
//   （`Unexpected token 'a', "name=alice" is not valid JSON`）；multipart 则会塌成垃圾键。
test('batchTargets: multipart / 不可转 JSON 的 body 跳过并点名', () => {
  const mk = (postData) => JSON.stringify({
    log: { entries: [{ request: {
      method: 'POST',
      url: 'http://t.local/up',
      headers: [{ name: 'Content-Type', value: 'multipart/form-data; boundary=--x' }],
      postData,
    } }] },
  });
  const mp = expandBatchTargets(mk({ text: '--x\r\nContent-Disposition: form-data; name="f"\r\n\r\n1\r\n--x--' }));
  assert.equal(mp.items.length, 0, 'multipart 条目应被跳过');
  assert.equal(mp.skipped, 1);
  assert.ok(mp.warnings.some((w) => /multipart/.test(w)), `未点名 multipart：${JSON.stringify(mp.warnings)}`);

  // 非 multipart 但转不出 JSON 的 body（裸 SOAP/XML 之类）
  const bad = expandBatchTargets(JSON.stringify({
    log: { entries: [{ request: {
      method: 'POST',
      url: 'http://t.local/soap',
      headers: [{ name: 'Content-Type', value: 'text/xml' }],
      postData: { text: '<soap:Envelope/>' },
    } }] },
  }));
  assert.equal(bad.items.length, 0);
  assert.ok(bad.warnings.some((w) => /无法转成 JSON/.test(w)), `未点名不可转 JSON 的 body：${JSON.stringify(bad.warnings)}`);
});

// ⑪ urlencoded body 必须在展开期就转成 JSON（不是留到扫描期）
test('batchTargets: urlencoded body 在展开期已 JSON 化', () => {
  const r = expandBatchTargets(HAR);
  const post = r.items.find((i) => i.method === 'POST');
  assert.ok(post);
  assert.doesNotThrow(() => JSON.parse(post.body), `展开出的 body 必须能被 JSON.parse：${post.body}`);
});
