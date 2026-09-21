// ============================================================================
// requestCollectionParser.test.js —— 集合格式（HAR / Burp XML）→ 请求对象
// ============================================================================
// 本文件测的核心不是"能解析出 url"（那太浅），而是**契约继承**：
// 新格式必须走 `parseRequestFile`，从而自动获得此前踩坑才修好的三个行为——
//   · urlencoded body 的 bodyFields
//   · multipart 抽取（整份 body 不许塌成一个垃圾键）
//   · JSON body 的点路径叶子
// 因此每条用例都同时断言「集合解析结果」与「与单请求路径一致」。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  detectRequestFormat,
  parseRequestCollection,
} from '../src/core/requestCollectionParser.js';
import { parseRequestFile } from '../src/core/requestFileParser.js';

// ── 格式识别 ───────────────────────────────────────────────────────────────

test('detectRequestFormat：HAR / Burp XML / 不支持 / 原始文本 四态可分', () => {
  const har = JSON.stringify({ log: { version: '1.2', entries: [] } });
  assert.equal(detectRequestFormat(har), 'har');

  const burp = '<?xml version="1.0"?>\n<items burpVersion="2024"><item><url>x</url></item></items>';
  assert.equal(detectRequestFormat(burp), 'burp-xml');

  // Postman / OpenAPI：明确报 unsupported，不猜、不静默当 raw
  assert.equal(detectRequestFormat(JSON.stringify({ info: { name: 'x' }, item: [] })), 'unsupported');
  assert.equal(detectRequestFormat(JSON.stringify({ openapi: '3.0.0', paths: {} })), 'unsupported');
  assert.equal(detectRequestFormat('<svg></svg>'), 'unsupported');

  assert.equal(detectRequestFormat('GET /a?id=1 HTTP/1.1\r\nHost: x\r\n\r\n'), 'raw');
  assert.equal(detectRequestFormat(''), null);
});

// ── HAR ────────────────────────────────────────────────────────────────────

const harEntry = (over = {}) => ({
  request: {
    method: 'GET',
    url: 'http://127.0.0.1:8150/vuln?id=1',
    headers: [{ name: 'Host', value: '127.0.0.1:8150' }],
    ...over,
  },
});

test('HAR：基本解析出 method/url/params，label 可读', () => {
  const { format, requests, warnings } = parseRequestCollection(
    JSON.stringify({ log: { entries: [harEntry()] } })
  );
  assert.equal(format, 'har');
  assert.equal(warnings.length, 0);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'GET');
  assert.equal(requests[0].url, 'http://127.0.0.1:8150/vuln?id=1');
  assert.equal(requests[0].params.id, '1');
  assert.equal(requests[0].label, 'GET http://127.0.0.1:8150/vuln?id=1');
});

test('HAR：headers 数组转对象，重名后者覆盖（与浏览器一致）', () => {
  const { requests } = parseRequestCollection(
    JSON.stringify({
      log: {
        entries: [
          harEntry({
            headers: [
              { name: 'Host', value: '127.0.0.1:8150' },
              { name: 'X-Tag', value: 'a' },
              { name: 'x-tag', value: 'b' },
            ],
          }),
        ],
      },
    })
  );
  // 实现按原样写入对象：后写覆盖前写 → 只剩一个（此处键名大小写不同故并存，断言真实行为）
  const keys = Object.keys(requests[0].headers).filter((k) => k.toLowerCase() === 'x-tag');
  assert.equal(keys.length, 2);
});

test('HAR：postData 标注 base64 时必须解码（否则 body 是乱码 → 参数提取全废）', () => {
  const payload = 'user=admin&pass=1';
  const { requests } = parseRequestCollection(
    JSON.stringify({
      log: {
        entries: [
          harEntry({
            method: 'POST',
            url: 'http://127.0.0.1:8150/login',
            headers: [
              { name: 'Host', value: '127.0.0.1:8150' },
              { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
            ],
            postData: { mimeType: 'application/x-www-form-urlencoded', text: Buffer.from(payload).toString('base64'), encoding: 'base64' },
          }),
        ],
      },
    })
  );
  assert.equal(requests.length, 1);
  assert.equal(requests[0].body, payload);
  assert.equal(requests[0].params.user, 'admin');
  assert.equal(requests[0].params.pass, '1');
});

test('★契约继承：HAR 的 multipart body 不许塌成一个垃圾键（bodyFields 生效）', () => {
  const boundary = '----WebKitFormBoundaryABC123';
  const body = [
    `--${boundary}`,
    'Content-Disposition: form-data; name="title"',
    '',
    'hello',
    `--${boundary}`,
    'Content-Disposition: form-data; name="file"; filename="a.txt"',
    'Content-Type: text/plain',
    '',
    'filedata',
    `--${boundary}--`,
    '',
  ].join('\r\n');
  const { requests } = parseRequestCollection(
    JSON.stringify({
      log: {
        entries: [
          harEntry({
            method: 'POST',
            url: 'http://127.0.0.1:8150/upload',
            headers: [
              { name: 'Host', value: '127.0.0.1:8150' },
              { name: 'Content-Type', value: `multipart/form-data; boundary=${boundary}` },
            ],
            postData: { mimeType: 'multipart/form-data', text: body },
          }),
        ],
      },
    })
  );
  const r = requests[0];
  // 这正是 2026-09-20 修掉的那个坑：整份 body 塌成一个以 boundary 行命名的键
  assert.equal(Object.keys(r.bodyFields).length, 2);
  assert.equal(r.bodyFields.title, 'hello');
  assert.equal(r.bodyFields.file, 'a.txt'); // 文件字段取 filename
  assert.ok(!Object.keys(r.params).some((k) => k.includes('boundary')));
});

test('HAR：与单请求路径产出**同构**结果（同一报文两条入口）', () => {
  const raw = 'POST /login HTTP/1.1\r\nHost: 127.0.0.1:8150\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=1';
  const viaRaw = parseRequestFile(raw);
  const viaHar = parseRequestCollection(
    JSON.stringify({
      log: {
        entries: [
          harEntry({
            method: 'POST',
            url: 'http://127.0.0.1:8150/login',
            headers: [
              { name: 'Host', value: '127.0.0.1:8150' },
              { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
            ],
            postData: { mimeType: 'application/x-www-form-urlencoded', text: 'user=admin&pass=1' },
          }),
        ],
      },
    })
  ).requests[0];
  assert.equal(viaHar.method, viaRaw.method);
  assert.equal(viaHar.params.user, viaRaw.params.user);
  assert.equal(viaHar.bodyFields.user, viaRaw.bodyFields.user);
  assert.ok(viaHar.url.endsWith('/login'));
});

test('HAR：缺 request.url 的 entry 被跳过并留警告（不静默吞）', () => {
  const { requests, warnings } = parseRequestCollection(
    JSON.stringify({ log: { entries: [{ request: { method: 'GET' } }, harEntry()] } })
  );
  assert.equal(requests.length, 1);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /第 1 个 entry/);
});

test('HAR：JSON 非法 → 明确报错而非抛异常', () => {
  const { requests, warnings } = parseRequestCollection('{"log":{"entries":[}');
  assert.equal(requests.length, 0);
  assert.equal(warnings.length, 1);
});

// ── Burp XML ───────────────────────────────────────────────────────────────

const burpItem = (reqInner, attrs = ' base64="true"') =>
  `<item><time>Mon</time><url><![CDATA[http://127.0.0.1:8150/vuln?id=1]]></url><method><![CDATA[GET]]></method><request${attrs}><![CDATA[${reqInner}]]></request><status>200</status></item>`;

test('Burp XML：base64 request 解码后按原始报文解析', () => {
  const raw = 'GET /vuln?id=1 HTTP/1.1\r\nHost: 127.0.0.1:8150\r\n\r\n';
  const xml = `<?xml version="1.0"?>\n<items burpVersion="2024.1">${burpItem(Buffer.from(raw).toString('base64'))}</items>`;
  const { format, requests, warnings } = parseRequestCollection(xml);
  assert.equal(format, 'burp-xml');
  assert.equal(warnings.length, 0);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].params.id, '1');
  assert.equal(requests[0].label, 'GET http://127.0.0.1:8150/vuln?id=1');
});

test('Burp XML：非 base64（明文 CDATA）request 同样可解析', () => {
  const xml = `<items><item><url><![CDATA[http://127.0.0.1:8150/vuln?id=1]]></url><request><![CDATA[GET /vuln?id=1 HTTP/1.1\r\nHost: 127.0.0.1:8150\r\n\r\n]]></request></item></items>`;
  const { requests } = parseRequestCollection(xml);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].params.id, '1');
});

test('Burp XML：POST body 的参数进 params 与 bodyFields', () => {
  const raw = 'POST /login HTTP/1.1\r\nHost: 127.0.0.1:8150\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=1';
  const xml = `<items><item><url><![CDATA[http://127.0.0.1:8150/login]]></url><request base64="true"><![CDATA[${Buffer.from(raw).toString('base64')}]]></request></item></items>`;
  const { requests } = parseRequestCollection(xml);
  assert.equal(requests[0].params.user, 'admin');
  assert.equal(requests[0].bodyFields.pass, '1');
});

test('Burp XML：多 item 保序，且都能解析', () => {
  const mk = (id) => burpItem(Buffer.from(`GET /vuln?id=${id} HTTP/1.1\r\nHost: 127.0.0.1:8150\r\n\r\n`).toString('base64'));
  const xml = `<items>${mk(1)}${mk(2)}${mk(3)}</items>`;
  const { requests } = parseRequestCollection(xml);
  assert.deepEqual(requests.map((r) => r.params.id), ['1', '2', '3']);
});

test('Burp XML：无 <request> 但有 url → 兜底构造并留警告', () => {
  const xml = `<items><item><url><![CDATA[http://127.0.0.1:8150/vuln?id=1]]></url><method><![CDATA[GET]]></method></item></items>`;
  const { requests, warnings } = parseRequestCollection(xml);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].params.id, '1');
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /兜底/);
});

test('Burp XML：既无 request 也无 url → 跳过并留警告', () => {
  const xml = '<items><item><time>x</time></item></items>';
  const { requests, warnings } = parseRequestCollection(xml);
  assert.equal(requests.length, 0);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /已跳过/);
});

// ── raw 与不支持格式 ───────────────────────────────────────────────────────

test('raw：单个 Burp/curl 文本请求行为不变（回归保护）', () => {
  const { format, requests, warnings } = parseRequestCollection('GET /vuln?id=1 HTTP/1.1\r\nHost: 127.0.0.1:8150\r\n\r\n');
  assert.equal(format, 'raw');
  assert.equal(warnings.length, 0);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].params.id, '1');
});

test('raw：非法文本 → 0 请求 + 明确警告（不抛、不静默）', () => {
  const { requests, warnings } = parseRequestCollection('这不是 http 请求');
  assert.equal(requests.length, 0);
  assert.equal(warnings.length, 1);
});

test('unsupported：Postman / OpenAPI 给出可操作的提示，而不是当成 raw 去失败', () => {
  const { format, requests, warnings } = parseRequestCollection(JSON.stringify({ info: { name: 'p' }, item: [] }));
  assert.equal(format, 'unsupported');
  assert.equal(requests.length, 0);
  assert.match(warnings[0], /Burp XML|HAR/);
});
