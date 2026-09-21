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

  // [D1 二期 2026-09-21] Postman / OpenAPI 已支持 → 不再报 unsupported；
  // 真正不支持的只剩「非 Burp 的 XML」（不硬猜格式）
  assert.equal(detectRequestFormat(JSON.stringify({ info: { name: 'x' }, item: [] })), 'postman');
  assert.equal(detectRequestFormat(JSON.stringify({ openapi: '3.0.0', paths: {} })), 'openapi');
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

test('unsupported：非 Burp 的 XML 给出可操作的提示，而不是当成 raw 去失败', () => {
  const { format, requests, warnings } = parseRequestCollection('<feed><entry/></feed>');
  assert.equal(format, 'unsupported');
  assert.equal(requests.length, 0);
  assert.match(warnings[0], /Burp XML|HAR|Postman/);
});

// ── [D1 二期 2026-09-21] Postman Collection ───────────────────────────────

const POSTMAN = {
  info: { name: 'demo', schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json' },
  item: [
    {
      name: 'folder', // 嵌套 folder：必须递归展开（Postman 导出常态）
      item: [
        {
          name: 'login',
          request: {
            method: 'POST',
            url: 'http://shop.test/login',
            header: [{ key: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
            body: { mode: 'urlencoded', urlencoded: [{ key: 'user', value: 'admin' }, { key: 'pass', value: '1' }] },
          },
        },
      ],
    },
    {
      name: 'upload',
      request: {
        method: 'POST',
        url: { raw: 'http://shop.test/upload', protocol: 'http', host: ['shop', 'test'], path: ['upload'] },
        header: [{ key: 'X-Skip', value: 'no', disabled: true }],
        body: {
          mode: 'formdata',
          formdata: [
            { key: 'title', value: 'hello', type: 'text' },
            { key: 'file', type: 'file', src: 'C:/tmp/a.png' },
          ],
        },
      },
    },
    { name: 'tpl', request: { method: 'GET', url: '{{baseUrl}}/x?id=1' } }, // 变量 → 跳过
  ],
};

test('detectRequestFormat：Postman / OpenAPI / OpenAPI-YAML 各自可辨', () => {
  assert.equal(detectRequestFormat(JSON.stringify(POSTMAN)), 'postman');
  assert.equal(detectRequestFormat(JSON.stringify({ openapi: '3.0.0', paths: {} })), 'openapi');
  assert.equal(detectRequestFormat(JSON.stringify({ swagger: '2.0', paths: {} })), 'openapi');
  assert.equal(detectRequestFormat('openapi: 3.0.0\ninfo:\n  title: x'), 'openapi-yaml');
});

test('Postman：嵌套 folder 递归展开；变量占位被跳过并提示', () => {
  const { format, requests, warnings } = parseRequestCollection(JSON.stringify(POSTMAN));
  assert.equal(format, 'postman');
  assert.equal(requests.length, 2, 'folder 内的 login + upload 应被展开，含 {{}} 的 tpl 应跳过');
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].url, 'http://shop.test/login');
  assert.equal(requests[0].params.user, 'admin');
  assert.equal(requests[1].url, 'http://shop.test/upload');
  assert.ok(warnings.some((w) => w.includes('{{')), '变量占位必须给出可操作提示');
});

test('Postman：header 数组映射，disabled=true 的头被跳过', () => {
  const { requests } = parseRequestCollection(JSON.stringify(POSTMAN));
  const up = requests.find((r) => r.url.endsWith('/upload'));
  assert.ok(!Object.keys(up.headers).some((k) => /^x-skip$/i.test(k)), 'disabled 头不该进请求');
});

test('★Postman formdata → 真 multipart 报文，bodyFields 拿到真实字段名（不许塌成 boundary 键）', () => {
  const { requests } = parseRequestCollection(JSON.stringify(POSTMAN));
  const up = requests.find((r) => r.url.endsWith('/upload'));
  assert.match(String(up.headers['Content-Type'] || ''), /multipart\/form-data; boundary=/);
  assert.equal(up.bodyFields.title, 'hello');
  assert.equal(up.bodyFields.file, 'a.png', '文件字段取 filename，不是绝对路径');
  assert.ok(!Object.keys(up.params).some((k) => k.includes('boundary')));
});

test('Postman：url 只有对象形态（无 raw）时用 protocol/host/path/query 拼', () => {
  const pm = {
    info: { name: 'p' },
    item: [{
      request: {
        method: 'GET',
        url: { protocol: 'https', host: ['a', 'test'], path: ['api', 'v1', 'users'], query: [{ key: 'id', value: '7' }] },
      },
    }],
  };
  const { requests, warnings } = parseRequestCollection(JSON.stringify(pm));
  assert.equal(warnings.length, 0);
  assert.equal(requests[0].url, 'https://a.test/api/v1/users?id=7');
});

// ── [D1 二期 2026-09-21] OpenAPI / Swagger ────────────────────────────────

const OPENAPI = {
  openapi: '3.0.0',
  servers: [{ url: 'http://api.test' }],
  paths: {
    '/users/{id}': {
      get: {
        parameters: [
          { name: 'id', in: 'path', schema: { type: 'integer' } },
          { name: 'q', in: 'query', example: 'kbd' },
        ],
      },
    },
    '/login': {
      post: {
        requestBody: {
          content: { 'application/json': { schema: { type: 'object', properties: { user: { type: 'string' } } } } },
        },
      },
    },
  },
};

test('OpenAPI：servers + paths×methods 展开，path 参数替换、query 拼接', () => {
  const { format, requests } = parseRequestCollection(JSON.stringify(OPENAPI));
  assert.equal(format, 'openapi');
  assert.equal(requests.length, 2);
  const get = requests.find((r) => r.method === 'GET');
  assert.equal(get.url, 'http://api.test/users/1?q=kbd', 'path 参数用占位 1、query 用 example');
});

test('★OpenAPI 必带「这是接口定义而非抓包」的警示（不伪装成真请求）', () => {
  const { warnings } = parseRequestCollection(JSON.stringify(OPENAPI));
  const w = warnings.find((x) => x.includes('接口定义'));
  assert.ok(w, `必须显式标注样例性质，实际 warnings=${JSON.stringify(warnings)}`);
  assert.match(w, /占位/);
});

test('OpenAPI：requestBody 的 JSON schema 递归造样例并带上 Content-Type', () => {
  const { requests } = parseRequestCollection(JSON.stringify(OPENAPI));
  const post = requests.find((r) => r.method === 'POST');
  assert.equal(post.url, 'http://api.test/login');
  assert.match(String(post.headers['Content-Type'] || ''), /application\/json/);
  assert.match(String(post.body), /user/);
});

test('OpenAPI：缺 servers/host → 明确报无法拼地址，不产出假请求', () => {
  const { requests, warnings } = parseRequestCollection(JSON.stringify({ openapi: '3.0.0', paths: { '/a': { get: {} } } }));
  assert.equal(requests.length, 0);
  assert.match(warnings[0], /servers/);
});

test('OpenAPI：YAML 形式给出「转成 JSON」的可操作指引，而不是当成 raw 报解析失败', () => {
  const { format, requests, warnings } = parseRequestCollection('openapi: 3.0.0\ninfo:\n  title: t\npaths: {}\n');
  assert.equal(format, 'openapi-yaml');
  assert.equal(requests.length, 0);
  assert.match(warnings[0], /JSON/);
});
