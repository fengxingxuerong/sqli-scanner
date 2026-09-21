// ============================================================================
// requestCollection.importWiring.test.js —— 集合格式走真 `-r` 的**接线**契约
// ============================================================================
// 为什么另开一支（沿用 requestFile.importWiring 的立场）：
// 解析器单测全绿 ≠ 入口是好的。`requestFileParser.multipart.test.js` 曾经全绿，
// 而真入口把解析好的字段丢开、把原始 body 塞给 urlencoded 启发式 —— 扫描照跑、0 检出。
// 所以本文件一律**从 applyRequestFile 进、从 args 出**，断言的是"引擎实际会收到什么"。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseArgs, applyRequestFile, parseLogFile } from '../bin/cli.js';

async function withTmp() {
  const dir = await mkdtemp(path.join(tmpdir(), 'r-coll-'));
  return {
    async write(name, text) {
      const p = path.join(dir, name);
      await writeFile(p, text, 'utf8');
      return p;
    },
    async done() { await rm(dir, { recursive: true, force: true }); },
  };
}

/** 走真 -r：写文件 → parseArgs → applyRequestFile。返回 { args, out }（out 为 stderr 文本） */
async function viaDashR(text, name) {
  const tmp = await withTmp();
  try {
    const f = await tmp.write(name, text);
    const chunks = [];
    const orig = console.error;
    console.error = (...a) => chunks.push(a.join(' '));
    let args;
    try {
      args = applyRequestFile(parseArgs(['node', 'cli', '-r', f]));
    } finally {
      console.error = orig;
    }
    return { args, out: chunks.join('\n') };
  } finally {
    await tmp.done();
  }
}

const HAR = (entries) => JSON.stringify({ log: { version: '1.2', creator: { name: 't' }, entries } });
const harReq = (over = {}) => ({
  request: { method: 'GET', url: 'http://shop.example.com/search?q=Keyboard', headers: [{ name: 'Host', value: 'shop.example.com' }], ...over },
});

test('-r 吃 HAR：url/method/search 参数进 args（原先直接报"需为 Burp/curl 文本格式"）', async () => {
  const { args } = await viaDashR(HAR([harReq()]), 'x.har');
  assert.ok(args, 'applyRequestFile 不该返回 null');
  assert.equal(args.url, 'http://shop.example.com/search?q=Keyboard');
  assert.equal(args.method, 'GET');
});

test('-r 吃 Burp XML（base64 request）：走到与文本路径同一结果', async () => {
  const raw = 'GET /search?q=Keyboard HTTP/1.1\r\nHost: shop.example.com\r\n\r\n';
  const xml = `<items burpVersion="2024"><item><url><![CDATA[http://shop.example.com/search?q=Keyboard]]></url><request base64="true"><![CDATA[${Buffer.from(raw).toString('base64')}]]></request></item></items>`;
  const { args } = await viaDashR(xml, 'burp.xml');
  assert.ok(args);
  assert.equal(args.url, 'http://shop.example.com/search?q=Keyboard');
  assert.equal(args.method, 'GET');
});

test('-r 吃 HAR 的 POST urlencoded：body 参数进 args', async () => {
  const { args } = await viaDashR(
    HAR([
      harReq({
        method: 'POST',
        url: 'http://shop.example.com/login',
        headers: [
          { name: 'Host', value: 'shop.example.com' },
          { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
        ],
        postData: { mimeType: 'application/x-www-form-urlencoded', text: 'user=admin&pass=1' },
      }),
    ]),
    'post.har'
  );
  assert.ok(args);
  assert.equal(args.method, 'POST');
  assert.match(String(args.body || ''), /user|admin/);
});

test('★接线契约：HAR 导入 multipart 不许把 body 塌成一个以 boundary 命名的垃圾键', async () => {
  const B = '----WebKitFormBoundaryQ1';
  const body = [
    `--${B}`,
    'Content-Disposition: form-data; name="username"',
    '',
    "ali'ce",
    `--${B}`,
    'Content-Disposition: form-data; name="caption"',
    '',
    'hello world',
    `--${B}--`,
    '',
  ].join('\r\n');
  const { args } = await viaDashR(
    HAR([
      harReq({
        method: 'POST',
        url: 'http://shop.example.com/profile/avatar',
        headers: [
          { name: 'Host', value: 'shop.example.com' },
          { name: 'Content-Type', value: `multipart/form-data; boundary=${B}` },
        ],
        postData: { mimeType: 'multipart/form-data', text: body },
      }),
    ]),
    'mp.har'
  );
  assert.ok(args);
  const b = String(args.body || '');
  assert.ok(!b.includes('boundary'), `body 不应含 boundary 字样（塌陷特征），实际=${b.slice(0, 120)}`);
  assert.ok(b.includes('username') && b.includes('caption'), `body 应含真实字段名，实际=${b.slice(0, 120)}`);
  assert.ok(b.includes('hello world'));
});

test('-r 吃 HAR 多请求：只取第 1 个，且**明确打印**共几个（不静默）', async () => {
  const { args, out } = await viaDashR(
    HAR([
      harReq({ url: 'http://a.example.com/first?id=1' }),
      harReq({ url: 'http://b.example.com/second?id=2' }),
      harReq({ url: 'http://c.example.com/third?id=3' }),
    ]),
    'many.har'
  );
  assert.ok(args);
  assert.equal(args.url, 'http://a.example.com/first?id=1');
  assert.match(out, /共 3 个请求/);
  assert.match(out, /只扫描第 1 个/);
});

test('-r 吃 Postman 集合：嵌套 folder 展开后取第 1 个请求', async () => {
  const pm = {
    info: { name: 'p' },
    item: [
      {
        name: 'folder',
        item: [{ name: 'q', request: { method: 'GET', url: 'http://shop.example.com/search?q=Keyboard' } }],
      },
    ],
  };
  const { args } = await viaDashR(JSON.stringify(pm), 'p.postman.json');
  assert.ok(args, 'Postman 集合应能被 -r 导入（D1 二期）');
  assert.equal(args.url, 'http://shop.example.com/search?q=Keyboard');
  assert.equal(args.method, 'GET');
});

test('-r 遇到真正不支持的格式（非 Burp 的 XML）：返回 null 并说明当前支持什么', async () => {
  const { args, out } = await viaDashR('<feed><entry/></feed>', 'x.xml');
  assert.equal(args, null);
  assert.match(out, /Burp XML|HAR|Postman/);
});

test('回归保护：单个 Burp/curl 文本请求走 -r 行为完全不变', async () => {
  const raw = 'POST /login HTTP/1.1\r\nHost: shop.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=admin&pass=1';
  const { args } = await viaDashR(raw, 'plain.req');
  assert.ok(args);
  assert.equal(args.url, 'http://shop.example.com/login');
  assert.equal(args.method, 'POST');
  assert.match(String(args.body || ''), /user|admin/);
});

// ── -l 的 Burp XML 分支：修复前 headers 恒空 / body 恒 null ─────────────────

test('★-l 读 Burp XML 的 POST：必须有 body 与 headers（修复前恒为 null/{}）', async () => {
  const raw = 'POST /login HTTP/1.1\r\nHost: shop.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\nCookie: session=abc123\r\n\r\nuser=admin&pass=1';
  const xml = `<items burpVersion="2024"><item><url><![CDATA[http://shop.example.com/login]]></url><method><![CDATA[POST]]></method><request base64="true"><![CDATA[${Buffer.from(raw).toString('base64')}]]></request></item></items>`;
  const tmp = await withTmp();
  try {
    const f = await tmp.write('burp.xml', xml);
    const reqs = parseLogFile(f);
    assert.equal(reqs.length, 1);
    assert.equal(reqs[0].method, 'POST');
    // 修复前：body=null、headers={} → body 注入点拿不到、需登录目标扫不到
    assert.ok(reqs[0].body, 'body 不该为 null（POST 参数会整批丢失）');
    assert.match(String(reqs[0].body), /user=admin/);
    const hk = Object.keys(reqs[0].headers || {});
    assert.ok(hk.some((k) => /^cookie$/i.test(k)), `headers 应含 Cookie，实际=${hk.join(',')}`);
    assert.ok(hk.some((k) => /^content-type$/i.test(k)));
  } finally {
    await tmp.done();
  }
});

test('-l 读 Burp XML：仍按原语义过滤非 http 与不支持的方法（回归保护）', async () => {
  const mk = (method, url) =>
    `<item><url><![CDATA[${url}]]></url><method><![CDATA[${method}]]></method><request base64="true"><![CDATA[${Buffer.from(`${method} /x HTTP/1.1\r\nHost: a.com\r\n\r\n`).toString('base64')}]]></request></item>`;
  const xml = `<items>${mk('GET', 'http://a.com/ok')}${mk('OPTIONS', 'http://a.com/opt')}${mk('GET', 'ftp://a.com/x')}</items>`;
  const tmp = await withTmp();
  try {
    const f = await tmp.write('filter.xml', xml);
    const reqs = parseLogFile(f);
    assert.equal(reqs.length, 1);
    assert.equal(reqs[0].url, 'http://a.com/ok');
  } finally {
    await tmp.done();
  }
});
