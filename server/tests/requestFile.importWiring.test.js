// ============================================================================
// requestFile.importWiring.test.js —— -r 抓包导入的**接线**契约（不是解析器单测）
// ============================================================================
// 为什么另开一支：`requestFileParser.multipart.test.js` 早就存在并且全绿，它测的是
// parseRequestFile 把 multipart 的三个字段抽出来——那一步**一直是对的**。
// 坏在下面一层：applyRequestFile 丢开解析器抽好的字段，把原始 body 塞进
// bodyToJsonString 的 urlencoded 启发式。multipart 里没有 '&'、只有 `name="…"` 里的 '='，
// 于是整份 body 塌成**一个**键，键名是 `--<boundary>\r\nContent-Disposition: form-data; name`。
// 结果：扫描正常跑完、0 检出、没有任何告警。
// 可复用的教训：**只测被调函数、不测调用链**，就会出现"测试全绿而入口是坏的"。
// 所以本文件一律从 applyRequestFile 进、从引擎收到的注入点出。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseArgs, applyRequestFile, resolveBodyChannel } from '../bin/cli.js';
import { TargetParser } from '../src/engine/TargetParser.js';
import { createTarget } from '../src/engine/models.js';

const B = '----WebKitFormBoundary7MA4';

const multipartReq = [
  'POST /profile/avatar?sid=9 HTTP/1.1',
  'Host: shop.example.com',
  `Content-Type: multipart/form-data; boundary=${B}`,
  'Cookie: session=abc123',
  '',
  `--${B}`,
  'Content-Disposition: form-data; name="username"',
  '',
  "ali'ce",
  `--${B}`,
  'Content-Disposition: form-data; name="caption"',
  '',
  'hello world',
  `--${B}`,
  'Content-Disposition: form-data; name="avatar"; filename="cat.png"',
  'Content-Type: image/png',
  '',
  'PNGDATA',
  `--${B}--`,
  '',
].join('\r\n');

/** 把一份请求文本走真 -r，返回递给引擎的 args */
async function viaDashR(reqText, write) {
  const f = await write('r-wiring.req', reqText);
  let args = parseArgs(['node', 'cli', '-r', f]);
  args = applyRequestFile(args);
  assert.ok(args, 'applyRequestFile 不该返回 null（解析失败）');
  return args;
}

async function withTmp() {
  const dir = await mkdtemp(path.join(tmpdir(), 'r-wiring-'));
  return {
    async write(name, text) { const p = path.join(dir, name); await writeFile(p, text, 'utf8'); return p; },
    async done() { await rm(dir, { recursive: true, force: true }); },
  };
}

async function bodyPoints(args) {
  const { bodyParams, jsonBody } = resolveBodyChannel(args.body ? JSON.parse(args.body) : {});
  const t = createTarget({
    url: args.url,
    method: args.method,
    bodyParams,
    jsonBody,
    fileParts: args.fileParts || [], // [D159] 文件字段单独成点
    config: { level: 1 },
  });
  const pts = await new TargetParser().discover(t);
  return pts.filter((p) => p.location === 'body').map((p) => p.param);
}

test('multipart -r：真实字段进引擎，绝不出现以 boundary 命名的垃圾键', async () => {
  const t = await withTmp();
  try {
    const args = await viaDashR(multipartReq, (n, c) => t.write(n, c));
    const parsed = JSON.parse(args.body);
    // [D159 2026-10-25 推翻记录] 本断言原为 ['avatar','caption','username']（文件字段混进
    // bodyFields）。文件字段的 filename 不是「可按 urlencoded 重发的值」——混进去会让发送侧
    // 把它当文本字段发、`filename` 属性消失，目标读到的文件名永远是空 ⇒ 注入值不进 SQL。
    // 现在文本字段进 bodyParams，文件字段单独走 args.fileParts。旧断言的那半句
    //「文件字段应取 filename」保留在新断言里（值没丢，只是换了通道）。
    assert.deepEqual(Object.keys(parsed).sort(), ['caption', 'username'],
      `-r 之后 body 只应剩文本字段，实际：${JSON.stringify(parsed)}`);
    assert.deepEqual(args.fileParts, [{ name: 'avatar', filename: 'cat.png', contentType: 'image/png' }],
      '文件字段必须按 name/filename/contentType 单独带走（发送侧据此重建 multipart）');
    const params = await bodyPoints(args);
    assert.deepEqual(params.sort(), ['avatar', 'caption', 'username'],
      '三个字段都必须成为注入点：文本字段走 bodyParams，文件字段走 fileParts');
    for (const p of params) {
      assert.ok(!/Content-Disposition|boundary/i.test(p), `注入点键名不该带 multipart 原文，实际：${p}`);
    }
  } finally { await t.done(); }
});

// [D159 2026-10-25 推翻记录] 原断言：「必须丢掉已对不上的 multipart Content-Type」。
// 那条成立于「引擎只能发 urlencoded」的时代——声明与实际不符确实更糟。但现在引擎会
// 按 boundary 重建 multipart（injection.js buildMultipartBody，e2e/pentest-lab /mp 与
// 本轮新增的 e2e/detect-surface-lab /api/upload 都是端到端证据），保留 Content-Type
// 才是「声明与实体一致」；丢掉它反而是把 multipart-only 目标推回 415。
test('multipart -r：保留 multipart Content-Type（发送侧按 boundary 重建报文）', async () => {
  const t = await withTmp();
  try {
    const args = await viaDashR(multipartReq, (n, c) => t.write(n, c));
    const ctKeys = Object.keys(args.headerObj || {}).filter((k) => /^content-type$/i.test(k));
    assert.deepEqual(ctKeys, ['Content-Type'], `headerObj 应保留 Content-Type，实际：${JSON.stringify(args.headerObj)}`);
    assert.match(String(args.headerObj['Content-Type']), /^multipart\/form-data;\s*boundary=/i,
      '声明的 Content-Type 必须仍是 multipart 且带 boundary');
  } finally { await t.done(); }
});

test('multipart -r：query 参数不能被混进 body（bodyFields 与 params 必须分开）', async () => {
  const t = await withTmp();
  try {
    const args = await viaDashR(multipartReq, (n, c) => t.write(n, c));
    const parsed = JSON.parse(args.body);
    assert.ok(!('sid' in parsed), 'sid 是 query 参数，不该出现在 body 里');
    assert.ok(/sid=9/.test(args.url), 'query 仍应留在 URL 上');
  } finally { await t.done(); }
});

test('urlencoded -r：既有行为不变（不能被 multipart 分支波及）', async () => {
  const t = await withTmp();
  try {
    const req = [
      'POST /login HTTP/1.1', 'Host: shop.example.com',
      'Content-Type: application/x-www-form-urlencoded', '',
      'user=alice&pass=pw%201', '',
    ].join('\r\n');
    const args = await viaDashR(req, (n, c) => t.write(n, c));
    assert.deepEqual(JSON.parse(args.body), { user: 'alice', pass: 'pw 1' });
    assert.deepEqual((await bodyPoints(args)).sort(), ['pass', 'user']);
  } finally { await t.done(); }
});

test('JSON -r：原样交给 jsonBody 通道，不经 urlencoded 启发式', async () => {
  const t = await withTmp();
  try {
    const req = [
      'POST /api/order HTTP/1.1', 'Host: shop.example.com',
      'Content-Type: application/json', '',
      '{"user":{"id":1},"note":"hi"}', '',
    ].join('\r\n');
    const args = await viaDashR(req, (n, c) => t.write(n, c));
    assert.deepEqual(JSON.parse(args.body), { user: { id: 1 }, note: 'hi' });
    assert.deepEqual((await bodyPoints(args)).sort(), ['note', 'user.id']);
  } finally { await t.done(); }
});

// [D160 2026-10-25] 声明 JSON 但 body 非法：必须出声。
// 旧行为静默丢 body ⇒ 0 个 body 点、扫描照常跑完、报告写「未检出」——与「没洞」同形。
test('[D160] JSON -r：CT=json 但 body 非法时显式告警（不静默丢 body）', async () => {
  const t = await withTmp();
  const warns = [];
  const origWarn = console.warn;
  console.warn = (...a) => { warns.push(a.join(' ')); };
  try {
    const req = [
      'POST /api/order HTTP/1.1', 'Host: shop.example.com',
      'Content-Type: application/json', '',
      '{"user":{"id":1},  <-- 被截断', '',
    ].join('\r\n');
    const args = await viaDashR(req, (n, c) => t.write(n, c));
    assert.ok(!args.body, `非法 JSON 不该被塞进 body（否则引擎会再崩一次），实际：${JSON.stringify(args.body)}`);
    const hit = warns.find((w) => /body 不是合法 JSON/.test(w));
    assert.ok(hit, `必须显式告警，实际 warn：${JSON.stringify(warns)}`);
    assert.match(hit, /未检出.*不代表没有注入/, '告警必须点明「未检出」不可当作阴性结论');
  } finally {
    console.warn = origWarn;
    await t.done();
  }
});
