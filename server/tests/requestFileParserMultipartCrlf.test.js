// ============================================================================
// tests/requestFileParserMultipartCrlf.test.js
// multipart/form-data 解析在各种行结束符下必须一致
//
// ⚠️ **本文件最初基于一个错误结论写成，现已订正 —— 记录在此以免重犯。**
//
// 初版断言"CRLF 下 multipart 解析全空"，理由是分段处用了
//     part.indexOf('\n\n')
// 而 CRLF 下头体之间的空行是 "\r\n\r\n"，两个 \n 之间夹着 \r ⇒ 找不到。
//
// **实测证明该结论是错的**：core/requestFileParser.js 第 51 行
//     const body = bodyParts.join('\n').trim();
// bodyParts 的元素来自 `trimmed.split(/\r?\n/)` —— 即**所有行结束符在此
// 已被统一成 LF**，之后 multipart 分段拿到的 body 永远是 LF 文本，
// `indexOf('\n\n')` 必然找得到。实测 LF 与 CRLF 输入得到完全相同的
// bodyFields { id: "42", q: "hello" }。
//
// 误判的来源：取证脚本里写了 `.replace(/\n/g, eol)` 做行结束符转换，
// 而 `multipartReq()` 内部**已经**用 eol join 过了 —— 换行符被替换了两次，
// 造出了一份现实中不存在的输入，于是"复现"了一个假缺陷。
//
// 这条与本项目反复出现的教训同源：**守卫的判据必须比被测对象更精确，
// 且"红"要能自证是真缺陷而不是构造错误**。一个基于假缺陷写出的红基线，
// 会把正确代码"修"坏。
//
// ── 本文件现在的价值 ────────────────────────────────────────────────────────
// 它锁定的是一条**真实存在但容易被误改**的性质：行结束符归一发生在
// `join('\n')` 这一处，下游 multipart/urlencoded/JSON 三条路径都依赖它。
// 若有人日后把 join 改成 join(eol) 或改成 `join('\n\n')`，三处会同时坏掉。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRequestFile } from '../src/core/requestFileParser.js';

const CT = 'multipart/form-data; boundary=X';

/** 按指定行结束符拼一份 multipart 请求文件（注意：只 join 一次） */
function multipartReq(eol, parts) {
  // parts 是"字段行数组"的数组 —— 先摊平再 join，避免行结束符被替换两次
  const body = [...parts.flat(), '--X--', ''].join(eol);
  return [
    'POST /upload HTTP/1.1',
    'Host: t.test',
    `Content-Type: ${CT}`,
    '',
    body,
  ].join(eol) + eol;
}

const part = (name, value, extra = '') => [
  '--X',
  `Content-Disposition: form-data; name="${name}"${extra}`,
  '',
  value,
];

test('自证-0) LF 与 CRLF 输入必须给出完全相同的结果（这才是本组要守的性质）', () => {
  const parts = [part('id', '42'), part('q', 'hello')];
  const lf = parseRequestFile(multipartReq('\n', parts));
  const crlf = parseRequestFile(multipartReq('\r\n', parts));
  assert.deepEqual(lf.bodyFields, { id: '42', q: 'hello' }, 'LF 下解析错误');
  assert.deepEqual(crlf.bodyFields, lf.bodyFields,
    `CRLF=${JSON.stringify(crlf.bodyFields)} ≠ LF=${JSON.stringify(lf.bodyFields)}`);
  assert.deepEqual(crlf.params, lf.params, 'params 在两种行结束符下必须一致');
});

test('契约-1) 行结束符归一发生在 join("\\n") 一处（不得改成保留原行结束符）', () => {
  // 下游 multipart 的 indexOf('\n\n')、urlencoded 的 split('&')、JSON 的 JSON.parse
  // 全部依赖 body 是 LF 文本。若有人改成 join(eol)，CRLF 输入下 multipart 会静默失效。
  const crlf = parseRequestFile(multipartReq('\r\n', [part('id', '42')]));
  assert.ok(!crlf.body.includes('\r'),
    `parseRequestFile 返回的 body 仍含 CR（${JSON.stringify(crlf.body.slice(0, 40))}）`
    + ' ⇒ 行结束符未归一，下游 multipart 的 indexOf("\\n\\n") 将失效');
  assert.ok(crlf.body.includes('\n\n'), '归一后 body 应含 LF 空行');
});

test('契约-2) 混合行结束符也必须解析出一致结果', () => {
  const mixed = 'POST /upload HTTP/1.1\r\nHost: t.test\nContent-Type: ' + CT + '\r\n\r\n'
    + '--X\r\nContent-Disposition: form-data; name="id"\r\n\n42\r\n'
    + '--X\nContent-Disposition: form-data; name="q"\n\nhello\n--X--\r\n';
  const r = parseRequestFile(mixed);
  assert.deepEqual(r.bodyFields, { id: '42', q: 'hello' },
    `混合行结束符下 bodyFields 为 ${JSON.stringify(r.bodyFields)}`);
});

test('契约-3) 多行字段值在两种行结束符下取值相同', () => {
  const build = (eol) => multipartReq(eol, [
    part('c', ['multi', 'line', 'value'].join(eol)),
    part('f', 'BIN', '; filename="x.txt"'),
  ]);
  const lf = parseRequestFile(build('\n'));
  const crlf = parseRequestFile(build('\r\n'));
  assert.equal(lf.bodyFields.c, 'multi\nline\nvalue', `LF 下多行值=${JSON.stringify(lf.bodyFields.c)}`);
  assert.equal(crlf.bodyFields.c, lf.bodyFields.c,
    `CRLF 下多行值=${JSON.stringify(crlf.bodyFields.c)} ≠ LF=${JSON.stringify(lf.bodyFields.c)}`);
  assert.equal(crlf.bodyFields.f, 'x.txt', '文件字段应取 filename');
});

test('契约-4) urlencoded / JSON 路径在 CRLF 下同样一致', () => {
  const urlenc = ['POST /a HTTP/1.1', 'Host: t.test',
    'Content-Type: application/x-www-form-urlencoded', '', 'id=42&q=hello'].join('\r\n');
  assert.equal(parseRequestFile(urlenc).bodyFields.q, 'hello', 'urlencoded CRLF 解析错误');

  const json = ['POST /a HTTP/1.1', 'Host: t.test',
    'Content-Type: application/json', '', '{"id":42,"q":"hi"}'].join('\r\n');
  assert.equal(parseRequestFile(json).bodyFields.id, '42', 'JSON CRLF 解析错误');
});

test('契约-5) 缺 Content-Type 时不得误判为 multipart（防判据放宽过头）', () => {
  const body = ['--X', 'Content-Disposition: form-data; name="id"', '', '42', '--X--', ''].join('\r\n');
  const req = ['POST /a HTTP/1.1', 'Host: t.test', '', body].join('\r\n');
  assert.deepEqual(parseRequestFile(req).bodyFields, {}, '无 Content-Type 时不应提取 multipart 字段');
});