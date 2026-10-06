// @vitest-environment node
// ============================================================================
// src/tests/requestParserBodyFieldsParity.test.ts
// 「body 注入字段提取」这条线的前端 ↔ 服务端契约（请求行首行之外的另一半）
//
// ── 为什么必须有 ────────────────────────────────────────────────────────────
// 既有 requestParser.serverParity.test.ts 只守住了**请求行首行**（方法集 +
// 版本可选性）。但请求解析在两端各有一份实现，真正会**分叉**的地方还有
// body 字段提取（multipart / urlencoded / JSON 三条路径）：
//
//   · 服务端 server/src/core/requestFileParser.js 的 bodyFields
//   · 前端  src/shared/requestParser.ts 的 extractBodyFields()
//
// 两份是**逐段照抄**的（同样的 `part.indexOf('\n\n')`、同样的
// `val.replace(/\r?\n$/, '')`、同样的 boundary 正则）。照抄意味着
// **改一份必然漏改另一份**，且没有任何东西会告诉你漏了。
//
// ── 实测到的分叉（2026-10-06）──────────────────────────────────────────────
// extractBodyFields 直接收到 CRLF body 时返回 {}，LF 时正常：
//
//     eol="\n"     bodyFields={"id":"42","q":"hello"}
//     eol="\r\n"   bodyFields={}
//
// 根因与 (requestParserMultipartCrlif 那条服务端同类判据) 完全一样：
// 分段处用 `part.indexOf('\n\n')`，而 CRLF 下头体之间的空行是 "\r\n\r\n"，
// 两个 \n 之间夹着 \r ⇒ 永远 -1 ⇒ head=整块、val='' ⇒ `if (val)` 永假。
//
// ⚠️ 当前前端 `parseRequestFile` 恰好没事，是因为它自己拼 body 时用 '\n'
// （逐行 `body += (body ? '\n' : '') + line`）。但 extractBodyFields 是
// **导出函数**，任何新调用方直接传 CRLF body 就会踩坑 ——
// 而服务端那份之所以没事，是因为 requestFileParser 里有 `join('\n')` 归一。
// 两端的"安全"来自**不同原因**，这本身就是语义漂移。
//
// 本测试的价值：让前端 extractBodyFields 对 CRLF 的行为与服务端一致，
// 且不管未来新增几个调用方，这个性质都不会破。
// ============================================================================

import { describe, it, expect } from 'vitest';
import { extractBodyFields } from '../shared/requestParser';

const CT_MP = 'multipart/form-data; boundary=X';
const CT_URLENC = 'application/x-www-form-urlencoded';
const CT_JSON = 'application/json';

const mpBody = (parts: string[][], eol: string) =>
  [...parts.map((p) => p.join(eol)), '--X--', ''].join(eol);

const run = (body: string, ct: string) => extractBodyFields(body, ct, {});

describe('body 字段提取：CRLF 与 LF 必须一致（前端与服务端同口径）', () => {
  // ── 自证：正常（LF）路径本来就对，否则本组守卫前提失效 ──
  it('自证-0: LF 行结束符下 multipart 正常提取', () => {
    const r = run(mpBody([['--X', 'Content-Disposition: form-data; name="id"', '', '42']], '\n'), CT_MP);
    expect(r.bodyFields).toEqual({ id: '42' });
  });

  it('自证-1: 服务端那份在同一输入下也不受影响（服务端有 join(\'\\n\') 归一）', async () => {
    // 服务端 parseRequestFile 会把行结束符统一成 LF，所以它的 CRLF 输入天然安全。
    // 这里只登记这个事实：前端不能依赖"调用方恰好归一了"这种巧合。
    const server = await import('../../server/src/core/requestFileParser.js');
    const raw = [
      'POST /u HTTP/1.1',
      'Host: t.test',
      `Content-Type: ${CT_MP}`,
      '',
      mpBody([['--X', 'Content-Disposition: form-data; name="id"', '', '42']], '\r\n'),
    ].join('\r\n');
    const parsed = server.parseRequestFile(raw);
    expect(parsed?.bodyFields).toEqual({ id: '42' });
  });

  // ── 缺陷：CRLF 下前端解析为空 ──
  it('缺陷-1: CRLF 行结束符下 multipart 必须提取出同样的字段', () => {
    const eol = '\r\n';
    const r = run(
      mpBody([['--X', 'Content-Disposition: form-data; name="id"', '', '42'],
        ['--X', 'Content-Disposition: form-data; name="q"', '', 'hello']], eol),
      CT_MP,
    );
    expect(r.bodyFields).toEqual({ id: '42', q: 'hello' });
  });

  it('缺陷-2: 混合行结束符也必须一致', () => {
    const body = '--X\r\nContent-Disposition: form-data; name="id"\r\n\r\n42\r\n'
      + '--X\nContent-Disposition: form-data; name="q"\n\nhello\n--X--\r\n';
    expect(run(body, CT_MP).bodyFields).toEqual({ id: '42', q: 'hello' });
  });

  // ── 契约：不得为通过本组守卫而放宽编码判定 ──
  it('契约-3: urlencoded / JSON 路径在 CRLF 下同样一致', () => {
    expect(run('id=42&q=hello', CT_URLENC).bodyFields).toEqual({ id: '42', q: 'hello' });
    expect(run('{"id":42,"q":"hi"}', CT_JSON).bodyFields).toEqual({ id: '42', q: 'hi' });
  });

  it('契约-4: 文件字段仍取 filename（CRLF 下不得回归）', () => {
    const eol = '\r\n';
    const r = run(
      mpBody([['--X', 'Content-Disposition: form-data; name="id"', '', '42'],
        ['--X', 'Content-Disposition: form-data; name="f"; filename="a.png"', '', 'BINARY']], eol),
      CT_MP,
    );
    expect(r.bodyFields.f).toBe('a.png');
    expect(r.bodyFields.id).toBe('42');
  });

  it('契约-5: 缺 Content-Type 时不得误判为 multipart（防判据放宽过头）', () => {
    const eol = '\r\n';
    const body = mpBody([['--X', 'Content-Disposition: form-data; name="id"', '', '42']], eol);
    expect(run(body, '').bodyFields).toEqual({});
  });

  it('契约-6: 空 body 与空 content-type 不得抛错', () => {
    expect(run('', CT_MP).bodyFields).toEqual({});
    expect(run('x', '').bodyFields).toEqual({});
  });

  // ── 空值字段的取值口径（注入⑥ 抓出守卫缺口后补的）──────────────────────
  // multipart 里 `if (val && ...)` 这个守卫**被一个"值恰好为空"的字段**守着：
  // 删掉它 ⇒ 该字段会以空串进 params/bodyFields，改变下发给引擎的注入候选。
  // 契约-3 用的是无换行的 urlencoded，压根走不到这条分支，所以一直漏着。
  it('契约-7: 值为空的 multipart 字段不得进入候选（空 ≠ 缺失）', () => {
    const eol = '\n';
    const r = run(mpBody([
      ['--X', 'Content-Disposition: form-data; name="empty"', '', ''],
      ['--X', 'Content-Disposition: form-data; name="full"', '', 'v'],
    ], eol), CT_MP);
    expect(r.params).toEqual({ full: 'v' });
    expect(r.bodyFields).toEqual({ full: 'v' });
  });

  it('契约-8: 同上，CRLF 下取值口径也必须一致', () => {
    const eol = '\r\n';
    const r = run(mpBody([
      ['--X', 'Content-Disposition: form-data; name="empty"', '', ''],
      ['--X', 'Content-Disposition: form-data; name="full"', '', 'v'],
    ], eol), CT_MP);
    expect(r.params).toEqual({ full: 'v' });
    expect(r.bodyFields).toEqual({ full: 'v' });
  });

  // ── urlencoded / JSON：这两条路线不依赖行结束符，但**取值口径**仍要钉住 ──
  // ⚠️ 注入③⑦（这两条路径改回用原始 body）不会让守卫变红 —— 这是**正确的**：
  //   它们的测试内容里没有换行符，改用哪个变量结果都一样。
  //   守卫必须诚实反映这一点，而不是靠一条"看起来能测到"的用例自我安慰。
  it('契约-9: urlencoded 空值字段与 JSON 空值字段的取值口径', () => {
    expect(run('a=&b=2', CT_URLENC).bodyFields).toEqual({ a: '', b: '2' });
    expect(run('{"a":"","b":2}', CT_JSON).bodyFields).toEqual({ a: '', b: '2' });
  });

  it('契约-10: JSON 嵌套叶子走点路径（两端口径一致）', () => {
    expect(run('{"u":{"id":1,"n":"x"}}', CT_JSON).bodyFields).toEqual({ 'u.id': '1', 'u.n': 'x' });
  });
});

describe('body 字段提取：两份实现的语义必须对齐（钉住共同口径）', () => {
  it('同名字段的优先级：query 优先，bodyFields 仍取 body 侧的值', () => {
    const params: Record<string, string> = { x: 'fromQuery' };
    const r = extractBodyFields('x=fromBody&y=1', CT_URLENC, params);
    expect(r.params.x).toBe('fromQuery');
    expect(r.bodyFields.x).toBe('fromBody');
    expect(r.params.y).toBe('1');
  });

  it('multipart 不得被 urlencoded 启发式吞掉（bodyFields 里不得出现 boundary 垃圾键）', () => {
    const eol = '\n';
    const r = run(mpBody([['--X', 'Content-Disposition: form-data; name="id"', '', '42']], eol), CT_MP);
    for (const k of Object.keys(r.params)) {
      expect(k).not.toContain('--X');
      expect(k).not.toContain('boundary');
    }
  });
});