import { describe, it, expect } from 'vitest';
import {
  tryAutoDetect,
  looksLikeRawRequest,
  parseRequestFile,
} from '../shared/requestParser';

// ── tryAutoDetect：原始 HTTP 请求 ──
describe('tryAutoDetect · 原始 HTTP 请求', () => {
  it('空输入与非请求文本返回 null', () => {
    expect(tryAutoDetect('')).toBeNull();
    expect(tryAutoDetect('   \n  ')).toBeNull();
    expect(tryAutoDetect('这是一段普通文本 http://x.com')).toBeNull();
  });

  it('绝对 URL 的 GET 请求：方法/URL 解析 + 噪声头剔除 + 自定义头保留', () => {
    const raw = [
      'GET http://example.com/item.php?id=1 HTTP/1.1',
      'Host: example.com',
      'User-Agent: Mozilla/5.0',
      'Sec-Fetch-Site: none',
      'X-Custom-Trace: abc123',
      '',
    ].join('\r\n');
    const r = tryAutoDetect(raw);
    expect(r).not.toBeNull();
    expect(r!.method).toBe('GET');
    expect(r!.url).toBe('http://example.com/item.php?id=1');
    const headers = JSON.parse(r!.headerText);
    // 噪声头与 sec-* 头剔除；Host 也属噪声（绝对 URL 场景无需回填）
    expect(headers).toEqual({ 'X-Custom-Trace': 'abc123' });
    expect(r!.cookieText).toBe('');
  });

  it('相对 URL 依赖 Host 头回填完整地址；缺失 Host 返回 null', () => {
    const withHost = [
      'GET /item.php?id=1 HTTP/1.1',
      'Host: example.com',
      '',
    ].join('\r\n');
    expect(tryAutoDetect(withHost)!.url).toBe('http://example.com/item.php?id=1');

    const noHost = 'GET /item.php?id=1 HTTP/1.1\r\nX-Other: 1\r\n';
    expect(tryAutoDetect(noHost)).toBeNull();
  });

  it('Cookie 头解析为 JSON 对象', () => {
    const raw = [
      'POST /login HTTP/1.1',
      'Host: example.com',
      'Cookie: PHPSESSID=abc123; theme=dark; broken',
      '',
    ].join('\r\n');
    const r = tryAutoDetect(raw)!;
    expect(JSON.parse(r.cookieText)).toEqual({ PHPSESSID: 'abc123', theme: 'dark' });
  });

  it('POST JSON body 归一为格式化 JSON', () => {
    const raw = [
      'POST /api/login HTTP/1.1',
      'Host: example.com',
      'Content-Type: application/json',
      '',
      '{"user":"admin","pass":"123"}',
    ].join('\r\n');
    const r = tryAutoDetect(raw)!;
    expect(r.method).toBe('POST');
    expect(JSON.parse(r.bodyText)).toEqual({ user: 'admin', pass: '123' });
  });

  it('POST form 表单体自动转为 JSON', () => {
    const raw = [
      'POST /login HTTP/1.1',
      'Host: example.com',
      '',
      'user=admin&pass=1%2B2&novalue',
    ].join('\r\n');
    const r = tryAutoDetect(raw)!;
    expect(JSON.parse(r.bodyText)).toEqual({ user: 'admin', pass: '1+2' });
  });
});

// ── tryAutoDetect：curl 命令 ──
describe('tryAutoDetect · curl 命令', () => {
  it('纯 URL curl 默认 GET', () => {
    const r = tryAutoDetect("curl 'http://x.com/a.php?id=1'")!;
    expect(r.method).toBe('GET');
    expect(r.url).toBe('http://x.com/a.php?id=1');
  });

  it('无 URL 的 curl 返回 null', () => {
    expect(tryAutoDetect('curl -X POST')).toBeNull();
  });

  it('-X POST + --data-raw：方法提升为 POST 且 body 保留', () => {
    const r = tryAutoDetect(
      "curl 'http://x.com/api' -X POST --data-raw '{\"a\":1}'"
    )!;
    expect(r.method).toBe('POST');
    expect(JSON.parse(r.bodyText)).toEqual({ a: 1 });
  });

  it('--data 使默认 GET 提升为 POST', () => {
    const r = tryAutoDetect("curl http://x.com/api -d 'a=1&b=2'")!;
    expect(r.method).toBe('POST');
    expect(JSON.parse(r.bodyText)).toEqual({ a: '1', b: '2' });
  });

  it('-H 头：噪声剔除、自定义保留、Cookie 单独归档', () => {
    const r = tryAutoDetect(
      "curl http://x.com/ -H 'User-Agent: curl/8' -H 'X-Token: t1' -H 'Cookie: sid=9'"
    )!;
    expect(JSON.parse(r.headerText)).toEqual({ 'X-Token': 't1' });
    expect(JSON.parse(r.cookieText)).toEqual({ sid: '9' });
  });

  it('-b/--cookie 短选项解析', () => {
    const r = tryAutoDetect("curl http://x.com/ --cookie 'a=1;b=2'")!;
    expect(JSON.parse(r.cookieText)).toEqual({ a: '1', b: '2' });
  });
});

// ── looksLikeRawRequest ──
describe('looksLikeRawRequest', () => {
  it('识别 HTTP 请求首行，大小写不敏感', () => {
    expect(looksLikeRawRequest('GET / HTTP/1.1')).toBe(true);
    expect(looksLikeRawRequest('  post /a HTTP/2')).toBe(true);
  });

  it('URL / curl / 普通文本不误判', () => {
    expect(looksLikeRawRequest('http://x.com/a.php?id=1')).toBe(false);
    expect(looksLikeRawRequest("curl http://x.com/")).toBe(false);
    expect(looksLikeRawRequest('GET')).toBe(false);
  });
});

// ── parseRequestFile（对标 sqlmap -r） ──
describe('parseRequestFile', () => {
  it('完整请求：URL query 提取为注入候选 params（含 URL 解码）', () => {
    const raw = [
      'GET /item.php?id=1&w=a%2Bb&flag HTTP/1.1',
      'Host: example.com',
      'Accept: */*',
      'X-Forwarded-For: 10.0.0.1',
      '',
    ].join('\r\n');
    const r = parseRequestFile(raw)!;
    expect(r.method).toBe('GET');
    expect(r.url).toBe('http://example.com/item.php?id=1&w=a%2Bb&flag');
    expect(r.params).toEqual({ id: '1', w: 'a+b', flag: '' });
    // 结构化 headers 不剔除噪声头，供导入后完整还原
    expect(r.headers).toEqual({ Host: 'example.com', Accept: '*/*', 'X-Forwarded-For': '10.0.0.1' });
    expect(r.cookieText).toBe('');
  });

  it('POST 带 Cookie 与 body 的完整导入', () => {
    const raw = [
      'POST /login HTTP/1.1',
      'Host: example.com',
      'Cookie: uid=7',
      '',
      'user=admin',
    ].join('\r\n');
    const r = parseRequestFile(raw)!;
    expect(r.method).toBe('POST');
    expect(JSON.parse(r.cookieText)).toEqual({ uid: '7' });
    expect(r.body).toBe('user=admin');
    expect(JSON.parse(r.bodyText)).toEqual({ user: 'admin' });
  });

  it('支持 BOM 前缀剥离（BOM 不影响首行匹配）', () => {
    const raw = '\uFEFFPOST /a HTTP/1.1\r\nHost: h.com\r\n';
    const r = parseRequestFile(raw)!;
    expect(r.method).toBe('POST');
    expect(r.url).toBe('http://h.com/a');
  });

  it('HEAD/OPTIONS 首行匹配但内部降级链不支持 → 返回 null（既有契约）', () => {
    // parseRequestFile 首行正则含 HEAD/OPTIONS，但 tryAutoDetect 仅识别
    // GET/POST/PUT/PATCH/DELETE，故 HEAD 请求文件当前返回 null
    expect(parseRequestFile('HEAD /a HTTP/1.1\r\nHost: h.com\r\n')).toBeNull();
  });

  it('空文本 / 非请求首行 / 缺 Host 返回 null', () => {
    expect(parseRequestFile('')).toBeNull();
    expect(parseRequestFile(null as unknown as string)).toBeNull();
    expect(parseRequestFile('not a request')).toBeNull();
    expect(parseRequestFile('GET /a HTTP/1.1\r\nX-Only: 1\r\n')).toBeNull();
  });
});

// ── body 编码分派：与服务端 requestFileParser 同口径 ──
// 这三条覆盖的是「前端导入 multipart/JSON 抓包拿不到字段名」的缺口：
// 以前 body 只有 urlencoded 启发式（toJsonText 里的 `=` 猜测），
// 粘贴 multipart 报文时整份 body 塌成一个以 boundary 行命名的垃圾键。
describe('parseRequestFile · body 编码分派', () => {
  it('multipart/form-data：text 字段进 params，文件字段取 filename', () => {
    const raw = [
      'POST /upload HTTP/1.1',
      'Host: up.example.com',
      'Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX',
      '',
      '------WebKitFormBoundaryX',
      'Content-Disposition: form-data; name="title"',
      '',
      'my report',
      '------WebKitFormBoundaryX',
      'Content-Disposition: form-data; name="avatar"; filename="a.png"',
      'Content-Type: image/png',
      '',
      'BINDATA',
      '------WebKitFormBoundaryX--',
    ].join('\r\n');
    const r = parseRequestFile(raw)!;
    expect(r.method).toBe('POST');
    expect(r.params.title).toBe('my report');
    expect(r.params.avatar).toBe('a.png'); // 文件字段值取 filename，不取二进制
    expect(r.body).toContain('BINDATA'); // body 原样保留，只读提取
    // bodyFields 只装来自 body 的字段（与 query 来源可区分）
    expect(r.bodyFields.title).toBe('my report');
    expect(r.bodyFields.avatar).toBe('a.png');
  });

  it('multipart 带引号 boundary + 无 boundary → 前者解析、后者不炸', () => {
    const quoted = [
      'POST /up HTTP/1.1',
      'Host: t.example.com',
      'Content-Type: multipart/form-data; boundary="QB-123"',
      '',
      '--QB-123',
      'Content-Disposition: form-data; name="q"',
      '',
      'v1',
      '--QB-123--',
    ].join('\r\n');
    expect(parseRequestFile(quoted)!.params.q).toBe('v1');

    const noB = [
      'POST /up HTTP/1.1',
      'Host: t.example.com',
      'Content-Type: multipart/form-data',
      '',
      'garbage',
    ].join('\r\n');
    const r = parseRequestFile(noB)!;
    expect(r.method).toBe('POST');
    expect('title' in r.params).toBe(false);
  });

  it('JSON body：顶层叶子并入 params，嵌套走点路径', () => {
    const raw = [
      'POST /api/user HTTP/1.1',
      'Host: api.example.com',
      'Content-Type: application/json',
      '',
      '{"user":{"id":7,"name":"bob"},"role":"admin"}',
    ].join('\r\n');
    const r = parseRequestFile(raw)!;
    expect(r.params['user.id']).toBe('7');
    expect(r.params['user.name']).toBe('bob');
    expect(r.params.role).toBe('admin');
    expect(r.bodyFields['user.id']).toBe('7');
  });
});
