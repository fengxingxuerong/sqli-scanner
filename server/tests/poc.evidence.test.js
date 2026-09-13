// ============================================================================
// tests/poc.evidence.test.js —— 可复现 PoC 证据链回归 [P0-FIX 2026-09-08]
//
// 覆盖三件事：
//   ① 四种注入点位（query / form / json body / header）的 PoC 结构正确，且 raw 报文
//      能被 core/requestFileParser.js 原样解析回来（存文件 → -r 导入 的逆运算闭环）；
//   ② payload 是攻击者可控串，curl 行会被粘进终端：含 ' $() 反引号 换行 时必须被引号
//      包住，不得逃逸出引号（否则「复现 PoC」本身成了命令执行入口）；
//   ③ 报告渲染侧：esc 覆盖引号（PoC 要塞进属性位）、safeHref 拒绝非 http(s)、
//      内网地址不可点击（报告在浏览器打开，点一下就是 SSRF）。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator, esc, safeHref, isInternalHost, renderUrlLink } from '../src/services/ReportGenerator.js';
import { buildPocRequest, buildPocEvidence, toCurl, toRawRequest } from '../src/engine/pocBuilder.js';
import { parseRequestFile } from '../src/core/requestFileParser.js';

const rg = new ReportGenerator();

// —— 公共夹具：与 injection.test.js 同构的 target/point ——
const baseTarget = (extra = {}) => ({
  mode: 'http',
  baseUrl: 'http://test.local/api/search?id=1',
  method: 'GET',
  bodyParams: {},
  cookieParams: { session: 'abc' },
  headerParams: { 'X-Api-Key': 'k1' },
  config: {},
  ...extra,
});

// 极简 shell 解析：把 curl 命令拆成「引号内文本」与「引号外文本」。
// 只认三种本模块会产出的形态：'...'、'\''（单引号转义）、$'...'（ANSI-C，含 \n \r \\ \'）。
function shellParse(cmd) {
  let literal = '';
  let outside = '';
  let i = 0;
  while (i < cmd.length) {
    const c = cmd[i];
    if (c === "'") {
      i++;
      while (i < cmd.length && cmd[i] !== "'") {
        literal += cmd[i];
        i++;
      }
      i++; // 闭合引号
      continue;
    }
    if (c === '\\' && cmd[i + 1] === "'") {
      literal += "'";
      i += 2;
      continue;
    }
    if (c === '$' && cmd[i + 1] === "'") {
      i += 2;
      while (i < cmd.length && cmd[i] !== "'") {
        if (cmd[i] === '\\') {
          const n = cmd[i + 1];
          literal += n === 'n' ? '\n' : n === 'r' ? '\r' : n;
          i += 2;
        } else {
          literal += cmd[i];
          i++;
        }
      }
      i++;
      continue;
    }
    outside += c;
    i++;
  }
  return { literal, outside };
}

// 断言：危险 shell 元字符只出现在引号内，且引号内文本原样还原 payload
function assertShellSafe(curl, payload) {
  const { literal, outside } = shellParse(curl);
  assert.ok(!/[$`;|&()<>\n\r\\]/.test(outside), `引号外出现 shell 元字符：${outside}`);
  assert.ok(!curl.includes('\n'), 'curl 必须是单行命令（换行会截断命令）');
  if (payload) assert.ok(literal.includes(payload), 'payload 应原样落在引号内');
}

// ---------------------------------------------------------------------------
// ① 四种点位的 PoC 结构
// ---------------------------------------------------------------------------

test('PoC/query 点位：GET 无 body，payload 编码进 URL，会话 Cookie 随请求带出', () => {
  const target = baseTarget();
  const point = { id: 'p1', location: 'url', param: 'id', originalValue: '1' };
  const poc = buildPocEvidence(target, point, "1' AND 1=1-- -");
  assert.equal(poc.method, 'GET');
  assert.equal(poc.body, '');
  assert.match(poc.url, /[?&]id=1%27\+AND\+1%3D1--\+-/);
  assert.equal(poc.headers.Cookie, 'session=abc'); // 登录后才可见的注入，不带 Cookie 就无法复现
  assert.equal(poc.headers['X-Api-Key'], 'k1');
  assert.ok(poc.curl.startsWith('curl -i -s -k -H'), poc.curl);
  assert.ok(poc.raw.startsWith('GET /api/search?'));
  assert.match(poc.raw, /HTTP\/1\.1\r\n/);
  assert.equal(typeof poc.generatedAt, 'string');
});

test('PoC/form 点位：POST + 全部表单字段保留（含 CSRF token），body 为 urlencoded', () => {
  const target = baseTarget({
    method: 'POST',
    baseUrl: 'http://test.local/api/search',
    headerParams: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  const point = {
    id: 'p2',
    location: 'body',
    param: 'user',
    originalValue: '1',
    formValues: { csrf: 'tok', user: '1' },
  };
  const poc = buildPocEvidence(target, point, "1' OR '1'='1");
  assert.equal(poc.method, 'POST');
  assert.match(poc.body, /^csrf=tok&user=1/);
  assert.match(poc.body, /OR/);
  assert.equal(poc.headers['Content-Type'], 'application/x-www-form-urlencoded');
  assert.ok(poc.curl.includes("--data '"), poc.curl);
  assert.ok(poc.curl.includes('-X')); // 非 GET 必须显式 -X，否则粘进终端会退化成 GET
  assert.match(poc.raw, /^POST \/api\/search HTTP\/1\.1\r\n/);
  assert.match(poc.raw, /Content-Length: \d+/);
});

test('PoC/json 点位：嵌套路径替换后整体重序列化，Content-Type 为 application/json', () => {
  const target = baseTarget({
    method: 'POST',
    baseUrl: 'http://test.local/api/v1/item',
    jsonBody: { user: { id: '1' }, tag: 'x' },
  });
  const point = { id: 'p3', location: 'body', param: 'user.id', originalValue: '1' };
  const poc = buildPocEvidence(target, point, "1\" UNION SELECT version()-- -");
  assert.equal(poc.headers['Content-Type'], 'application/json');
  const parsed = JSON.parse(poc.body);
  assert.equal(parsed.user.id, "1\" UNION SELECT version()-- -");
  assert.equal(parsed.tag, 'x'); // 兄弟字段必须原样保留，否则服务器可能直接 400 → 复现失败
});

test('PoC/header 点位：注入值落在请求头上，curl 用 -H 表达', () => {
  const target = baseTarget();
  const point = { id: 'p4', location: 'header', param: 'X-Forwarded-For', originalValue: '1.1.1.1' };
  const poc = buildPocEvidence(target, point, "1.1.1.1' OR SLEEP(2)-- -");
  assert.equal(poc.headers['X-Forwarded-For'], "1.1.1.1' OR SLEEP(2)-- -");
  assert.ok(poc.curl.includes("-H 'X-Forwarded-For: 1.1.1.1'\\'' OR SLEEP(2)-- -'"), poc.curl);
  assert.match(poc.raw, /X-Forwarded-For: 1\.1\.1\.1' OR SLEEP\(2\)-- -\r\n/);
});

test('PoC/prefix+suffix 语义继承：与扫描时真实请求同构（不能只拼裸 payload）', () => {
  const target = baseTarget({ config: { prefix: "'))", suffix: '-- -' } });
  const point = { id: 'p5', location: 'url', param: 'id', originalValue: '1' };
  const poc = buildPocEvidence(target, point, '1 UNION SELECT 1');
  const u = new URL(poc.url);
  assert.equal(u.searchParams.get('id'), "'))1 UNION SELECT 1-- -");
});

test('PoC/降级：缺注入点上下文时返回最小 GET 且不抛（历史报告快照也能出 PoC）', () => {
  const req = buildPocRequest({ baseUrl: 'http://test.local/a' }, null, 'x');
  assert.equal(req.method, 'GET');
  assert.equal(req.url, 'http://test.local/a');
  assert.deepEqual(req.headers, {});
  assert.equal(req.body, '');
  assert.match(req.note, /降级/);
  // 直连模式：没有 HTTP 请求，SQL 即 PoC，curl/raw 一律留空（不产出误导性命令）
  const direct = buildPocRequest(
    { mode: 'direct', sqlTemplate: 'SELECT * FROM t WHERE id = {INJECT}' },
    { location: 'direct', param: 'id', originalValue: '1', sqlTemplate: 'SELECT * FROM t WHERE id = {INJECT}' },
    '1 OR 1=1'
  );
  assert.equal(direct.method, 'SQL');
  assert.equal(direct.url, '');
  assert.equal(direct.body, 'SELECT * FROM t WHERE id = 1 OR 1=1');
  assert.equal(toCurl(direct), '');
  assert.equal(toRawRequest(direct), '');
});

// ---------------------------------------------------------------------------
// ② shell 安全：payload 不得逃逸出引号
// ---------------------------------------------------------------------------

test('shell 安全：header 点位 payload 含 \' $() 反引号 时不产生引号逃逸', () => {
  const target = baseTarget();
  const point = { id: 'p6', location: 'header', param: 'X-Inject', originalValue: '1' };
  const payload = "1'\"$(`id`)|touch /tmp/pwned";
  const poc = buildPocEvidence(target, point, payload);
  assertShellSafe(poc.curl, "1'\"$(`id`)");
  // 反引号/$( 只能出现在单引号内部
  assert.ok(poc.curl.includes("`id`"), 'payload 文本应保留（已引用即惰性）');
  assert.ok(!poc.curl.includes("';"), "不得出现闭合引号后紧跟分号的逃逸：" + poc.curl);
});

test('shell 安全：json body 含 \' 与反引号时 --data 仍在引号内', () => {
  const target = baseTarget({ method: 'POST', baseUrl: 'http://test.local/api/v1/item', jsonBody: { q: '1' } });
  const point = { id: 'p7', location: 'body', param: 'q', originalValue: '1' };
  // q 无点路径 → injection.js 走表单语义；jsonBody 存在但路径不含点 → data 仍是对象，
  // 无显式 Content-Type 时按 axios 语义补 application/json（PoC 与实际发送形态一致）
  const poc = buildPocEvidence(target, point, "a'`id`$(id)");
  assert.equal(poc.headers['Content-Type'], 'application/json');
  assertShellSafe(poc.curl);
  assert.ok(poc.curl.includes('--data'), poc.curl);
});

test('shell 安全：body 含换行 → ANSI-C 引用保持单行命令且换行不逃逸', () => {
  const curl = toCurl({
    method: 'POST',
    url: 'http://test.local/x',
    headers: { 'X-A': "v\r\nInjected: yes" }, // 头里的换行必须被压掉（否则请求走私/解析错位）
    body: "line1\nline2's`id`",
  });
  assert.ok(!curl.includes('\n'), 'curl 必须单行');
  assert.ok(curl.includes("$'"), '含换行的体应使用 $\'...\' ANSI-C 引用');
  assert.ok(!curl.includes('Injected: yes\r\n'), '头值不得带裸换行');
  const { literal, outside } = shellParse(curl);
  assert.ok(!/[$`;|&()<>\n\r\\]/.test(outside), `引号外出现 shell 元字符：${outside}`);
  assert.ok(literal.includes("line1\nline2's`id`"), literal);
});

test('shell 安全：raw 报文里 header 换行被压平（不破坏报文分帧）', () => {
  const raw = toRawRequest({
    method: 'POST',
    url: 'http://test.local/x',
    headers: { 'X-A': "a\nb" },
    body: 'keep\nbody',
  });
  const head = raw.split('\r\n\r\n')[0];
  assert.ok(!head.split('\r\n').join('').includes('\n'), `头部区段不得含裸换行：${head}`);
  assert.match(head, /X-A: a b/);
  assert.ok(raw.endsWith('keep\nbody'), 'body 原样保留');
});

// ---------------------------------------------------------------------------
// ③ raw ⇄ requestFileParser 逆运算闭环
// ---------------------------------------------------------------------------

for (const [name, target, point, payload] of [
  [
    'query',
    baseTarget(),
    { location: 'url', param: 'id', originalValue: '1' },
    "1' AND 1=1-- -",
  ],
  [
    'form',
    baseTarget({ method: 'POST', baseUrl: 'http://test.local/api/search', headerParams: { 'Content-Type': 'application/x-www-form-urlencoded' } }),
    { location: 'body', param: 'user', originalValue: '1', formValues: { csrf: 'tok', user: '1' } },
    "1' OR '1'='1",
  ],
  [
    'json',
    baseTarget({ method: 'PUT', baseUrl: 'http://test.local/api/v1/item', jsonBody: { user: { id: '1' } } }),
    { location: 'body', param: 'user.id', originalValue: '1' },
    '1 UNION SELECT 1',
  ],
  [
    'header',
    baseTarget({ baseUrl: 'https://test.local:443/api/search?id=1' }),
    { location: 'header', param: 'X-Inject', originalValue: '1' },
    "1' OR 1=1",
  ],
]) {
  test(`round-trip/${name}：raw 经 parseRequestFile 还原后 method/url/头/body 一致`, () => {
    const poc = buildPocEvidence(target, point, payload);
    const back = parseRequestFile(poc.raw);
    assert.ok(back, `解析失败：${JSON.stringify(poc.raw)}`);
    assert.equal(back.method, poc.method);
    // URL 按 WHATWG 归一化后比较：解析侧靠 Host 端口反推协议（:443 → https），
    // 归一化会抹掉冗余默认端口，两边语义等价即视为一致。
    assert.equal(new URL(back.url).href, new URL(poc.url).href);
    assert.equal(back.body, poc.body);
    for (const [k, v] of Object.entries(poc.headers)) {
      const got = Object.entries(back.headers).find(([bk]) => bk.toLowerCase() === k.toLowerCase());
      assert.ok(got, `还原后缺少请求头 ${k}`);
      assert.equal(got[1], String(v).replace(/[\r\n]+/g, ' '));
    }
    // 内网 https 端口必须显式落在 Host 里：解析侧靠 :443 反推协议，丢了就还原成 http
    if (/^https:/.test(poc.url)) assert.match(poc.raw, /Host: [^\r\n]*:443\r\n/);
  });
}

// ---------------------------------------------------------------------------
// ④ 报告渲染：esc / safeHref / 复现方式小节
// ---------------------------------------------------------------------------
test('round-trip/已编码 payload 带裸空格：请求行仍合法且可被解析回来', () => {
  // 命中 injection.js 的 preEncoded 分支（tamper 输出形态）：query 里会混入未编码的空格
  const target = baseTarget();
  const point = { id: 'p8', location: 'url', param: 'id', originalValue: '1' };
  const poc = buildPocEvidence(target, point, "1'%20AND%20sleep(2) 1=1");
  assert.ok(poc.url.includes(' '), '引擎侧 URL 确实带裸空格（本用例的前提）');
  assert.match(poc.raw, /^GET \S+ HTTP\/1\.1\r\n/, `请求行不得被空格截断：${poc.raw.split('\r\n')[0]}`);
  const back = parseRequestFile(poc.raw);
  assert.equal(back.params.id, decodeURIComponent("1'%20AND%20sleep(2) 1=1"));
});

test('esc：& < > " \' 全部转义，含引号的 payload 无法越出属性位', () => {
  assert.equal(esc('a"b'), 'a&#34;b');
  assert.equal(esc("a'b"), 'a&#39;b');
  assert.equal(esc('<x>&'), '&lt;x&gt;&amp;');
  const payload = `"><img src=x onerror=alert(1)>`;
  const e = esc(payload);
  assert.ok(!e.includes('"'), '转义后不得残留裸双引号');
  assert.ok(!e.includes("'"), '转义后不得残留裸单引号');
  assert.ok(!e.includes('<'), '转义后不得残留 <');
  const attr = `<div title="${e}">`;
  // 属性定界符只应有首尾两个，payload 无法提前闭合 title="…"
  assert.equal((attr.match(/"/g) || []).length, 2, attr);
});

test('safeHref：仅放行 http/https，javascript:/data:/file:/vbscript: 一律拒绝', () => {
  assert.equal(safeHref('http://example.com/a?b=1'), 'http://example.com/a?b=1');
  assert.equal(safeHref('https://example.com'), 'https://example.com');
  assert.equal(safeHref('javascript:alert(1)'), null);
  assert.equal(safeHref('JaVaScRiPt&colon;alert(1)'), null);
  assert.equal(safeHref('java\nscript:alert(1)'), null); // 控制字符绕过面
  assert.equal(safeHref('data:text/html,<script>alert(1)</script>'), null);
  assert.equal(safeHref('file:///etc/passwd'), null);
  assert.equal(safeHref('http://x<a>'), null); // 非法 URL 不可点
  assert.equal(safeHref(null), null);
});

test('renderUrlLink：外链可点、内网降级为 <code>、非 http(s) 降级为纯文本', () => {
  const ext = renderUrlLink('http://example.com/poc');
  assert.match(ext, /^<a href="http:\/\/example\.com\/poc"/);
  assert.match(ext, /rel="noopener noreferrer nofollow"/);
  for (const internal of [
    'http://127.0.0.1:8080/a',
    'http://localhost/a',
    'http://10.1.2.3/a',
    'http://192.168.0.5/a',
    'http://172.20.0.9/a',
    'http://intranet.local/a',
    'http://ci.internal/a',
    'http://[::1]:80/a',
  ]) {
    const html = renderUrlLink(internal);
    assert.ok(!html.includes('<a href'), `内网地址不可生成链接：${internal} → ${html}`);
    assert.match(html, /^<code>/);
  }
  assert.equal(isInternalHost('172.16.0.1'), true);
  assert.equal(isInternalHost('172.15.0.1'), false); // 172.16-31 才是私有段
  assert.equal(renderUrlLink('javascript:alert(1)'), 'javascript:alert(1)');
});

test('报告接线：toHTML/toMarkdown 新增复现方式小节，且只增字段不改既有结构', () => {
  const target = baseTarget();
  const point = { id: 'p1', location: 'url', param: 'id', originalValue: '1' };
  const vuln = {
    id: 'v1',
    pointId: 'p1',
    technique: 'union',
    dbms: 'MySQL',
    riskLevel: 'High',
    payloads: ["1' UNION SELECT 1,2-- -"],
    description: '联合查询命中',
  };
  const report = rg.build('s1', target, [point], [vuln], null);

  // 输入对象不得被污染（ScanManager 内存快照零感知）
  assert.equal('poc' in report.vulns[0], false);
  assert.equal('poc' in vuln, false);

  const json = JSON.parse(rg.toJSON(report));
  const poc = json.vulns[0].poc;
  assert.deepEqual(
    Object.keys(poc).sort(),
    ['body', 'curl', 'generatedAt', 'headers', 'method', 'note', 'payload', 'raw', 'url'].sort()
  );
  // 既有字段一个不少
  for (const k of ['id', 'pointId', 'technique', 'dbms', 'riskLevel', 'payloads', 'description', 'evidence']) {
    assert.ok(k in json.vulns[0], `既有字段 ${k} 丢失`);
  }

  const html = rg.toHTML(report);
  assert.match(html, /<h2>复现方式（PoC）<\/h2>/);
  assert.match(html, /<pre class="curl">curl -i -s -k/);
  assert.match(html, /<details><summary>原始 HTTP 报文/);
  assert.ok(html.includes('&lt;details&gt;') === false);
  // 内网目标（PoC 与报告头）都不得生成可点链接
  assert.ok(!html.includes('<a href="http://test.local'), '内网 .local 不应可点');
  // 既有小节仍在原位（页脚在 </body> 前）
  assert.match(html, /<h2>Payload 示例<\/h2>/);
  assert.ok(html.indexOf('本报告仅供授权安全测试使用') < html.lastIndexOf('</body>'));

  const md = rg.toMarkdown(report);
  assert.match(md, /## 复现方式（PoC）/);
  assert.match(md, /```bash\ncurl -i -s -k/);
  assert.match(md, /```http\nGET \/api\/search/);
  assert.match(md, /## Payload 示例/);
});

test('报告渲染：payload 含反引号时 Markdown 围栏不被提前闭合', () => {
  const target = baseTarget();
  const point = { id: 'p1', location: 'header', param: 'X-Inject', originalValue: '1' };
  const report = rg.build('s2', target, [point], [
    { pointId: 'p1', technique: 'error', dbms: 'MySQL', riskLevel: 'High', payloads: ['1` UNION ``` SELECT --'], description: '' },
  ], null);
  const md = rg.toMarkdown(report);
  // 围栏长度（4 个反引号）> 正文最长反引号串（3），故内容不会提前闭合
  assert.match(md, /curl（复制即跑）：\n\n````bash\n/);
  assert.match(md, /````http\nGET \/api\/search/);
  const html = rg.toHTML(report);
  // HTML 侧不存在围栏问题：整段落在转义后的 <pre> 代码块内
  assert.match(html, /<pre class="curl">curl -i -s -k/);
  assert.match(html, /1` UNION ``` SELECT --/);
});

test('报告接线：无漏洞 / 无 poc 时复现方式小节给出空态而不报错', () => {
  const html = rg.toHTML(rg.build('s3', baseTarget(), [], [], null));
  assert.match(html, /<h2>复现方式（PoC）<\/h2>/);
  assert.match(html, /未发现漏洞，无可复现请求/);
  const md = rg.toMarkdown(rg.build('s3', baseTarget(), [], [], null));
  assert.match(md, /未发现漏洞，无可复现请求/);
});

test('报告接线：同报告多次导出逐字节一致（generatedAt 走 WeakMap 缓存，md/markdown 等价）', () => {
  const report = rg.build('s5', baseTarget(), [{ id: 'p1', location: 'url', param: 'id', originalValue: '1' }], [
    { pointId: 'p1', technique: 'boolean', riskLevel: 'Medium', payloads: ["1' AND 1=1-- -", "1' AND 1=2-- -"], description: '' },
  ], null);
  // 跨事件循环也要一致（旧写法会因两次 Date 不同而失败，正是本缓存要消除的阅派）
  const a = rg.toMarkdown(report);
  const b = rg.toMarkdown(report);
  assert.equal(a, b);
  const json = JSON.parse(rg.toJSON(report));
  // [FIX 2026-09-14 flaky] 原文用 /生成时间：([^\n]+)/ 抓到的是**报告级** meta.generatedAt
  // （ReportGenerator 报告头那一行），却与 **PoC 级** json.vulns[0].poc.generatedAt 比较——
  // 两者是两次独立的 Date.now()，跨毫秒边界即失败（实测 5 次挂 2 次）。
  // 改为断言「PoC 自身的生成时间确实出现在报告里」：语义正确且不依赖毫秒巧合。
  assert.ok(
    a.includes(json.vulns[0].poc.generatedAt),
    `PoC 生成时间应出现在 markdown 中：${json.vulns[0].poc.generatedAt}`
  );
  assert.equal(
    json.vulns[0].poc.curl,
    "curl -i -s -k -H 'X-Api-Key: k1' -H 'Cookie: session=abc' 'http://test.local/api/search?id=1%27+AND+1%3D1--+-'"
  );
});

test('报告接线：已带 poc 的漏洞不重复计算（幂等，尊重外部预生成）', () => {
  const vuln = { pointId: 'p1', technique: 'union', riskLevel: 'High', payloads: ['x'], poc: { url: 'pre', method: 'GET', headers: {}, body: '', curl: '', raw: '', note: '', generatedAt: 't', payload: 'x' } };
  const report = { scanId: 's4', target: baseTarget(), points: [{ id: 'p1', location: 'url', param: 'id', originalValue: '1' }], vulns: [vuln], data: null, riskLevel: 'High' };
  const json = JSON.parse(rg.toJSON(report));
  assert.equal(json.vulns[0].poc.generatedAt, 't');
});
