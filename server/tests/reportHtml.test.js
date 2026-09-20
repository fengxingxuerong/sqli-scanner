// =====================================================================
// reportHtml.test.js —— 报告侧 HTML 渲染原语的单测
//
// [为什么单独建文件]
// [大文件拆分 2026-09-21] esc / isInternalHost / safeHref / renderUrlLink 从
// ReportGenerator.js 外移到 services/reportHtml.js。此前它们只能通过完整的
// toHTML 渲染间接验证（要先构造一份含漏洞的报告）。
//
// 这四个函数是**安全边界不是美化**：报告常在浏览器里打开，而 PoC 文本、URL、
// 参数名全部来自被测目标（不可信输入）。转义漏一处 → 报告文件里的存储型 XSS；
// 内网地址放行 → 点一下就是 SSRF。抽成无依赖纯函数后可以穷举。
// =====================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { esc, isInternalHost, safeHref, renderUrlLink } from '../src/services/reportHtml.js';

// ── esc ──────────────────────────────────────────────────────────────

test('esc：五个危险字符全覆盖，且用**数字实体**表示引号', () => {
  assert.equal(esc(`&<>"'`), '&amp;&lt;&gt;&#34;&#39;');
});

test('★安全★ esc：引号转 &#34; / &#39;（数字实体，不是 &quot;）', () => {
  // 为什么必须是数字实体：PoC 文本要落进 title/href 等属性位，
  // &#34; 不会被任何解析器当引号闭合；&quot; 在裸属性上下文里可能出问题。
  // ReportGenerator._escape 用的是 &quot;（被既有测试锁定，属另一条轨道）。
  assert.equal(esc('"'), '&#34;');
  assert.equal(esc("'"), '&#39;');
  assert.ok(!esc('"').includes('&quot;'), '不得退化成 &quot;');
});

test('esc：null/undefined → 空串（不抛错）', () => {
  assert.equal(esc(null), '');
  assert.equal(esc(undefined), '');
});

test('esc：非字符串值先 String()（数字/布尔）', () => {
  assert.equal(esc(0), '0');
  assert.equal(esc(true), 'true');
});

test('★安全★ esc：脚本标签被完全中和（报告里的存储型 XSS 面）', () => {
  const out = esc('<script>alert(1)</script>');
  assert.ok(!out.includes('<script'), '不得残留可执行的标签');
  assert.equal(out, '&lt;script&gt;alert(1)&lt;/script&gt;');
  // 属性位逃逸尝试：带上引号想把属性闭合
  assert.ok(!esc('" onmouseover="alert(1)').includes('"'), '引号必须被转义，否则属性逃逸');
});

test('esc：重复扫描安全（二次转义会翻倍，故调用方不可重复转义）', () => {
  // 记录现状：esc 不是幂等的（& → &amp; → &amp;amp;）。
  assert.equal(esc(esc('&')), '&amp;amp;', 'esc 非幂等 —— 钉住现状，调用方只转义一次');
});

// ── isInternalHost ───────────────────────────────────────────────────

test('isInternalHost：回环与常见内网段全部命中', () => {
  for (const h of [
    'localhost', 'a.localhost', '::1', '0.0.0.0', '0',
    '127.0.0.1', '127.1.2.3',
    '10.0.0.1', '10.255.255.254',
    '192.168.1.1', '169.254.169.254', '192.0.0.1',
    '172.16.0.1', '172.31.255.255',
  ]) {
    assert.equal(isInternalHost(h), true, `${h} 应判为内网`);
  }
});

test('isInternalHost：172 段边界（.15/.32 不是内网）', () => {
  assert.equal(isInternalHost('172.15.0.1'), false, '172.15 不在 16-31');
  assert.equal(isInternalHost('172.32.0.1'), false, '172.32 超出 31');
  assert.equal(isInternalHost('172.16.0.1'), true);
  assert.equal(isInternalHost('172.31.0.1'), true);
});

test('isInternalHost：公网域名/地址不命中', () => {
  for (const h of ['example.com', '8.8.8.8', '1.1.1.1', '93.184.216.34']) {
    assert.equal(isInternalHost(h), false, `${h} 应判为公网`);
  }
});

test('isInternalHost：.local / .internal 后缀命中；大小写与尾点不敏感', () => {
  assert.equal(isInternalHost('foo.local'), true);
  assert.equal(isInternalHost('foo.internal'), true);
  assert.equal(isInternalHost('FOO.LOCAL'), true, '大小写不敏感（内部已 toLowerCase）');
  assert.equal(isInternalHost('localhost.'), true, '尾点被剥离');
});

test('isInternalHost：IPv6 方括号被剥离（::1 与 [::1] 同判）', () => {
  assert.equal(isInternalHost('[::1]'), true);
  assert.equal(isInternalHost('[2001:db8::1]'), false);
});

test('isInternalHost：空值 → false（调用方按「非内网」处理）', () => {
  assert.equal(isInternalHost(''), false);
  assert.equal(isInternalHost(null), false);
});

// ── safeHref ─────────────────────────────────────────────────────────

test('safeHref：http/https 放行', () => {
  assert.equal(safeHref('https://example.com/a?b=1'), 'https://example.com/a?b=1');
  assert.equal(safeHref('http://example.com'), 'http://example.com');
  assert.equal(safeHref('HTTPS://EXAMPLE.COM'), 'HTTPS://EXAMPLE.COM', '大小写不敏感');
});

test('★安全★ safeHref：危险协议一律返回 null', () => {
  for (const u of [
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'file:///etc/passwd',
    'vbscript:msgbox(1)',
    'ftp://example.com',
  ]) {
    assert.equal(safeHref(u), null, `${u} 必须被拒`);
  }
});

test('★安全★ safeHref：危险协议前的空白/控制字符不影响拦截', () => {
  assert.equal(safeHref('java\nscript:alert(1)'), null);
  assert.equal(safeHref('java\tscript:alert(1)'), null);
  assert.equal(safeHref(' javascript:alert(1)'), null, '前导空白');
  assert.equal(safeHref('java script:alert(1)'), null);
  // ⚠ 如实记录（已实测，勿被源码注释误导）：这 4 条**不是**靠「剥控制字符」拦住的 ——
  // 协议白名单 `^https?://` 本身就把它们全拒了。源码注释称「java\nscript: 是经典绕过面」
  // 在**当前**逻辑下不成立：把剥离换成 trim() 后这 4 条仍全为 null（实测 10 例仅 1 例真有差异）。
  // 控制字符剥离的真正作用见下一条用例。
});

test('safeHref：剥掉 URL **内部**的控制字符（剥离逻辑的真实作用）', () => {
  // 唯一能区分「有无控制字符剥离」的输入：协议合法、但路径里混了控制字符。
  // 有剥离 → 'https://example.com/ab'；仅 trim → 原样带控制字符返回。
  assert.equal(safeHref('https://example.com/a\u007fb'), 'https://example.com/ab');
  assert.equal(safeHref('https://example.com/a\u0001b'), 'https://example.com/ab');
  assert.equal(safeHref('https://exa\u0000mple.com'), 'https://example.com');
});

test('safeHref：非法 URL / 空值 → null（不抛错）', () => {
  assert.equal(safeHref(''), null);
  assert.equal(safeHref(null), null);
  assert.equal(safeHref('not-a-url'), null);
  assert.equal(safeHref('http://'), null, '空 host');
});

// ── renderUrlLink ────────────────────────────────────────────────────

test('renderUrlLink：公网 https → 可点击 <a>，带 noopener noreferrer', () => {
  const out = renderUrlLink('https://example.com/p', 'https://example.com/p');
  assert.match(out, /^<a href="https:\/\/example\.com\/p"/);
  assert.ok(out.includes('rel="noopener noreferrer nofollow"'), '须防 window.opener 反向引用');
  assert.ok(out.includes('target="_blank"'));
});

test('★安全★ renderUrlLink：内网地址 → <code> 纯文本（点一下就是 SSRF）', () => {
  const out = renderUrlLink('http://127.0.0.1:8080/admin', 'http://127.0.0.1:8080/admin');
  assert.ok(!out.includes('<a '), '内网不得生成链接');
  assert.match(out, /^<code>/);
  assert.ok(out.includes('127.0.0.1'), '文本仍可读（保留可审计性）');
});

test('★安全★ renderUrlLink：危险协议 → 降级纯文本（无 href）', () => {
  const out = renderUrlLink('javascript:alert(1)', 'click me');
  assert.ok(!out.includes('<a '), '不得生成链接');
  assert.equal(out, 'click me');
});

test('renderUrlLink：label 缺省时用 url；文本与 href 双双转义', () => {
  assert.ok(renderUrlLink('https://example.com/a?x=1&y=2').includes('&amp;'));
  const xss = renderUrlLink('https://example.com/?q=<script>', '<img>');
  assert.ok(!xss.includes('<img>'), 'label 必须被转义');
  assert.ok(xss.includes('&lt;img&gt;'));
});

test('renderUrlLink：空/非法输入 → 纯文本（不抛错）', () => {
  assert.equal(renderUrlLink('', ''), '');
  assert.equal(renderUrlLink(null, null), '-', 'label 与 url 皆空 → 缺省显示 -');
  assert.equal(renderUrlLink('not-a-url', 'x'), 'x');
});
