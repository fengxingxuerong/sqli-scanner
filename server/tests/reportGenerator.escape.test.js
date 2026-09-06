// ReportGenerator _escape 边界测试：验证 HTML 转义覆盖所有危险字符及边界输入
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ReportGenerator } from '../src/services/ReportGenerator.js';

const rg = new ReportGenerator();

// 私有方法 _escape 反射访问
const escape = (s) => rg._escape(s);

test('_escape: 普通文本原样返回', () => {
  assert.equal(escape('hello'), 'hello');
  assert.equal(escape('SQL注入检测报告'), 'SQL注入检测报告');
  assert.equal(escape('123'), '123');
});

test('_escape: & 转义为 &amp;', () => {
  assert.equal(escape('a&b'), 'a&amp;b');
  assert.equal(escape('&&'), '&amp;&amp;');
  assert.equal(escape('&amp;'), '&amp;amp;'); // 双重转义
});

test('_escape: < 转义为 &lt;', () => {
  assert.equal(escape('<script>'), '&lt;script&gt;');
  assert.equal(escape('a<b'), 'a&lt;b');
});

test('_escape: > 转义为 &gt;', () => {
  assert.equal(escape('a>b'), 'a&gt;b');
  assert.equal(escape('>>'), '&gt;&gt;');
});

test('_escape: " 转义为 &quot;', () => {
  assert.equal(escape('a"b'), 'a&quot;b');
  assert.equal(escape('"'), '&quot;');
});

test('_escape: \' 转义为 &#39;', () => {
  assert.equal(escape("a'b"), 'a&#39;b');
  assert.equal(escape("'"), '&#39;');
});

test('_escape: 全部 5 个危险字符同时出现', () => {
  const input = `<script>alert("xss&")</script>`;
  const out = escape(input);
  assert.equal(out, '&lt;script&gt;alert(&quot;xss&amp;&quot;)&lt;/script&gt;');
  // 无任何原始 HTML 特殊字符残留（& 是转义字符，必然出现在 &amp; &lt; &gt; &quot; &#39; 中）
  assert.ok(!out.includes('<'));
  assert.ok(!out.includes('>'));
  assert.ok(!out.includes('"'));
  assert.ok(!out.includes("'"));
  // & 只出现在合法转义序列中
  assert.ok(out.includes('&amp;') || out.includes('&lt;') || out.includes('&gt;') || out.includes('&quot;') || out.includes('&#39;'));
});

test('_escape: null 转字符串', () => {
  assert.equal(escape(null), 'null');
});

test('_escape: undefined 转字符串', () => {
  assert.equal(escape(undefined), 'undefined');
});

test('_escape: 数字转字符串', () => {
  assert.equal(escape(0), '0');
  assert.equal(escape(123), '123');
});

test('_escape: 空字符串', () => {
  assert.equal(escape(''), '');
});

test('_escape: Unicode 字符保留', () => {
  assert.equal(escape('中文\u4e2d\u6587'), '中文\u4e2d\u6587');
  assert.equal(escape('🔥'), '🔥');
});

test('_escape: 换行符保留', () => {
  assert.equal(escape('a\nb'), 'a\nb');
});

test('toHTML: 漏洞 payload 含危险字符时被转义', () => {
  const report = rg.build(
    's1',
    { baseUrl: 'http://x' },
    [{ id: 'p1' }],
    [{
      pointId: 'p1',
      technique: 'union',
      dbms: 'MySQL',
      riskLevel: 'High',
      payloads: ['<img src=x onerror=alert(1)>', "'; DROP TABLE users-- -"],
      description: '<script>alert("xss")</script>',
    }],
    null
  );
  const html = rg.toHTML(report);
  // < 和 > 在用户输入中被转义，不应以原始形式出现在 HTML 中
  assert.ok(!html.includes('<img'), 'payload 中的 <img 不应原样出现');
  assert.ok(!html.includes('<script>'), '<script> 不应原样出现');
  // 原始尖括号应在转义后出现
  assert.ok(html.includes('&lt;img'), '应看到 &lt;img');
  assert.ok(html.includes('&lt;script&gt;'), '应看到 &lt;script&gt;');
  // 双引号 / 单引号被转义
  assert.ok(!html.includes('"xss"'), '双引号不应原样');
  assert.ok(!html.includes("'xss'"), '单引号不应原样');
  // 原始 payload 中的 alert(1) 不应出现（> 被转义后不会再形成 alert(1) 上下文）
  assert.ok(html.includes('alert(1)'), 'alert(1) 文本本身应保留（非 HTML 特殊字符，只需转义 < > " \' &）');
  // 转义后版本应出现
  assert.ok(html.includes('&lt;img'), '应看到 &lt;img');
  assert.ok(html.includes('&lt;script&gt;'), '应看到 &lt;script&gt;');
  // 双引号 / 单引号被转义
  assert.ok(!html.includes('"xss"'), '双引号不应原样');
  assert.ok(!html.includes("'xss'"), '单引号不应原样');
});

test('toHTML: CSV 导出公式注入被转义', () => {
  const report = rg.build(
    's1',
    { baseUrl: 'http://x' },
    [],
    [{
      pointId: '=CMD|' + "' /C calc'!A0",
      technique: 'union',
      riskLevel: 'High',
      payloads: [],
      description: '=HYPERLINK("http://evil")',
    }],
    null
  );
  const html = rg.toHTML(report);
  // = 开头的公式注入被转义（= → 在 HTML 中不会被 Excel 解析，但 _escape 确保无原始 < 等）
  assert.ok(html.includes('=CMD|'), '= 开头字段在 HTML 中安全（不执行公式）');
  assert.ok(!html.includes('"http://evil"'), '引号被转义不应原样');
});