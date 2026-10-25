// ============================================================================
// formEnctype.multipart.test.js —— [D168] 页面表单 enctype=multipart 的发送形态
// ============================================================================
// 缺陷：`<form enctype="multipart/form-data">` 的上传表单只有**标记**里写着编码类型，
// 没有任何请求头可读 ⇒ --forms / 爬取路径发现的注入点一律按 urlencoded 发 ⇒ 只认
// multipart 的端点 415/400 ⇒ 字段从未进业务逻辑、报告写「未检出」（与 D159 的 -r 场景同型）。
// 修法：解析表单时记住 enctype，发送侧在没有声明头时用它决定是否按 multipart 重建。
// A/B 实测（e2e/detect-surface-lab 的 /form-upload）：修复前 0 检出，修复后 3 条。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import { createTarget, createInjectionPoint } from '../src/engine/models.js';
import { buildInjectionRequest } from '../src/engine/injection.js';

const parser = new TargetParser();

test('[D168] 表单解析：enctype=multipart/form-data 被记录', () => {
  const html = '<form action="/up" method="post" enctype="multipart/form-data">'
    + '<input type="text" name="caption" value="hi">'
    + '<input type="submit" name="go" value="1">'
    + '</form>';
  const [form] = parser._parseForms(html, 'http://shop.example.com/page');
  assert.equal(form.enctype, 'multipart/form-data');
  assert.equal(form.method, 'POST');
});

test('[D168] 表单解析：没有 enctype 时为空串（走既有 urlencoded 语义）', () => {
  const html = '<form action="/login" method="post"><input name="user" value="a"></form>';
  const [form] = parser._parseForms(html, 'http://shop.example.com/page');
  assert.equal(form.enctype, '');
});

test('[D168] 发送侧：点带 formEnctype=multipart ⇒ 报文是 multipart（不是 urlencoded）', () => {
  const target = createTarget({ url: 'http://shop.example.com/form-upload', method: 'POST', config: { level: 5 } });
  const point = createInjectionPoint('body', 'caption', 'alice', {
    formMethod: 'POST',
    actionUrl: 'http://shop.example.com/api/form-upload',
    formValues: { caption: 'alice', go: 'upload' },
    formEnctype: 'multipart/form-data',
  });
  const req = buildInjectionRequest(target, point, "alice' AND 1=1-- -");
  assert.equal(typeof req.data, 'string', 'multipart 应是字符串报文');
  assert.match(req.headers['Content-Type'], /^multipart\/form-data; boundary=.+/);
  assert.ok(String(req.data).includes('name="caption"'), '注入字段必须出现在报文里');
  assert.ok(String(req.data).includes('name="go"'), '按钮伴随字段必须保留');
  assert.ok(!String(req.data).includes('caption=alice'), '不得退化成 urlencoded');
});

test('[D168] 回归：没有 enctype 且没有声明头的表单点仍是 urlencoded', () => {
  const target = createTarget({ url: 'http://shop.example.com/login', method: 'POST', config: { level: 5 } });
  const point = createInjectionPoint('body', 'user', 'alice', {
    formMethod: 'POST',
    actionUrl: 'http://shop.example.com/login',
    formValues: { user: 'alice' },
  });
  const req = buildInjectionRequest(target, point, "alice' AND 1=1-- -");
  assert.equal(req.headers['Content-Type'], 'application/x-www-form-urlencoded');
  assert.ok(!String(req.data).includes('Content-Disposition'));
});
