// ============================================================================
// formSelect.test.js —— [D171] 表单 `<select>` 字段采集
// ============================================================================
// 缺陷：表单解析此前只认 `<input>` / `<textarea>`（D112 注释里把 `<select>` 登记为
// 「后续按需补」）。筛选/排序表单的注入面经常就在下拉值上（`sort`/`status`/`id`），
// 缺它时这类表单只剩按钮字段 ⇒ **0 个注入点** ⇒ 报告写「未检出」。
// A/B 实测（e2e/detect-surface-lab 的 /select-filter-page）：不采集时日志 `[发现] 0 个注入点`
// 且 0 检出；采集后 3 条命中、安全对照 0 误报。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';

const parser = new TargetParser();
const page = (formHtml) => parser._parseForms(`<html><body>${formHtml}</body></html>`, 'http://shop.example.com/filter');

test('[D171] select：取 selected 选项的 value', () => {
  const [form] = page('<form action="/api/filter" method="post">'
    + '<select name="id"><option value="1">one</option><option value="2" selected>two</option></select>'
    + '<input type="submit" name="go" value="x"></form>');
  assert.equal(form.values.id, '2');
  assert.ok(form.injectableNames.includes('id'), 'select 字段必须成为注入点候选');
});

test('[D171] select：没有 selected 时取第一个带 value 的选项（浏览器默认行为）', () => {
  const [form] = page('<form action="/api/filter" method="post">'
    + '<select name="sort"><option value="name">Name</option><option value="price">Price</option></select></form>');
  assert.equal(form.values.sort, 'name');
});

test('[D171] select：无 value 属性的 option 整体跳过（浏览器会提交文本，当注入点会发畸形报文）', () => {
  const [form] = page('<form action="/api/filter" method="post">'
    + '<select name="sort"><option>Name</option><option>Price</option></select></form>');
  assert.ok(!('sort' in form.values), '没有 value 的下拉不采集');
  assert.deepEqual(form.injectableNames, []);
});

test('[D171] select：同名字段 input 优先（与 textarea 同口径）', () => {
  const [form] = page('<form action="/api/filter" method="post">'
    + '<input name="q" value="from-input">'
    + '<select name="q"><option value="from-select">x</option></select></form>');
  assert.equal(form.values.q, 'from-input');
});

test('[D171] 多个 select：各自取默认值，互不覆盖', () => {
  const [form] = page('<form action="/api/filter" method="post">'
    + '<select name="status"><option value="1">A</option><option value="2" selected>B</option></select>'
    + '<select name="sort"><option value="name">N</option></select></form>');
  assert.equal(form.values.status, '2');
  assert.equal(form.values.sort, 'name');
});
