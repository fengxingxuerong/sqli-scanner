// ============================================================================
// tests/dumpFormat.test.js —— 拖库结果格式化的直接单测
// [大文件拆分 2026-09-20]
//
// 为什么必须写这一组：
//   这 5 个函数原先住在 Extractor 内部，只能通过完整的拖库链路（起靶场 → 注入 →
//   提取 → 格式化）间接验证「转义对不对」。但 CSV/HTML 转义**是注入面**：
//     · CSV：单元格转义漏一处 → 导出文件结构被拖库内容破坏（多出一列/多出一行）；
//     · HTML：实体编码漏一处 → 报表里出现**存储型 XSS**（数据来自目标库，完全不可信）。
//   抽成纯函数后可穷举边界，且一次验完即对所有调用方生效。
//
// 本组同时钉住三个易被"顺手改坏"的行为契约（详见 formatDumpData 的 JSDoc）：
//   ① json 返回**数组**而非字符串；
//   ② 空数据返回**格式骨架**而非空数组；
//   ③ 未知 format **抛错**而非静默回落。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  escapeCsvCell,
  formatCsv,
  formatSql,
  formatHtml,
  formatDumpData,
} from '../src/engine/dumpFormat.js';

// ── escapeCsvCell ────────────────────────────────────────────────────────────

test('escapeCsvCell：普通值原样返回（不加引号）', () => {
  assert.equal(escapeCsvCell('abc'), 'abc');
  assert.equal(escapeCsvCell('123'), '123');
});

test('escapeCsvCell：null/undefined → 空串', () => {
  assert.equal(escapeCsvCell(null), '');
  assert.equal(escapeCsvCell(undefined), '');
});

test('escapeCsvCell：含逗号 → 双引号包裹', () => {
  assert.equal(escapeCsvCell('a,b'), '"a,b"');
});

test('escapeCsvCell：含双引号 → 内部引号双写', () => {
  assert.equal(escapeCsvCell('say "hi"'), '"say ""hi"""');
});

test('escapeCsvCell：含换行（\\n 与 \\r）→ 包裹', () => {
  assert.equal(escapeCsvCell('a\nb'), '"a\nb"');
  assert.equal(escapeCsvCell('a\rb'), '"a\rb"');
});

test('escapeCsvCell：首尾空格 → 包裹（否则往返一轮空格丢失）', () => {
  assert.equal(escapeCsvCell(' a'), '" a"');
  assert.equal(escapeCsvCell('a '), '"a "');
  assert.equal(escapeCsvCell(' a '), '" a "');
});

test('escapeCsvCell：中段空格**不**包裹（避免过度引用）', () => {
  assert.equal(escapeCsvCell('a b'), 'a b');
});

test('escapeCsvCell：组合场景（逗号 + 引号 + 换行）', () => {
  assert.equal(escapeCsvCell('a,"b"\nc'), '"a,""b""\nc"');
});

test('escapeCsvCell：非字符串值转成字符串', () => {
  assert.equal(escapeCsvCell(0), '0');
  assert.equal(escapeCsvCell(false), 'false');
});

// ── formatCsv ────────────────────────────────────────────────────────────────

test('formatCsv：表头 + 行数据，\\n 分隔', () => {
  const out = formatCsv([{ id: 1, name: 'a' }], ['id', 'name']);
  assert.equal(out, 'id,name\n1,a');
});

test('formatCsv：单元格内的逗号不会额外分列（转义生效）', () => {
  const out = formatCsv([{ note: 'x,y' }], ['note']);
  assert.equal(out, 'note\n"x,y"');
  // 关键断言：整行按「非引号内」的逗号切，应只有 1 个字段
  const row = out.split('\n')[1];
  assert.equal(row, '"x,y"');
});

test('formatCsv：空 rows → 只返回表头', () => {
  assert.equal(formatCsv([], ['a', 'b']), 'a,b');
});

// ── formatSql ────────────────────────────────────────────────────────────────

test('formatSql：生成 INSERT 语句', () => {
  const out = formatSql([{ id: 1, name: 'a' }], ['id', 'name'], 'users');
  assert.equal(out, "INSERT INTO users (id, name) VALUES ('1', 'a');");
});

test('formatSql：**非字符串值也加引号**（既有行为，勿"顺手优化"）', () => {
  // 拆分管线时实测确认：实现只对 null/undefined 特判为 NULL，其余一律
  // String(v) 后加引号 —— 数字 1 会输出 '1' 而非 1。
  // 这在多数数据库里可隐式转换，属可接受行为；但它**不是** bug 修复目标，
  // 因为改动会波及所有既有导出产物（客户可能已按带引号的脚本入库）。
  const out = formatSql([{ n: 42, b: true }], ['n', 'b'], 't');
  assert.equal(out, "INSERT INTO t (n, b) VALUES ('42', 'true');");
});

test('formatSql：字符串值单引号转义（双写）', () => {
  const out = formatSql([{ n: "O'Brien" }], ['n'], 't');
  assert.equal(out, "INSERT INTO t (n) VALUES ('O''Brien');");
});

test('formatSql：null/undefined → SQL NULL（不加引号）', () => {
  const out = formatSql([{ a: null, b: undefined }], ['a', 'b'], 't');
  assert.equal(out, 'INSERT INTO t (a, b) VALUES (NULL, NULL);');
});

test('formatSql：多行 → 每行一条 INSERT', () => {
  const out = formatSql([{ a: 1 }, { a: 2 }], ['a'], 't');
  assert.equal(out.split('\n').length, 2);
});

// ── formatHtml ───────────────────────────────────────────────────────────────

test('formatHtml：生成 table 结构与表头', () => {
  const out = formatHtml([{ id: 1 }], ['id']);
  assert.match(out, /^<table><thead><tr><th>id<\/th><\/tr><\/thead>/);
  assert.match(out, /<tbody><tr><td>1<\/td><\/tr><\/tbody><\/table>$/);
});

test('formatHtml：**HTML 实体编码**（安全边界，防报表存储型 XSS）', () => {
  const out = formatHtml([{ c: '<script>alert(1)</script>' }], ['c']);
  assert.ok(!out.includes('<script>'), '未编码的 <script> 会直接执行');
  assert.ok(out.includes('&lt;script&gt;'));
});

test('formatHtml：五个实体全部编码（& < > " \'）', () => {
  const out = formatHtml([{ c: `&<>"'` }], ['c']);
  assert.ok(out.includes('&amp;&lt;&gt;&quot;&#39;'));
});

test('formatHtml：表头也编码（列名同样来自目标库）', () => {
  const out = formatHtml([], ['<img src=x>']);
  assert.ok(!out.includes('<img'), '列名未编码时可注入');
  assert.ok(out.includes('&lt;img src=x&gt;'));
});

// ── formatDumpData（分发层 + 三个契约）──────────────────────────────────────

test('formatDumpData：json（默认）返回**原始数组**而非字符串', () => {
  const rows = [{ a: 1 }];
  assert.equal(formatDumpData(rows, ['a'], 't'), rows, 'json 须返回同一引用');
  assert.equal(formatDumpData(rows, ['a'], 't', 'json'), rows);
});

test('formatDumpData：csv/sql/html 各走对应实现', () => {
  const rows = [{ a: 'x' }];
  assert.equal(formatDumpData(rows, ['a'], 't', 'csv'), 'a\nx');
  assert.equal(formatDumpData(rows, ['a'], 't', 'sql'), "INSERT INTO t (a) VALUES ('x');");
  assert.match(formatDumpData(rows, ['a'], 't', 'html'), /^<table>/);
});

test('formatDumpData：columns 缺省时从首行推断', () => {
  assert.equal(formatDumpData([{ a: 1, b: 2 }], undefined, 't', 'csv'), 'a,b\n1,2');
});

test('formatDumpData 契约②：空数据返回**格式骨架**（报告层靠它区分「真拖到 0 行」）', () => {
  assert.equal(formatDumpData([], ['a', 'b'], 't', 'csv'), 'a,b', 'CSV 应给表头');
  assert.equal(formatDumpData([], ['a'], 't', 'sql'), '', 'SQL 应给空串');
  assert.equal(formatDumpData([], ['a'], 't', 'html'), '<table><thead><tr><th>a</th></tr></thead><tbody></tbody></table>');
});

test('formatDumpData 契约③：未知 format → **抛错**（不静默回落）', () => {
  assert.throws(
    () => formatDumpData([{ a: 1 }], ['a'], 't', 'xml'),
    /不支持的 dump 格式: xml/
  );
});

test('formatDumpData：非数组 rows 视同空（走骨架分支）', () => {
  assert.equal(formatDumpData(null, ['a'], 't', 'csv'), 'a');
  assert.equal(formatDumpData(undefined, ['a'], 't', 'sql'), '');
});
