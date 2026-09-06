// tamper 占位暂存还原测试（修复 P0 硬伤）
//
// 背景：applyTampers 直接将含提取标记（__S__/__E__/SQLISCANNER<N>）的 payload
// 传入 tamper 链，编码类 tamper（charunicodeencode/lowercase/char2hex 等）会
// 破坏标记 → 引擎在响应中无法匹配 → UNION 漏检 / 数据提取失败。
//
// 修复：占位暂存还原——用纯数字占位符替换标记（数字不被大多数编码类 tamper
// 变换），执行 tamper 后还原；还原失败则回退到不保护版本。
//
// 用例：
//   1) 无 tamper 插件 → 原样返回
//   2) 无标记 payload + space2comment → tamper 正常执行
//   3) 有 SQLISCANNER0 标记 + lowercase → 标记被保护（保持大写）
//   4) 有 SQLISCANNER0 标记 + charunicodeencode → 标记被保护（不被编码）
//   5) 有 __S__/__E__ 标记 + lowercase → 标记被保护
//   6) 有 __S__/__E__ 标记 + char2hex → 还原失败，回退到不保护版本
//   7) 多标记同时保护（__S__、__E__、SQLISCANNER0）+ lowercase
//   8) __S__INL__E__ 复合标记 + lowercase → 拆分保护后正确还原
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyTampers } from '../src/core/tamper/applyTampers.js';

const ctx = { config: { wafEvasion: {} } };

test('1) 无 tamper 插件 → 原样返回', () => {
  const payload = "1 UNION SELECT 'SQLISCANNER0', '__S__', '__E__'";
  const out = applyTampers(payload, ctx, []);
  assert.equal(out, payload);
});

test('2) 无标记 payload + space2comment → tamper 正常执行', () => {
  const payload = '1 UNION SELECT 2';
  const out = applyTampers(payload, ctx, ['space2comment']);
  assert.equal(out, '1/**/UNION/**/SELECT/**/2');
  // 不应包含占位符残留
  assert.ok(!/7331999/.test(out), '不应有占位符残留');
});

test('3) 有 SQLISCANNER0 标记 + lowercase → 标记被保护（保持大写）', () => {
  const payload = "1 UNION SELECT 'SQLISCANNER0'";
  const out = applyTampers(payload, ctx, ['lowercase']);
  // SQL 部分应转小写
  assert.ok(out.includes('1/**/') === false, '不应被 space2comment 处理');
  assert.ok(out.startsWith('1 union select'), 'SQL 关键字应转小写');
  // 标记应保持原样大写（被占位符保护，不被 lowercase 影响）
  assert.ok(out.includes('SQLISCANNER0'), '标记应保持大写不被 lowercase 破坏');
  // 不应包含占位符残留
  assert.ok(!/7331999/.test(out), '不应有占位符残留');
});

test('4) 有 SQLISCANNER0 标记 + charunicodeencode → 标记被保护（不被编码）', () => {
  const payload = "1 UNION SELECT 'SQLISCANNER0'";
  const out = applyTampers(payload, ctx, ['charunicodeencode']);
  // SQL 字母应被编码为 %uXXXX
  assert.ok(out.includes('%u0055%u004e%u0049%u004f%u004e'), 'UNION 应被编码');
  // 标记应保持原样（占位符是纯数字，charunicodeencode 只编码字母）
  assert.ok(out.includes('SQLISCANNER0'), '标记应保持原样不被编码');
  assert.ok(!/7331999/.test(out), '不应有占位符残留');
});

test('5) 有 __S__/__E__ 标记 + lowercase → 标记被保护', () => {
  const payload = "CONCAT('__S__', col, '__E__')";
  const out = applyTampers(payload, ctx, ['lowercase']);
  // SQL 函数名应转小写（concat 本来就是小写，但参数名 col 也应转小写）
  assert.ok(out.includes('concat('), '函数名应转小写');
  // 标记应保持原样
  assert.ok(out.includes('__S__'), '__S__ 应保持原样');
  assert.ok(out.includes('__E__'), '__E__ 应保持原样');
  assert.ok(!/7331999/.test(out), '不应有占位符残留');
});

test('6) 有 __S__/__E__ 标记 + char2hex → 还原失败，回退到不保护版本', () => {
  const payload = "CONCAT('__S__', col, '__E__')";
  const out = applyTampers(payload, ctx, ['char2hex']);
  // char2hex 把引号内字符编码为 \xHH，占位符也在引号内被编码 → 还原失败 → 回退
  // 回退版本 = 不保护标记直接执行 char2hex
  // __S__ 的下划线 _ = 0x5f，S = 0x53
  // __E__ 的下划线 _ = 0x5f，E = 0x45
  assert.ok(out.includes('\\x5f\\x5f\\x53\\x5f\\x5f'), '__S__ 应被 char2hex 编码为 \\xHH（回退后不保护）');
  assert.ok(out.includes('\\x5f\\x5f\\x45\\x5f\\x5f'), '__E__ 应被 char2hex 编码为 \\xHH（回退后不保护）');
  // 不应包含原始标记（被 char2hex 编码了）
  assert.ok(!out.includes('__S__'), '不应有原始 __S__ 标记（已被编码）');
  // 不应包含占位符残留
  assert.ok(!/7331999/.test(out), '不应有占位符残留');
});

test('7) 多标记同时保护（__S__、__E__、SQLISCANNER0）+ lowercase', () => {
  const payload = "1 UNION SELECT CONCAT('__S__', 'SQLISCANNER0', '__E__')";
  const out = applyTampers(payload, ctx, ['lowercase']);
  // SQL 部分应转小写
  assert.ok(out.includes('1 union select'), 'SQL 关键字应转小写');
  // 三个标记都应保持原样
  assert.ok(out.includes('__S__'), '__S__ 应保持原样');
  assert.ok(out.includes('__E__'), '__E__ 应保持原样');
  assert.ok(out.includes('SQLISCANNER0'), 'SQLISCANNER0 应保持原样');
  // 不应包含占位符残留
  assert.ok(!/7331999/.test(out), '不应有占位符残留');
});

test('8) __S__INL__E__ 复合标记 + lowercase → 拆分保护后正确还原', () => {
  // __S__INL__E__ 包含 __S__ 和 __E__，会被拆分为两个占位符
  // INL 部分不被保护，会被 lowercase 转为 inl
  // 还原后：__S__inl__E__
  const payload = "SELECT '__S__INL__E__'";
  const out = applyTampers(payload, ctx, ['lowercase']);
  // SQL 关键字应转小写
  assert.ok(out.startsWith('select'), 'SELECT 应转小写');
  // __S__ 和 __E__ 应被保护（保持原样）
  assert.ok(out.includes('__S__'), '__S__ 应保持原样');
  assert.ok(out.includes('__E__'), '__E__ 应保持原样');
  // INL 应被 lowercase 转为 inl
  assert.ok(out.includes('inl'), 'INL 应转小写');
  // 不应包含占位符残留
  assert.ok(!/7331999/.test(out), '不应有占位符残留');
});

test('9) 多 tamper 链式 + 标记保护（space2comment + lowercase）', () => {
  const payload = "1 UNION SELECT 'SQLISCANNER0'";
  const out = applyTampers(payload, ctx, ['space2comment', 'lowercase']);
  // space2comment 先执行：空格 → /**/
  // lowercase 后执行：全部转小写
  // 标记被保护：占位符是纯数字，两个 tamper 都不影响数字
  assert.ok(out.includes('/**/'), '空格应被替换为 /**/');
  assert.ok(out.includes('1/**/union/**/select'), 'SQL 关键字应转小写');
  assert.ok(out.includes('SQLISCANNER0'), '标记应保持原样');
  assert.ok(!/7331999/.test(out), '不应有占位符残留');
});

// [P0-FIX 2026-09-05] 数字粘连回归：编码类 tamper 把占位符相邻字符编成
// 以数字结尾的形式（如 x → %u0078），数字粘连使 (?<!\d) 锚点失配 →
// 严格还原漏掉第二个标记 → 回退到不保护版本 → 标记被编码 → UNION 拖库静默失败。
test('10) 数字粘连场景：__S__x__E__ + charunicodeencode → 两标记均还原', () => {
  const payload = "__S__x__E__ UNION SELECT";
  const out = applyTampers(payload, ctx, ['charunicodeencode']);
  assert.ok(out.includes('__S__'), `__S__ 应被还原，实际: ${out}`);
  assert.ok(out.includes('__E__'), `__E__ 应被还原，实际: ${out}`);
  assert.ok(!/7331999/.test(out), '不应有占位符残留');
});

test('11) 粘连 + payload 自带 7331999xxx 长数字 → 标记还原且原生数字不被误还原', () => {
  const payload = "__S__x__E__7331999001 UNION SELECT";
  const out = applyTampers(payload, ctx, ['charunicodeencode']);
  assert.ok(out.includes('__S__'), `__S__ 应被还原，实际: ${out}`);
  assert.ok(out.includes('__E__'), `__E__ 应被还原，实际: ${out}`);
});

test('12) 三标记两两粘连 __S__x__E__y__S__ + charunicodeencode → 全部还原', () => {
  const payload = "__S__x__E__y__S__ AND 1=1";
  const out = applyTampers(payload, ctx, ['charunicodeencode']);
  assert.equal((out.match(/__S__/g) || []).length, 2, `__S__ 应出现 2 次，实际: ${out}`);
  assert.equal((out.match(/__E__/g) || []).length, 1, `__E__ 应出现 1 次，实际: ${out}`);
  assert.ok(!/7331999/.test(out), '不应有占位符残留');
});

test('13) 全部编码类 tamper 扫描：__S__/__E__ 要么完好还原、要么整体回退（不半还原）', () => {
  // 遍历高风险编码类 tamper：标记要么完整保留（保护成功），
  // 要么完全按无保护版本变换（回退一致）——不允许出现"一半还原一半编码"的中间态
  // 中间态是最危险的：引擎按保护版构造请求却按无保护版匹配响应 → 静默失败。
  const encoded = ['charunicodeencode', 'charunicodeescape', 'htmlencode', 'hexentities',
    'decentities', 'char2hex', 'keyword2hex', 'octalencode', 'bin2hex'];
  const payload = "CONCAT('__S__', col, '__E__')";
  for (const name of encoded) {
    const out = applyTampers(payload, ctx, [name]);
    const sRestored = out.includes('__S__');
    const eRestored = out.includes('__E__');
    // 全还原 或 全不还原（回退后两个标记都被同一 tamper 变换）——两者必须一致
    assert.equal(sRestored, eRestored, `[${name}] 标记还原状态不一致（半还原中间态）: ${out}`);
  }
});

