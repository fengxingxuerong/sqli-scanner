// =====================================================================
// scanConfigUtils.test.js —— 配置入口值消毒原语的单测
//
// [为什么单独建文件]
// [大文件拆分 2026-09-21] clamp 家族 + clampParams 从 api/scanRoutes.js 外移到
// api/scanConfigUtils.js。此前它们是**文件内私有箭头函数**，只能通过
// 「构造一份 body 调 sanitizeStart」间接验证（且要看最终 config 才能反推）。
//
// 这簇是配置入口的第一道闸门，重点钉**边界语义**：
//   · clampInt/clampNum 的区间与取整差异；
//   · clampStr 的「null/空串 → undefined」语义（不是返回默认值）；
//   · pick* 的「未传 → undefined」（下游靠它区分「没传」与「传了非法值」）；
//   · sanitizeCookieMap 的原型污染键过滤（__proto__ 进来会污染整个进程）；
//   · clampParams 的数量/长度上限（DoS 面）。
// =====================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  clampInt, clampNum, boolOf, clampStr, pickInt, pickBool,
  sanitizeCookieMap, clampParams,
} from '../src/api/scanConfigUtils.js';

// ── clampInt ─────────────────────────────────────────────────────────

test('clampInt：区间内原样（并取整）', () => {
  assert.equal(clampInt(5, 0, 1, 10), 5);
  assert.equal(clampInt(5.4, 0, 1, 10), 5, '四舍五入');
  assert.equal(clampInt(5.6, 0, 1, 10), 6);
});

test('clampInt：超出上下界被钳制', () => {
  assert.equal(clampInt(999, 0, 1, 10), 10);
  assert.equal(clampInt(-999, 0, 1, 10), 1);
  assert.equal(clampInt(1, 0, 1, 10), 1, '边界含');
  assert.equal(clampInt(10, 0, 1, 10), 10, '边界含');
});

test('clampInt：非有限数 → def（NaN/Infinity/非数字字符串/对象）', () => {
  assert.equal(clampInt(NaN, 3, 1, 10), 3);
  assert.equal(clampInt(Infinity, 3, 1, 10), 3, 'Infinity 走 def，不是钳到 max');
  assert.equal(clampInt(-Infinity, 3, 1, 10), 3);
  assert.equal(clampInt('abc', 3, 1, 10), 3);
  assert.equal(clampInt({}, 3, 1, 10), 3);
  assert.equal(clampInt(undefined, 3, 1, 10), 3);
});

test('clampInt：数字字符串按数字处理（Number 转换）', () => {
  assert.equal(clampInt('5', 0, 1, 10), 5);
  // ⚠ 空串陷阱（实测钉住，勿想当然）：Number('') === 0 是**有限数**，
  // 所以不会走 def，而是被钳到下界 —— clampInt('', 7, 1, 10) === 1 而非 7。
  // 若某配置键需要「空串视为未传」，应在调用侧先判空，不能靠 clampInt。
  assert.equal(Number(''), 0, '前提');
  assert.equal(clampInt('', 7, 1, 10), 1);
});

test('clampInt：def 传 undefined 时非法输入返回 undefined（历史用法）', () => {
  assert.equal(clampInt(NaN, undefined, 1, 10), undefined);
  assert.equal(clampInt(5, undefined, 1, 10), 5, '合法输入仍正常');
});

// ── clampNum ─────────────────────────────────────────────────────────

test('clampNum：与 clampInt 的差别是**不取整**（时间阈值需要小数）', () => {
  assert.equal(clampNum(2.5, 0, 0, 10), 2.5);
  assert.equal(clampInt(2.5, 0, 0, 10), 3, '对照：clampInt 会取整');
  assert.equal(clampNum(0.1, 0, 0, 1), 0.1);
});

test('clampNum：非法值 → def，超界被钳制', () => {
  assert.equal(clampNum('x', 1.5, 0, 10), 1.5);
  assert.equal(clampNum(99, 1, 0, 10), 10);
});

// ── boolOf ───────────────────────────────────────────────────────────

test('boolOf：null/undefined 用默认值，其余走真值判定', () => {
  assert.equal(boolOf(null, true), true);
  assert.equal(boolOf(undefined, true), true);
  assert.equal(boolOf(undefined), false, '缺省默认 false');
  assert.equal(boolOf(true), true);
  assert.equal(boolOf(1), true);
  assert.equal(boolOf(0), false);
  assert.equal(boolOf(''), false);
  assert.equal(boolOf('false'), true, '非空字符串是 truthy —— 不做字符串解析');
});

// ── clampStr ─────────────────────────────────────────────────────────

test('clampStr：超长截断，短串原样（不填充、不 trim）', () => {
  assert.equal(clampStr('abcdef', null, 3), 'abc');
  assert.equal(clampStr('ab', null, 10), 'ab');
  assert.equal(clampStr('  a  ', null, 10), '  a  ', '不 trim');
});

test('★语义★ clampStr：null/undefined → undefined（不是默认值）', () => {
  // 「该键不写入」的信号，下游靠它省略字段。
  assert.equal(clampStr(null, 'x', 10), undefined);
  assert.equal(clampStr(undefined, 'x', 10), undefined);
  assert.equal(clampStr('', 'x', 10), undefined, '空串同样视为「没配」');
});

test('clampStr：非字符串先 String()', () => {
  assert.equal(clampStr(12345, null, 3), '123');
  assert.equal(clampStr(false, null, 10), 'false');
});

// ── pickInt / pickBool ───────────────────────────────────────────────

test('★语义★ pickInt：键未传（undefined/null）→ undefined，**不是**默认值', () => {
  // 这是与 clampInt 的关键差别：pick 用于「用户没传就不写进 config」。
  assert.equal(pickInt({}, 'nope', 5, 1, 10), undefined);
  assert.equal(pickInt({ n: null }, 'n', 5, 1, 10), undefined);
  assert.equal(pickInt({ n: 5 }, 'n', 0, 1, 10), 5, '传了就钳制');
});

test('pickInt：传了非法值 → def（走 clampInt）', () => {
  assert.equal(pickInt({ n: 'abc' }, 'n', 7, 1, 10), 7);
  assert.equal(pickInt({ n: 999 }, 'n', 7, 1, 10), 10);
});

test('★语义★ pickBool：键未传 → undefined（可区分 false）', () => {
  assert.equal(pickBool({}, 'b'), undefined);
  assert.equal(pickBool({ b: null }, 'b'), undefined);
  assert.equal(pickBool({ b: false }, 'b'), false, '显式 false 必须保留');
  assert.equal(pickBool({ b: 1 }, 'b'), true);
});

// ── sanitizeCookieMap ────────────────────────────────────────────────

test('sanitizeCookieMap：保留合法字符串键值对', () => {
  assert.deepEqual(sanitizeCookieMap({ a: '1', b: '2' }), { a: '1', b: '2' });
});

test('★安全★ sanitizeCookieMap：过滤原型污染键 __proto__ / constructor / prototype', () => {
  // 若原样合并进配置对象会污染 Object.prototype（影响整个进程），不是"数据不好看"。
  const out = sanitizeCookieMap({ __proto__: 'x', constructor: 'y', prototype: 'z', ok: '1' });
  assert.deepEqual(out, { ok: '1' });
  assert.equal({}.x, undefined, 'Object.prototype 未被污染');
});

test('sanitizeCookieMap：非字符串键值被丢弃；空键/超长被丢弃', () => {
  assert.deepEqual(sanitizeCookieMap({ a: 1 }), undefined, '非字符串值 → 全丢 → undefined');
  assert.deepEqual(sanitizeCookieMap({ a: '1', b: 2 }), { a: '1' });
  assert.deepEqual(sanitizeCookieMap({ '': 'v', k: 'v' }), { k: 'v' }, '空键丢弃');
  assert.equal(sanitizeCookieMap({ ['k'.repeat(300)]: 'v' }), undefined, '超长键丢弃');
  assert.equal(sanitizeCookieMap({ k: 'v'.repeat(5000) }), undefined, '超长值丢弃');
});

test('sanitizeCookieMap：上限 32 键（超出部分丢弃）', () => {
  const big = {};
  for (let i = 0; i < 50; i++) big[`k${i}`] = 'v';
  assert.equal(Object.keys(sanitizeCookieMap(big)).length, 32);
});

test('sanitizeCookieMap：非对象/数组/null → undefined（不抛错）', () => {
  assert.equal(sanitizeCookieMap(null), undefined);
  assert.equal(sanitizeCookieMap('str'), undefined);
  assert.equal(sanitizeCookieMap([]), undefined);
  assert.equal(sanitizeCookieMap({}), undefined, '空对象 → undefined（n=0）');
});

// ── clampParams ──────────────────────────────────────────────────────

test('clampParams：键名与值长度被截断', () => {
  const out = clampParams({ ['k'.repeat(200)]: 'v'.repeat(20000) }, 50, 10000, 100);
  assert.equal(Object.keys(out)[0].length, 100);
  assert.equal(out[Object.keys(out)[0]].length, 10000);
});

test('clampParams：超出 maxKeys 的条目被丢弃（DoS 面）', () => {
  const big = {};
  for (let i = 0; i < 100; i++) big[`k${i}`] = 'v';
  assert.equal(Object.keys(clampParams(big)).length, 50);
});

test('clampParams：非字符串值转字符串（null → 空串而非 "null"）', () => {
  assert.deepEqual(clampParams({ a: null }), { a: '' });
  assert.deepEqual(clampParams({ a: 5 }), { a: '5' });
});

test('clampParams：非对象/数组/null → 空对象（不抛错）', () => {
  assert.deepEqual(clampParams(null), {});
  assert.deepEqual(clampParams([]), {});
  assert.deepEqual(clampParams('x'), {});
});
