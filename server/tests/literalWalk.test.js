// ============================================================================
// tests/literalWalk.test.js —— literalWalk 遍历抽象单测（D57 5.1）
//
// 关键契约：未闭合字面量 → onAbort 且原样输出（design §2.5 风险缓解）
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { walkLiterals } from '../src/core/tamper/literalWalk.js';

test('无回调时原样透传', () => {
  assert.equal(walkLiterals("SELECT * FROM t WHERE a = 'hello'"), "SELECT * FROM t WHERE a = 'hello'");
  assert.equal(walkLiterals('a "b" c'), 'a "b" c');
});

test('onText：引号外文本段回调', () => {
  const result = walkLiterals("SELECT * FROM t WHERE a = 'hello'", {
    onText: (t) => t.replace(/ /g, '_'),
  });
  assert.equal(result, "SELECT_*_FROM_t_WHERE_a_=_'hello'");
});

test('onLiteral：引号内字面量回调', () => {
  const result = walkLiterals("WHERE a = 'hello'", {
    onLiteral: (body, quote) => `X${quote}${body}${quote}`,
  });
  assert.equal(result, "WHERE a = X'hello'");
});

test('onLiteral：双引号字面量回调', () => {
  const result = walkLiterals('WHERE a = "hello"', {
    onLiteral: (body, quote) => `X${quote}${body}${quote}`,
  });
  assert.equal(result, 'WHERE a = X"hello"');
});

test('关键契约：未闭合单引号 → onAbort 且原样输出', () => {
  const src = "WHERE a = 'unclosed";
  const result = walkLiterals(src, {
    onLiteral: (body) => `ENCODED('${body}')`,
    onAbort: (remaining) => remaining,
  });
  assert.equal(result, "WHERE a = 'unclosed", '未闭合应原样输出，不被编码');
});

test('关键契约：未闭合双引号 → onAbort 且原样输出', () => {
  const src = 'WHERE a = "unclosed';
  const result = walkLiterals(src, {
    onLiteral: (body) => `ENCODED("${body}")`,
    onAbort: (remaining) => remaining,
  });
  assert.equal(result, 'WHERE a = "unclosed', '未闭合应原样输出，不被编码');
});

test('关键契约：未闭合无 onAbort 时默认原样输出', () => {
  const src = "WHERE a = 'unclosed";
  const result = walkLiterals(src, {
    onLiteral: (body) => `ENCODED('${body}')`,
  });
  assert.equal(result, "WHERE a = 'unclosed");
});

test('行注释 -- 内的引号不触发字面量扫描', () => {
  const src = "SELECT 1 -- this has 'quotes' inside\nAND 2";
  const result = walkLiterals(src, {
    onText: (t) => t.replace(/ /g, '_'),
  });
  // 注释行原样透传，不替换空格
  assert.ok(result.includes("-- this has 'quotes' inside"), '注释内引号不触发字面量');
  assert.ok(result.includes("SELECT_1_"), '注释前文本被变换');
});

test('多段交替：text-literal-text-literal-text', () => {
  const src = "a='1' AND b='2'";
  const result = walkLiterals(src, {
    onText: (t) => t.toUpperCase(),
    onLiteral: (body) => `[${body}]`,
  });
  assert.equal(result, "A=[1] AND B=[2]");
});

test('空串和 null 安全', () => {
  assert.equal(walkLiterals(''), '');
  assert.equal(walkLiterals(null), '');
  assert.equal(walkLiterals(undefined), '');
});

test('转义引号在字面量内不提前闭合', () => {
  const src = "a = 'it\\'s ok'";
  const result = walkLiterals(src, {
    onLiteral: (body) => `[${body}]`,
  });
  assert.equal(result, "a = [it\\'s ok]");
});