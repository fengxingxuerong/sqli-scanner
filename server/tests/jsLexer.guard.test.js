// ============================================================================
// tests/jsLexer.guard.test.js —— 词法内核单测（D53 / spec 5.1.1 / design §1.2.2）
//
// 词法内核是嵌套/复杂度/重复/死代码/类型覆盖五道门禁的共同地基。
// 地基若把模板串、注释里的字符算进代码，所有上层度量都会系统性高估，
// 而门禁是「只许变浅/只减不增」的——高估 = 基线虚高 = 门禁被放宽。
// 故此处用最直接的反例钉住「什么不算代码」。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lex, findFunctions, countBranches, effectiveBodyLines } from '../../scripts/lib/jsLexer.mjs';

test('词法：模板串里的 { 不计深度', () => {
  const src = 'if (a) {\n  const x = `${a}.${b}`;\n  const y = "{}{}";\n}\n';
  assert.equal(lex(src).maxDepth, 1);
});

test('词法：注释里的 { 不计深度', () => {
  const src = 'if (a) {\n  // { { {\n  /* { { */\n}\n';
  assert.equal(lex(src).maxDepth, 1);
});

test('词法：模板串/注释/字符串里的 if 关键字不计入分支', () => {
  const src = 'const x = `if if if`;\n// if if\n/* if */\nconst y = "if";\n';
  assert.equal(countBranches(lex(src).tokens), 0);
});

test('词法：真实嵌套逐层递增（判据随嵌套变化，非固定）', () => {
  const src = 'function f(){\n if(a){\n  for(;;){\n   try{\n    x();\n   }catch(e){ }\n  }\n }\n}\n';
  assert.equal(lex(src).maxDepth, 4);
});

test('词法：对象字面量不计深度（否则基线虚高 = 门禁被放宽）', () => {
  const src = 'const a = {\n  b: 1,\n};\nfunction f(){\n  return {\n    c: 2,\n  };\n}\n';
  assert.equal(lex(src).maxDepth, 1, '赋值/返回对象字面量不进深度，仅 function 块计 1');
});

test('countBranches：if/for/while/case/catch/&&/||/??/?. /三目 各计一次', () => {
  const src = 'if(a){for(;;){}while(b){}switch(c){case 1:}try{}catch(e){}}\n'
    + 'const x = a && b || c ?? d;\nconst y = a?.b;\nconst z = a ? b : c;\n';
  assert.equal(countBranches(lex(src).tokens), 10);
});

test('findFunctions：识别 function / 类方法（类名.方法名）/ 箭头', () => {
  const src = [
    'function foo(a, b) {',
    '  return a + b;',
    '}',
    'class A {',
    '  bar(x) {',
    '    return x;',
    '  }',
    '}',
    'const f = (p) => {',
    '  return p;',
    '};',
  ].join('\n');
  const { functions } = findFunctions(src);
  const names = functions.map((fn) => fn.name);
  assert.ok(names.includes('foo'), `应识别 function foo，实际：${names.join(',')}`);
  assert.ok(names.includes('A.bar'), `应识别类方法 A.bar，实际：${names.join(',')}`);
  assert.ok(names.some((nm) => nm.startsWith('<arrow@')), `应识别箭头函数，实际：${names.join(',')}`);
  const foo = functions.find((fn) => fn.name === 'foo');
  assert.deepEqual(foo.params, ['a', 'b']);
});

test('findFunctions：if/for/switch 控制块不被当成函数', () => {
  const src = 'if (a) { x(); }\nfor (;;) { y(); }\nswitch (c) { case 1: z(); }\n';
  assert.equal(findFunctions(src).functions.length, 0);
});

test('effectiveBodyLines：剔除空行与纯注释行', () => {
  const src = 'function f() {\n  // 注释\n\n  const a = 1;\n  /* 块注释\n     继续 */\n  return a;\n}';
  assert.equal(effectiveBodyLines(src, 1, 8), 4);
});

test('lex：brace token 带 block 标记（对象字面量 vs 代码块）', () => {
  const src = 'const o = { a: 1 };\nif (x) { y(); }';
  const { tokens } = lex(src);
  const braceOpens = tokens.filter((t) => t.type === 'brace' && t.value === '{');
  assert.equal(braceOpens.filter((t) => t.block).length, 1, 'if 的块是 block');
  assert.equal(braceOpens.filter((t) => !t.block).length, 1, '对象字面量不是 block');
});

// ── [D66 2026-10-14] 正则字面量分支的回归判据 ────────────────────────────────
// 修复动机：此前正文不处理正则，`/[\\"]/` 里的引号被当字符串开 ⇒ 吞到文件尾，
// 后续函数全部丢失（jsonescape.js 的 transform 在 typecoverage 统计中蒸发）。

test('lex：正则体里的引号不再吞代码（D66 修复的动机场景）', () => {
  const src = 'const R = /[\\\\"]/g;\nfunction f(a){ return a; }\n';
  const { functions } = findFunctions(src);
  assert.ok(functions.some((fn) => fn.name === 'f'), '正则后的函数应被识别（此前被吞）');
});

test('lex：除法不误判为正则（a / b / c 三个 ident 相邻）', () => {
  const src = 'function g(a, b) { return a / b / 2; }\nfunction h(c) { return c/2; }\n';
  const { functions } = findFunctions(src);
  assert.equal(functions.length, 2, '除法场景两个函数都应识别');
  // 若 `/` 被误判为正则，`b / 2; }...` 会被当正则吞掉，函数边界损坏
  assert.equal(countBranches(lex(src).tokens), 0, '除法不产生分支');
});

test('lex：字符类内的 / 不结束正则（/[a/]/）', () => {
  const src = 'const R = /[a/]/;\nfunction f(x) { return x; }\n';
  const { functions } = findFunctions(src);
  assert.ok(functions.some((fn) => fn.name === 'f'), '字符类内的 / 不应提前结束正则');
});

test('lex：正则位置白名单（return /re/ 识别；`) / 2` 按除法走）', () => {
  const okSrc = 'function f() { return /ab+c/gi.test(s); }\n';
  assert.ok(findFunctions(okSrc).functions.some((fn) => fn.name === 'f'), 'return 后的正则应被识别');
  // 除法：`) / x` 处 `/` 前是 `)`，不在正则位置
  const divSrc = 'function g(a) { return (a + 1) / 2; }\n';
  assert.equal(countBranches(lex(divSrc).tokens), 0, '`) / 2` 不应形成任何分支/吞并');
  assert.ok(findFunctions(divSrc).functions.some((fn) => fn.name === 'g'), '除法后的函数结构完好');
});

test('lex：未闭合正则（换行即断）回落为普通 token，不吞后续行', () => {
  const src = 'const a = 1;\nconst bad = /foo\nfunction after() { return 1; }\n';
  const { functions } = findFunctions(src);
  assert.ok(functions.some((fn) => fn.name === 'after'), '未闭合正则不应吞掉后续函数');
});