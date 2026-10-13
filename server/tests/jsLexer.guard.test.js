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