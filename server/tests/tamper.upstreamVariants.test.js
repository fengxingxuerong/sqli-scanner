// ============================================================================
// tamper.upstreamVariants.test.js —— T-6「上游形态变体」5 件的结构性判据
//
// 背景（批次 D13）：版本注释族（versionedkeywords / versionedmorekeywords /
// halfversionedmorekeywords / modsecurity*versioned）的本仓形态与上游 1.10.10 不同
// （带空格逐词包裹 vs 贴字/不闭合/整段单注释）。谁上默认由 modsec-live 真机 A/B 判，
// 本批先把上游形态做成**不动默认链**的变体插件。期望不自己写：逐字节锚点放在各插件
// 的 doctests 字段（取自上游 docstring，由 tamper.doctest.test.js 自动复验）；
// 本文件钉 doctest 覆盖不到的**结构性不变量**，使其杀得掉「照着期望硬编码」的实现。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
// 导入即触发内置插件注册（applyTampers.js 内部 registerMany）
import '../src/core/tamper/applyTampers.js';

const get = (name) => {
  const p = tamperRegistry.get(name);
  assert.ok(p, `插件 ${name} 应已注册`);
  return p;
};

test('nospace 两件：贴字判据 —— 输出不存在「空格 + /*!」', () => {
  for (const name of ['versionedkeywordsnospace', 'versionedmorekeywordsnospace']) {
    const out = get(name).transform('1 UNION ALL SELECT NULL#');
    assert.ok(!/ \/\*!/.test(out), `${name}: 注释标记旁不允许残留空格 ⇒ ${out}`);
    assert.ok(out.includes('/*!UNION*//*!ALL*/'), `${name}: 相邻关键词应呈贴字邻接形态 ⇒ ${out}`);
  }
});

test('nospace 两件的覆盖面差异由「函数调用是否包裹」承载（防两件实现互相漂移）', () => {
  const input = 'SELECT CONCAT(CHAR(1), NULL) FROM t';
  const bare = get('versionedkeywordsnospace').transform(input);
  const more = get('versionedmorekeywordsnospace').transform(input);
  // versionedkeywordsnospace：后随 ( 的词不包 ⇒ CONCAT( / CHAR( / FROM t 的 t?（t 非关键词）原样
  assert.ok(bare.includes('CONCAT(') && bare.includes('CHAR('), `裸词形态不包函数调用 ⇒ ${bare}`);
  // versionedmorekeywordsnospace：函数名也包（/*!CONCAT*/(），但 CAST ∈ 排除集不包
  assert.ok(more.includes('/*!CONCAT*/(') && more.includes('/*!CHAR*/('), `函数名应被包裹 ⇒ ${more}`);
  const cast = get('versionedmorekeywordsnospace').transform('SELECT CAST(1 AS CHAR)');
  assert.ok(!cast.includes('/*!CAST'), `CAST ∈ IGNORE_SPACE_AFFECTED 排除集，不得包裹 ⇒ ${cast}`);
  assert.ok(cast.includes('/*!AS*//*!CHAR*/'), `AS/CHAR 应被包裹 ⇒ ${cast}`);
});

test('open 件：前插的 /*!0 不闭合 —— 输出不引入任何 */', () => {
  const input = "1' UNION ALL SELECT CONCAT(CHAR(58,107,112,113,58),IFNULL(CAST(CURRENT_USER() AS CHAR),CHAR(32)),CHAR(58,97,110,121,58)), NULL, NULL# AND 'QDWa'='QDWa";
  const out = get('halfversionedmorekeywordsopen').transform(input);
  assert.ok(!out.includes('*/'), `不闭合判据：输出不得出现 */ ⇒ ${out}`);
  // 上游 doctest 形态恰好 14 个 /*!0（UNION/ALL/SELECT/CONCAT/CHAR×3/IFNULL/CURRENT_USER/AS/NULL×2/AND，
  // 含 # 之后的 AND；CAST ∈ 排除集故不前插）
  assert.equal((out.match(/\/\*!0/g) || []).length, 14, `前插计数应为 14 ⇒ ${out}`);
  assert.ok(!out.includes(' /*!0'), `空格贴字判据 ⇒ ${out}`);
});

test('zeroversionedblock：单条注释判据 —— 恰一个 /*! 与一个 */，注释后缀原样保留', () => {
  const out = get('modsecurityzeroversionedblock').transform('1 AND 2>1-- ');
  assert.equal((out.match(/\/\*!/g) || []).length, 1, `整段单注释 ⇒ ${out}`);
  assert.equal((out.match(/\*\//g) || []).length, 1, `恰一个闭合 ⇒ ${out}`);
  assert.ok(out.endsWith('*/-- '), `注释截断后缀（-- ）应原样在尾部 ⇒ ${out}`);
  assert.equal(get('modsecurityzeroversionedblock').transform('1AND2>1'), '1AND2>1', '无空格 ⇒ 原样返回');
  // 注释截断按上游 marker **优先级**（# → -- → /*）而非位置：# 在后也优先截它 ⇒ -- x 留在注释体内
  const pri = get('modsecurityzeroversionedblock').transform('1 AND 2>1-- x#y');
  assert.ok(pri.endsWith('*/#y') && pri.includes('/*!00000AND 2>1-- x*/'), `postfix 取最先命中的优先级 marker（#）⇒ ${pri}`);
});

test('versionedblock：ctx.rng 注入下完全确定（仓规同 randomcomments）', () => {
  const p = get('modsecurityversionedblock');
  const out = p.transform('1 AND 2>1--', { rng: () => 0.5 });
  assert.equal(out, '1 /*!30550AND 2>1*/--', `rng=0.5 ⇒ 100+450=550 ⇒ ${out}`);
  // 缺省 rng：两次输出都满足 match 契约的形态（且允许彼此不同）
  const a = p.transform('1 AND 2>1--');
  const b = p.transform('1 AND 2>1--');
  for (const o of [a, b]) assert.match(o, /^1 \/\*!30\d{3}AND 2>1\*\/--$/, `缺省 rng 形态 ⇒ ${o}`);
});

test('5 件全部登记且不改动默认链成员（变体不进 wafRecommend 的默认链）', () => {
  const names = [
    'versionedkeywordsnospace',
    'versionedmorekeywordsnospace',
    'halfversionedmorekeywordsopen',
    'modsecurityversionedblock',
    'modsecurityzeroversionedblock',
  ];
  for (const n of names) assert.ok(tamperRegistry.get(n), `${n} 应已注册`);
  // 默认件原样在册（本批不动它们的行为）
  for (const n of ['versionedkeywords', 'versionedmorekeywords', 'halfversionedmorekeywords', 'modsecurityversioned', 'modsecurityzeroversioned']) {
    assert.ok(tamperRegistry.get(n), `默认件 ${n} 应保持注册`);
  }
});
