// waf.bypassSemantics.test.js —— 语义索引的机械验证
// ============================================================================
// 本测试的核心不是"跑通"，而是**让元数据声明接受机械检验**：
//   CORE_SEMANTICS 里每条 `eliminates: ['or']` 都是人工写的**声明**，
//   本项目明确规定「不采信组件自报」——所以这里用插件自己的 transform 实测：
//   构造一个**确实含该 token** 的样本，应用插件后断言该 token **字面消失**。
//
//   ⚠️ 样本先自检「确实含该 token」再断言，否则插件对该样本空转 →
//      断言恒真 = 假绿（本仓反复踩的"断言太浅"）。这两步缺一不可。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
import '../src/core/tamper/applyTampers.js';
import {
  CORE_SEMANTICS,
  buildSemanticIndex,
  indexCoverage,
  listSemantics,
  maxNonWordRun,
  selectByAvoiding,
  estimatePunctCost,
  assertIndexIntegrity,
  SEMANTIC_CATEGORIES,
} from '../src/core/waf/bypass/semantics.js';

/** token → 保证含该 token 的最小样本（用于 eliminates 声明的实测检验） */
const SAMPLES = {
  and: '1 AND 1=1',
  or: '1 OR 1=1',
  '=': 'a=1',
  ' ': '1 AND 1=1',
  '>': 'a>1',
  substring: "SUBSTRING('abc',1,1)",
  'concat(': "CONCAT('a','b')",
  "'": "'abc'",
  '--': '1-- -',
  '\t': '1\tAND\t1',
  '\n': '1\nAND\n1',
  '/**/': '1/**/AND/**/1',
};

/** 断言"应用后该 token 消失"，且先自检样本有效（防空转假绿）。
 *  返回 null 表示通过，否则返回失败描述（由调用方汇总，一次暴露全部问题）。 */
function checkEliminates(name, token) {
  const plugin = tamperRegistry.get(name);
  if (!plugin) return `${name}: 插件未注册`;
  const sample = (SAMPLE_OVERRIDES[name] && SAMPLE_OVERRIDES[name][token]) || SAMPLES[token];
  if (sample === undefined) return `${name}: eliminates 声明了未登记的 token「${token}」→ 请补 SAMPLES 映射`;

  const re = new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
  if (!re.test(sample)) return `[样本自检] ${name}: 样本「${sample}」不含「${token}」→ 断言会空转`;

  const out = plugin.transform(sample, {});
  if (re.test(out)) {
    return `${name}: 声明 eliminates:「${token}」但 transform 后仍在 → ${JSON.stringify(out)}`;
  }
  return null;
}

/**
 * 插件专属样本：有些插件的适用形态很窄（如 substring2leftright 只认 PostgreSQL 的
 * `SUBSTRING(x FROM y FOR n)` 拼写），用通用样本会空转。
 * ⚠️ 这不是"为了让测试过而改样本"——插件的窄适用面本身就是**必须显式记录的事实**，
 *    否则 T2 选弹时会选到它却白跑。故同时写进 note 与 applicablePattern。
 */
const SAMPLE_OVERRIDES = {
  substring2leftright: { substring: 'SUBSTRING((SELECT usename FROM pg_user)::text FROM 1 FOR 1)' },
};

test('语义索引：完整性自检通过（索引里的插件名必须真实存在，防清单腐烂）', () => {
  assert.equal(assertIndexIntegrity(), true);
});

test('语义索引：覆盖度诚实报告，total 必须等于注册表实际插件数', () => {
  const c = indexCoverage();
  assert.equal(c.total, tamperRegistry.all().length);
  assert.equal(c.curated + c.family + c.unclassified, c.total);
  // 未分类项必须被列出（不假装全覆盖）
  assert.equal(c.unclassifiedNames.length, c.unclassified);
  assert.equal(new Set(c.unclassifiedNames).size, c.unclassified, '未分类清单不应有重复');
});

test('语义索引：每个精标条目必须声明了 body（token 声明或 note），禁空壳', () => {
  for (const [name, meta] of Object.entries(CORE_SEMANTICS)) {
    const body = (meta.eliminates?.length || 0) + (meta.mutates?.length || 0) + (meta.introduces?.length || 0);
    assert.ok(body > 0 || meta.note, `${name} 是空壳条目`);
  }
});

test('机械检验：eliminates 声明必须被插件真实 transform 兑现', () => {
  const problems = [];
  let checked = 0;
  for (const [name, meta] of Object.entries(CORE_SEMANTICS)) {
    for (const token of meta.eliminates || []) {
      const p = checkEliminates(name, token);
      if (p) problems.push(p);
      checked += 1;
    }
  }
  assert.deepEqual(problems, [], `有 ${problems.length} 条声明不成立（一次看全）：\n  - ${problems.join('\n  - ')}`);
  // 防"一条都没验"的空转
  assert.ok(checked >= 20, `实际检验的 eliminates 声明只有 ${checked} 条，疑似断言被跳过`);
});

test('机械检验：族派生条目的 eliminates 同样要兑现（space2*/tab2*/newline2*/comment2*）', () => {
  const derived = listSemantics().filter((e) => e.source === 'family' && (e.eliminates || []).length);
  const problems = [];
  for (const e of derived) {
    for (const token of e.eliminates) {
      const p = checkEliminates(e.name, token);
      if (p) problems.push(p);
    }
  }
  assert.deepEqual(problems, [], `族派生条目有 ${problems.length} 条声明不成立：\n  - ${problems.join('\n  - ')}`);
  // 下限按实测设（不是拍脑袋的整数）：族规则覆盖的插件数
  assert.ok(derived.length >= 40, `族派生条目仅 ${derived.length} 条，space2* 族覆盖异常`);
});

test('口径：maxNonWordRun 对齐 CRS 942460 —— `-- -` 是 4 连非词字符', () => {
  assert.equal(maxNonWordRun('1-- -'), 4);
  assert.equal(maxNonWordRun('1 AND 1=1'), 1);
  assert.equal(maxNonWordRun('/**/'), 4);
  assert.equal(maxNonWordRun('abc'), 0);
});

test('口径：dash2hash 确实降低标点代价（wafRecommend 实测结论的可复算形态）', () => {
  const before = maxNonWordRun('1-- -');
  const after = estimatePunctCost(['dash2hash'], '1-- -');
  assert.equal(after.before, before);
  assert.ok(after.after <= before, `dash2hash 后非词串反而变长：${before} → ${after.after}`);
  assert.equal(after.failed.length, 0, `链中插件抛错：${after.failed.join(',')}`);
});

test('机械检验：reducesPunct 声明必须真的降低非词字符连续串（CRS 942460 对抗维度）', () => {
  const reducers = Object.entries(CORE_SEMANTICS).filter(([, m]) => m.reducesPunct);
  assert.ok(reducers.length > 0, '应至少有一条 reducesPunct 声明（dash2hash）—— 全空说明维度未被使用');
  const problems = [];
  for (const [name] of reducers) {
    const plugin = tamperRegistry.get(name);
    const sample = '1-- -';
    const before = maxNonWordRun(sample);
    const out = plugin.transform(sample, {});
    const after = maxNonWordRun(out);
    if (!(after < before)) {
      problems.push(`${name}: ${JSON.stringify(sample)}(${before}) → ${JSON.stringify(out)}(${after})，未降低`);
    }
  }
  assert.deepEqual(problems, [], `reducesPunct 声明不成立：\n  - ${problems.join('\n  - ')}`);
});

test('选弹：黑名单命中 eliminates 的插件进入 boosted（正面对抗目标黑名单）', () => {
  const r = selectByAvoiding(['or']);
  assert.ok(r.boosted.includes('symboliclogical'), 'symboliclogical 消除 or，应被加分');
  assert.ok(!r.dropped.some((d) => d.name === 'symboliclogical'), 'symboliclogical 不应被丢弃');
});

test('选弹：mutates 命中黑名单的插件被排除（该词字面仍在，简单正则仍会匹配）', () => {
  const r = selectByAvoiding(['union']);
  for (const n of ['misunion', 'union2no', 'dunion', '0eunion']) {
    assert.ok(
      r.dropped.some((d) => d.name === n && d.reason.startsWith('mutates:')),
      `${n} 的 mutates 含 union，应被排除`,
    );
    assert.ok(!r.usable.includes(n), `${n} 不应出现在 usable 里`);
  }
});

test('选弹：unclassified 在黑名单非空时必须被排除（不认识的不敢用，避免盲试噪声）', () => {
  const r = selectByAvoiding(['select']);
  const unclassified = indexCoverage().unclassifiedNames;
  if (unclassified.length) {
    for (const n of unclassified) {
      assert.ok(r.dropped.some((d) => d.name === n && d.reason === 'unclassified'), `${n} 是未分类项，应被排除`);
    }
  }
  // 反向：黑名单为空时不做保守排除（保持既有行为）
  const r0 = selectByAvoiding([]);
  assert.equal(r0.dropped.filter((d) => d.reason === 'unclassified').length, 0);
});

test('选弹：返回的 usable 必须通过既有链守卫（terminal/dbms 语义不在本模块重复实现）', () => {
  const r = selectByAvoiding(['or', 'select']);
  const validated = tamperRegistry.validateChain(r.usable, {});
  assert.deepEqual(r.usable, validated.plugins);
  assert.ok(Array.isArray(r.dropped));
});

test('类别枚举：listSemantics 可按类别过滤，且类别值都在枚举内', () => {
  const valid = new Set(Object.values(SEMANTIC_CATEGORIES));
  for (const e of listSemantics()) {
    assert.ok(
      valid.has(e.category) || e.category === 'unclassified',
      `${e.name} 的类别 ${e.category} 不在枚举内`,
    );
  }
  const lex = listSemantics({ category: SEMANTIC_CATEGORIES.LEXICAL });
  assert.ok(lex.length > 0);
  assert.ok(lex.every((e) => e.category === SEMANTIC_CATEGORIES.LEXICAL));
});

test('索引是懒加载单例：多次调用返回同一对象（避免每次重建 228 条）', () => {
  assert.equal(buildSemanticIndex(), buildSemanticIndex());
});
