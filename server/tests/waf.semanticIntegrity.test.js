// waf.semanticIntegrity.test.js —— 弹药库实测派生与语义完整性的机械守卫
// ============================================================================
// 本文件守两件事，缺一都会让 D15 的成果悄悄退化：
//   ① **派生的收益**真的兑现：真机唯一打穿的 unionvaluesrow/unionvalues 是未分类插件，
//      没有实测派生就永远进不了候选池（只能靠人工对拍进静态表）。
//   ② **结构判据**真的抓得住、且不误杀：抓不住 ⇒ 假弹药继续占名额；误杀 ⇒ 真弹药被请走。
//
// ⚠️ 每条"应该命中"的断言都配一条"不应该命中"的对照 —— 只有一边的断言是空转
//    （判据写成恒真也能过）。这是本仓反复强调的反假绿纪律。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  PROBE_CORPUS,
  INVARIANTS,
  auditPlugin,
  auditAll,
  semanticUnsafeRegistry,
  isSemanticallyUnsafe,
  findInwordSplit,
  findUnclosedComment,
  normalizeForToken,
} from '../src/core/waf/bypass/semanticIntegrity.js';
import { buildSemanticIndex } from '../src/core/waf/bypass/semantics.js';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
import '../src/core/tamper/applyTampers.js';

// ── 一、词内切分：抓得住 + 不误杀 ──────────────────────────────────────────

test('命中：词内切分族必须被 inword-split 抓到（D14 真机证伪的同型）', () => {
  // 这七件都是「在标识符内部插分隔符」：`UN/**/ION` 在 MySQL 里是两个标识符
  // ⇒ 整条语法错误。它们能过 WAF（破坏整词匹配）却拼不出可执行的 SQL，
  // 正是「放行 19/19、打穿 0/19」的机理来源。
  const targets = ['sap', 'lad', 'dhs', 'accessfilter', 'aspjetty', 'nullencode', 'squiggle'];
  const unsafe = semanticUnsafeRegistry();
  for (const n of targets) {
    assert.ok(unsafe.has(n), `${n} 应被判为语义不可用（词内切分）`);
    assert.ok(
      unsafe.get(n).some((v) => v.id === 'inword-split'),
      `${n} 的违规类型应为 inword-split，实际：${JSON.stringify(unsafe.get(n))}`,
    );
  }
});

test('不误杀：词**间**插入注释是合法写法，不得被判词内切分', () => {
  // `UNION/**/SELECT` 的注释落在原本就有空白的位置 ⇒ MySQL 正常解析。
  // 判据若退化成「出现 字母/注释/字母 就算」，这一条会立刻变红 —— 故必须留在测试里。
  for (const n of ['space2comment', 'randomcomments', 'comments', 'versionedkeywords', 'informationschemacomment']) {
    assert.ok(!isSemanticallyUnsafe(n), `${n} 是词间/合法形态，不应被判语义不可用`);
  }
});

test('★ 反向钉子：判据若退化成「字母-注释-字母」宽松匹配，会立刻误杀合法插件', () => {
  // 这条不是测实现，是**证明严格判据的必要性**：宽松版对合法输出也会命中，
  // 所以 `findInwordSplit` 的「前后文在原文里必须连续」这一层不能删。
  const legal = tamperRegistry.get('space2comment').transform('1 UNION SELECT 1', {});
  assert.ok(legal.includes('/**/'), `space2comment 应真的插入了注释，实际：${JSON.stringify(legal)}`);

  const loose = /[A-Za-z0-9_]\/\*\*\/[A-Za-z0-9_]/.test(legal); // 宽松版（只看形态）
  assert.equal(loose, true, '宽松判据应当命中合法输出（否则本条钉子无效）');
  assert.deepEqual(
    findInwordSplit('1 UNION SELECT 1', legal),
    [],
    `严格判据不得命中词间插入：${JSON.stringify(legal)}`,
  );
});

test('inword-split 的判据本身：词内命中、词间不命中', () => {
  assert.deepEqual(findInwordSplit('UNION', 'UN/**/ION'), ['UN[/**/]ION'], '词内：原文是字母紧邻');
  assert.deepEqual(findInwordSplit('UNION SELECT', 'UNION/**/SELECT'), [], '词间：原文有空白');
  assert.deepEqual(findInwordSplit('AND', 'A~~ND'), ['A[~~]ND'], '~~ 也是分隔符');
});

// ── 二、注释未闭合 ────────────────────────────────────────────────────────

test('★ 真机复核钉子（D16）：12 件名单逐件成立，含被怀疑过的 misunion / lad', async () => {
  // 依据：CI run 37788832263 的 PL1 真机报告（CRS 4.30.0 / PL1 / 靶站 db 模式）逐件核对。
  //
  // ⚠️ 读那份报告时**必须**先读它的「口径」第 5 条：「直连打穿(本链)」一列会被
  //    **nop 样本**污染 —— 该链没改动过的样本本来就打穿，不能算它的功劳。
  //    实测复核（本机可复现）：
  //      · misunion：报告值 5/19 …但未改动的 12 条里打穿 5 条、它真正改动的 7 条**全挂**
  //      · lad    ：报告值 1/19 …未改动的 2 条里打穿 1 条、真正改动的 17 条**全挂**
  //    ⇒ 真机证据**支持**判据（不是误杀）。本钉子防的就是"看到 >0 就放宽判据"这类改动。
  const names = [
    'keywordSplit', 'misunion', 'sap', 'lad', 'dhs', 'accessfilter', 'aspjetty',
    'nullencode', 'squiggle',
    'randomboundary', 'halfversionedmysql', 'halfversionedmorekeywordsopen',
  ];
  assert.equal(names.length, 12, '名单规模变了 ⇒ 必须重新做一轮真机复核再改这里');
  const unsafe = semanticUnsafeRegistry();
  for (const n of names) {
    assert.ok(unsafe.has(n), `${n} 应被判语义不可用（真机已复核该判定成立）`);
  }
});

test('命中：块注释未闭合必须被抓到（整段留在注释里，MySQL 解析不到）', () => {
  const unsafe = semanticUnsafeRegistry();
  for (const n of ['halfversionedmysql', 'halfversionedmorekeywordsopen']) {
    assert.ok(unsafe.has(n), `${n} 应被判为语义不可用（注释未闭合）`);
    assert.ok(unsafe.get(n).some((v) => v.id === 'unclosed-comment'), `${n} 应为 unclosed-comment`);
  }
  // 直接验判据本身（不经过注册表）
  assert.ok(findUnclosedComment('1 /*!0UNION /*!0SELECT 1').length > 0, '开 2 闭 0 ⇒ 命中');
  assert.deepEqual(findUnclosedComment('1 /*!00000UNION*/ SELECT 1'), [], '开 1 闭 1 ⇒ 不命中');
});

test('不误杀：版本注释**闭合**的写法合法（zeroversioned / modsecurityzeroversioned）', () => {
  for (const n of ['zeroversioned', 'modsecurityzeroversioned']) {
    assert.ok(!isSemanticallyUnsafe(n), `${n} 的注释是闭合的，不应被判不可用`);
  }
});

// ── 三、派生口径 ──────────────────────────────────────────────────────────

test('★ 派生口径：URL 编码后的关键词不算「已消失」（normalizeForToken 的必要性）', () => {
  // `%09UNION` 里的 `9` 是词字符 ⇒ 词边界判据失配 ⇒ 不还原就会把"还在的 UNION"
  // 误算成已消失，进而把一批空白族错认成"消除 union/select 的强弹药"（污染 covers 打分）。
  assert.match(normalizeForToken('1%09UNION'), /\sUNION$/, 'URL 编码应被还原为空白');
  assert.ok(!/\bunion\b/i.test('1%09UNION'), '未还原时词边界确实失配（本条的前置事实）');
  // 兑现到插件：randomwhitespace 只换空白，不得派生出消除 union
  const rw = auditPlugin('randomwhitespace');
  assert.ok(!rw.eliminates.includes('union'), `randomwhitespace 不应派生出消除 union，实际：${JSON.stringify(rw.eliminates)}`);
});

test('★ 语料必须覆盖「无 FROM 标量子查询」与「字符串字面量」两种形态', () => {
  // 少任一条，条件型插件会被误判成 nop（"形态不匹配" ≠ "没本事"）：
  //   · 标量子查询形态 ⇒ scalarselectinline（D3 原创、真机方向的关键弹药）
  //   · 字符串字面量形态 ⇒ hexliterals / quote2hex 一类
  const joined = PROBE_CORPUS.join('\n');
  assert.match(joined, /\(\s*SELECT\s+version\(\)\s*\)/i, '语料缺少无 FROM 标量子查询形态');
  assert.match(joined, /'abc'/, '语料缺少字符串字面量形态');
  // 兑现：前者必须让 scalarselectinline 派生出 eliminates:['select']
  const ssi = auditPlugin('scalarselectinline');
  assert.ok(
    ssi.eliminates.includes('select'),
    `scalarselectinline 应派生 eliminates:['select']，实际 ${JSON.stringify(ssi.eliminates)}（changed=${ssi.changed}）`,
  );
});

test('★ 回归钉子：真机唯一打穿的 unionvaluesrow/unionvalues 必须被派生并进索引', () => {
  const idx = buildSemanticIndex();
  for (const n of ['unionvaluesrow', 'unionvalues']) {
    const meta = idx.get(n);
    assert.ok(meta, `${n} 应在索引里`);
    assert.equal(meta.category, 'unclassified', `${n} 仍是未分类 —— 本条正是为它存在的`);
    assert.ok(
      (meta.eliminates || []).includes('select'),
      `${n} 必须派生出 eliminates:['select']，否则定向搜索永远选不到它（实际 ${JSON.stringify(meta.eliminates)}）`,
    );
    assert.ok(!isSemanticallyUnsafe(n), `${n} 是合法弹药，不得被判不可用`);
  }
});

test('派生兜底标记：整串编码族必须被标 eliminatesAll（否则会霸榜 covers）', () => {
  // 编码族消除的是整个 payload 的明文，不是某个词 ⇒ 若不标 eliminatesAll，
  // scoreMeta 会把它当成"消除 16 个词的超级弹药"排第一（既有纪律：兜底弹药必须靠后）。
  const codecs = ['encode2hex', 'encode2dec', 'encode2oct', 'decentities'];
  for (const n of codecs) {
    const a = auditPlugin(n);
    assert.equal(a.eliminatesAll, true, `${n} 应被判为整串编码（eliminatesAll）`);
  }
  // 对照：只换空白的不得被当成编码族
  assert.equal(auditPlugin('randomwhitespace').eliminatesAll, false, 'randomwhitespace 不是整串编码');
});

// ── 四、不变量表自身的完整性 ──────────────────────────────────────────────

test('不变量表不得腐烂：每条都要有真实命中者（防"写了没人中"的空转）', () => {
  const all = auditAll();
  for (const inv of INVARIANTS) {
    const hit = [...all.values()].filter((r) => (r.violations || []).some((v) => v.id === inv.id));
    assert.ok(hit.length > 0, `不变量 ${inv.id} 在全库没有任何命中者 ⇒ 判据空转或已失效`);
  }
  assert.equal(INVARIANTS.length, 2, '新增/删除不变量需同步更新本文件与文档口径');
});

test('审计覆盖全库：每个已注册插件都有审计结果，且不存在抛错插件', () => {
  const all = auditAll();
  assert.equal(all.size, tamperRegistry.all().length, '审计数应等于插件数');
  const errs = [...all.values()].filter((r) => r.error);
  assert.deepEqual(errs.map((r) => `${r.name}:${r.error}`), [], `插件 transform 抛错：${errs.length} 件`);
});

test('语义不可用名单规模合理（既不为空，也不至于把弹药库清空）', () => {
  const unsafe = semanticUnsafeRegistry();
  const total = tamperRegistry.all().length;
  assert.ok(unsafe.size >= 8, `命中数仅 ${unsafe.size} 件，疑似判据失效`);
  assert.ok(unsafe.size < total * 0.15, `命中 ${unsafe.size}/${total} 件，占比过高 ⇒ 判据过宽，会误杀`);
});
