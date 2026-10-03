// waf.bypassSearcher.test.js —— 定向变异搜索器的机械验证
// ============================================================================
// 两条主线：
//   ① 元数据/映射表**不得腐烂**（双向守卫，对齐 ci-local 的 EXCLUDED_JOBS 做法）
//   ② 生成的链必须**真的能消除它声称消除的被拦词** —— 用插件自身 transform 实测，
//      不看 `covers` 这个自报字段（本仓铁律：不采信组件自报状态）
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
import { applyTampers } from '../src/core/tamper/applyTampers.js';
import { TOKEN_PROBES, TAMPER_COVERS, UNREGISTERED_COVER_NAMES } from '../src/core/waf/blockProfile.js';
import {
  PROBE_TOKEN_MAP,
  planChainsByProfile,
  mergeCandidateChains,
  isGeneratedChain,
  probeTokensToTokens,
} from '../src/core/waf/bypass/searcher.js';
import { buildSemanticIndex } from '../src/core/waf/bypass/semantics.js';

/** token → 保证含该 token 的最小样本 */
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
  '::': 'a::text',
};

test('映射表不得腐烂：PROBE_TOKEN_MAP 的 id 集合与 TOKEN_PROBES 双向一致', () => {
  const probeIds = TOKEN_PROBES.map((p) => p.id).sort();
  const mapIds = Object.keys(PROBE_TOKEN_MAP).sort();
  assert.deepEqual(mapIds, probeIds, '新增探针必须同步补 PROBE_TOKEN_MAP（否则新探针画像结果无法转成 token，选弹会漏）');
});

test('清单不得腐烂：TAMPER_COVERS 的未注册名必须与白名单**双向**相等', () => {
  const unregistered = Object.keys(TAMPER_COVERS).filter((n) => !tamperRegistry.get(n)).sort();
  const whitelisted = [...UNREGISTERED_COVER_NAMES].sort();
  assert.deepEqual(
    unregistered,
    whitelisted,
    '① 新增未注册插件名必须显式登记进 UNREGISTERED_COVER_NAMES；② 白名单里已注册的名应移出（白名单自身也会腐烂）',
  );
});

test('探针 id → token：映射正确，未知 id 静默忽略（不抛、不污染）', () => {
  assert.deepEqual(probeTokensToTokens(['and']), ['and']);
  assert.deepEqual(probeTokensToTokens(['quote']), ["'"]);
  const withUnknown = probeTokensToTokens(['and', 'not-a-probe']);
  assert.deepEqual(withUnknown, ['and']);
  assert.deepEqual(probeTokensToTokens([]), []);
});

test('空黑名单 → 不生成任何链，并给出 emptyReason（不盲试）', () => {
  const r = planChainsByProfile({ blockedTokens: [] });
  assert.equal(r.chains.length, 0);
  assert.ok(r.emptyReason && r.emptyReason.length > 0, '必须说明为何没有候选');
});

test('定向生成：拦 and/or 时候选含 symboliclogical，且兜底编码链排在其后', () => {
  const r = planChainsByProfile({ blockedTokens: ['and', 'or'], maxChains: 6 });
  assert.ok(r.chains.length > 0);
  const targeted = r.chains.filter((c) => !c.isCodec);
  assert.ok(
    targeted.some((c) => c.plugins.includes('symboliclogical')),
    'symboliclogical 声明 eliminates: [and, or]，必须在针对性候选里',
  );
  // 兜底弹药（整串编码）必须整体排在针对性候选之后
  const lastTargeted = r.chains.map((c) => c.isCodec).lastIndexOf(false);
  const firstCodec = r.chains.map((c) => c.isCodec).indexOf(true);
  if (firstCodec >= 0) {
    assert.ok(firstCodec > lastTargeted, '编码兜底链必须排在所有针对性候选之后');
    assert.equal(r.chains[r.chains.length - 1].isCodec, true, '末位应是兜底链');
  }
});

test('机械检验：非兜底链必须真的消除它声称消除的被拦词（用插件 transform 实测）', () => {
  const problems = [];
  let checked = 0;
  const cases = [
    { blocked: ['and', 'or'] },
    { blocked: ['quote'] },
    { blocked: ['cmp'] },
  ];
  for (const { blocked } of cases) {
    const r = planChainsByProfile({ blockedTokens: blocked, maxChains: 4 });
    for (const chain of r.chains) {
      if (chain.isCodec) continue; // 兜底链走"整串编码"，另测
      for (const token of chain.covers) {
        const sample = SAMPLES[token];
        if (sample === undefined) {
          problems.push(`token「${token}」缺样本映射 → 断言会空转，请补 SAMPLES`);
          continue;
        }
        const re = new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
        if (!re.test(sample)) {
          problems.push(`[样本自检] 样本「${sample}」不含 token「${token}」`);
          continue;
        }
        const out = applyTampers(sample, { config: {} }, chain.plugins);
        checked += 1;
        if (re.test(out)) {
          problems.push(
            `链 [${chain.plugins.join(',')}] 声称消除「${token}」，实测仍存在：${JSON.stringify(out)}`,
          );
        }
      }
    }
  }
  assert.deepEqual(problems, [], `有 ${problems.length} 条 covers 声明不成立：\n  - ${problems.join('\n  - ')}`);
  assert.ok(checked >= 3, `实际检验的链-词组合只有 ${checked} 个，疑似断言被跳过`);
});

test('机械检验：兜底编码链必须让明文被拦词消失（整串编码的承诺）', () => {
  const r = planChainsByProfile({ blockedTokens: ['and', 'or'], maxChains: 8 });
  const codecs = r.chains.filter((c) => c.isCodec);
  assert.ok(codecs.length > 0, '拦 and/or 时应有编码兜底链');
  for (const chain of codecs) {
    const out = applyTampers('1 AND 1=1', { config: {} }, chain.plugins);
    assert.ok(
      !/\band\b/i.test(out),
      `兜底链 [${chain.plugins.join(',')}] 输出仍含明文 AND：${JSON.stringify(out)}`,
    );
  }
});

test('生成的链必须逐条通过既有链守卫（terminal/dbms 语义不自建第二套判据）', () => {
  for (const blocked of [['and', 'or'], ['quote'], ['space', 'comment']]) {
    const r = planChainsByProfile({ blockedTokens: blocked, maxChains: 6 });
    for (const c of r.chains) {
      const v = tamperRegistry.validateChain(c.plugins, {});
      assert.deepEqual(
        v.plugins,
        c.plugins,
        `链 [${c.plugins.join(',')}] 被 validateChain 改写/截断，说明选弹放进了非法组合`,
      );
      for (const n of c.plugins) assert.ok(tamperRegistry.get(n), `${n} 未注册却进了候选链`);
    }
  }
});

test('排序不变量：针对性优先 → covers 多者优先 → 标点代价小者优先（同层内稳定）', () => {
  const r = planChainsByProfile({ blockedTokens: ['quote'], maxChains: 6 });
  const targeted = r.chains.filter((c) => !c.isCodec);
  for (let i = 1; i < targeted.length; i++) {
    const a = targeted[i - 1];
    const b = targeted[i];
    if (a.covers.length === b.covers.length) {
      assert.ok(a.punctDelta <= b.punctDelta, '同覆盖数下，标点代价小者应排前面（CRS 标点预算）');
    } else {
      assert.ok(a.covers.length >= b.covers.length, '覆盖被拦词多者应排前面');
    }
  }
});

test('mergeCandidateChains：静态链在前（保既有行为为首选）、去重、vendor 兜底', () => {
  const staticChains = [{ vendor: 'MyWAF', plugins: ['dash2hash'] }];
  const generated = [{ plugins: ['dash2hash'] }, { plugins: ['symboliclogical'] }];
  const merged = mergeCandidateChains(staticChains, generated);
  assert.equal(merged.length, 2, '重复链应去重');
  assert.equal(merged[0].vendor, 'MyWAF', '静态链必须保持首位（保守回退语义）');
  assert.equal(merged[0].plugins[0], 'dash2hash');
  assert.ok(isGeneratedChain(merged[1].vendor), '生成链的 vendor 应可被识别出来源');
  assert.ok(!isGeneratedChain(merged[0].vendor));
});

test('mergeCandidateChains：空输入安全（不抛、返回数组）', () => {
  assert.deepEqual(mergeCandidateChains(), []);
  assert.deepEqual(mergeCandidateChains(null, null), []);
  assert.deepEqual(mergeCandidateChains([], [null, { plugins: [] }]), []);
});

// ── [批次C 2026-10-03] 减标点补位 + 三链组合 ──────────────────────────────────
// 背景：covers=0 的 reducesPunct 插件（dash2hash）此前被 `.filter(covers > 0)` 挡在
// 候选池外 ⇒ CRS 标点预算方向（942460/942431）唯一实证有效项从生成器里消失，
// 实证首选链 dash2hash×hexliterals（wafRecommend OPERATOR_SWAP_CHAINS[0]/[3] 两种
// 顺序都在案）不可能被生成。以下用例钉住这两个维度，撤掉实现即红。

test('★减标点补位：拦 quote 时必须生成实证首选形态（dash2hash×hexliterals 两个顺序）', () => {
  const r = planChainsByProfile({ blockedTokens: ['quote'], maxChains: 12 });
  const shapes = r.chains.map((c) => c.plugins.join('+'));
  assert.ok(shapes.includes('hexliterals+dash2hash'), `缺 [hexliterals,dash2hash]：${shapes.join(' / ')}`);
  assert.ok(shapes.includes('dash2hash+hexliterals'), `缺 [dash2hash,hexliterals]（实证两序都在案）：${shapes.join(' / ')}`);
  // 覆盖声明不受补位影响：补位者只减标点，不抢 covers
  const pair = r.chains.find((c) => c.plugins.join('+') === 'hexliterals+dash2hash');
  assert.deepEqual(pair.covers, ["'"], '补位链的 covers 应来自消除者（quote）');
  assert.equal(pair.source, 'pair+punct');
});

test('减标点插件单独不占定向名额（covers=0 ⇒ 不产生单插件链，那是盲试）', () => {
  const r = planChainsByProfile({ blockedTokens: ['union'], maxChains: 20 });
  const solo = r.chains.find((c) => c.plugins.length === 1 && c.plugins[0] === 'dash2hash');
  assert.equal(solo, undefined, 'dash2hash 不消除任何被拦词，不得作为单插件候选');
});

test('★三链组合：三族同时被拦时能生成「消除者×2 + 减标点」的全覆盖链', () => {
  // quote + space + comment：hexliterals（LITERAL，quote）/ space2comment（WHITESPACE，space）
  // / dash2hash（标点）。'comment'（--）当前无消除者（dash2hash 被机械检验钉死为不消除
  // '--'），故 covers 应为 quote+space 两族 —— 这正是「双链覆盖不满、需要三链」的形态。
  const r = planChainsByProfile({ blockedTokens: ['quote', 'space', 'comment'], maxChains: 20 });
  const triples = r.chains.filter((c) => c.plugins.length === 3);
  assert.ok(triples.length > 0, `应有三链组合，实得：${r.chains.map((c) => c.plugins.join('+')).join(' / ')}`);
  const best = triples[0];
  assert.ok(best.covers.length >= 2, `三链组合覆盖数应 ≥2，实得 ${best.covers.join(',')}`);
  // 三链必须异类别（一个消除者一个类别，补位者第三类）
  const cats = best.plugins.map((p) => {
    const idx = buildSemanticIndex();
    return idx.get(p)?.category;
  });
  assert.equal(new Set(cats).size, 3, `三链应覆盖三个不同语义类别，实得 ${cats.join(',')}`);
});

test('★机械检验：补位链与三链声称的 covers 必须被整链真实消除（不采信自报）', () => {
  const cases = [
    { blocked: ['quote'], chain: 'hexliterals+dash2hash' },
    { blocked: ['quote'], chain: 'dash2hash+hexliterals' },
    { blocked: ['quote', 'space', 'comment'], anyTriple: true },
  ];
  let checked = 0;
  for (const { blocked, chain, anyTriple } of cases) {
    const r = planChainsByProfile({ blockedTokens: blocked, maxChains: 20 });
    const target = anyTriple
      ? r.chains.find((c) => c.plugins.length === 3)
      : r.chains.find((c) => c.plugins.join('+') === chain);
    assert.ok(target, `候选里找不到 ${chain || '三链'}：${r.chains.map((c) => c.plugins.join('+')).join(' / ')}`);
    for (const token of target.covers) {
      const sample = SAMPLES[token];
      assert.ok(sample !== undefined, `token「${token}」缺样本映射`);
      const re = new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      const out = applyTampers(sample, { config: {} }, target.plugins);
      assert.ok(!re.test(out), `链 [${target.plugins.join(',')}] 声称消除「${token}」，实测仍存在：${JSON.stringify(out)}`);
      checked += 1;
    }
  }
  assert.ok(checked >= 3, `实际检验的链-词组合只有 ${checked} 个，疑似断言被跳过`);
});
