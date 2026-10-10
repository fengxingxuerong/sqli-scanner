// ============================================================================
// waf.blockProfile.test.js —— 逐词拦截画像 + 定向选链
// ============================================================================
// 这一层的价值不在"能发请求"，而在**选链不再盲选**：
//   原先 `chainVerify` 对候选链做 `list.slice(0, MAX_CHAINS)` 按序截断 —— 3 个名额有可能
//   全花在「消除 `--` 的链」上，而目标实际拦的是 `union`。
// 因此本文件重点钉三件事：① 排序确实按"能消除被拦词"；② 排序稳定且不改入参；
// ③ 画像用 **strict** 判据（体缩水不算"被拦"，否则缩水型目标会让画像整体失真）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  looksBlocked,
  coveredTokens,
  rankChainsByProfile,
  profileBlockedTokens,
  blockedPatternOf,
  TOKEN_PROBES,
} from '../src/core/waf/blockProfile.js';

const target = { url: 'http://mock.test/?id=1', baseUrl: 'http://mock.test/?id=1', method: 'GET' };
const point = { id: 'p1', location: 'url', param: 'id', originalValue: '1' };
const OK = () => ({ status: 200, data: 'ok page ' + 'x'.repeat(300) });
const BLOCKED = () => ({ status: 403, data: 'blocked' });
const SHRUNK = () => ({ status: 200, data: 'x' });

/** 按**调用顺序**返回预设响应的 mock（profileBlockedTokens 是串行发探针的） */
function seqClient(list) {
  let i = 0;
  return {
    async request() {
      const r = list[Math.min(i++, list.length - 1)];
      if (typeof r === 'function') return r();
      if (r instanceof Error) throw r;
      return r;
    },
  };
}

// ── looksBlocked 口径 ─────────────────────────────────────────────────────

test('looksBlocked：状态码/请求失败=被拦；strict 下体缩水不算被拦', () => {
  assert.equal(looksBlocked(null, 300), true, '请求失败按被拦（保守）');
  assert.equal(looksBlocked({ status: 403, data: '' }, 300), true);
  assert.equal(looksBlocked(SHRUNK(), 300), true, '非 strict：体缩水算敏感');
  assert.equal(looksBlocked(SHRUNK(), 300, { strict: true }), false, 'strict：体缩水不算被拦');
  assert.equal(looksBlocked({ status: 200, data: 'blocked by WAF' }, 300, { strict: true }), true);
  assert.equal(looksBlocked(OK(), 300), false);
});

// ── TAMPER_COVERS / coveredTokens ─────────────────────────────────────────

test('coveredTokens：多插件取并集；未声明的插件不贡献 token', () => {
  assert.deepEqual([...coveredTokens(['symboliclogical'])].sort(), ['and', 'or']);
  const both = coveredTokens(['symboliclogical', 'space2comment']);
  assert.ok(both.has('and') && both.has('space'));
  assert.equal(coveredTokens(['不存在的插件']).size, 0);
  assert.equal(coveredTokens([]).size, 0);
});

// ── rankChainsByProfile（纯函数，本轮核心）────────────────────────────────

test('★定向选链：能消除被拦词的链排到前面（替代按序截断）', () => {
  const chains = [
    { vendor: 'v1', plugins: ['equaltolike'] }, // 不消除任何被拦 token
    { vendor: 'v2', plugins: ['charencode'] }, // 消除 quote/space/paren/comma/cmp
  ];
  // 目标被拦的是 UNION → charencode 的声明里没有 union
  assert.deepEqual(rankChainsByProfile(chains, ['union']).map((c) => c.vendor), ['v1', 'v2'], '无人命中 → 保持原序');
  // 目标被拦的是 quote → charencode 命中
  assert.deepEqual(rankChainsByProfile(chains, ['quote']).map((c) => c.vendor), ['v2', 'v1']);
  // 命中数多者优先
  assert.deepEqual(rankChainsByProfile(chains, ['quote', 'space']).map((c) => c.vendor), ['v2', 'v1']);
});

test('rankChainsByProfile：空画像 → 原序；同分稳定；不改入参', () => {
  const chains = [
    { vendor: 'a', plugins: ['symboliclogical'] },
    { vendor: 'b', plugins: ['logical_operators'] }, // 与 a 消除同一组 token → 同分
    { vendor: 'c', plugins: ['equaltolike'] },
  ];
  const snapshot = JSON.stringify(chains);
  assert.deepEqual(rankChainsByProfile(chains, []).map((c) => c.vendor), ['a', 'b', 'c']);
  assert.deepEqual(rankChainsByProfile(chains, null).map((c) => c.vendor), ['a', 'b', 'c']);
  const ranked = rankChainsByProfile(chains, ['and']);
  assert.deepEqual(ranked.map((c) => c.vendor), ['a', 'b', 'c'], 'a/b 同分应保持原序（稳定排序）');
  assert.notEqual(ranked, chains, '应返回新数组');
  assert.equal(JSON.stringify(chains), snapshot, '不得修改入参');
});

test('rankChainsByProfile：过滤掉空链/非法项', () => {
  const chains = [{ plugins: [] }, null, { plugins: ['charencode'] }, { vendor: 'x' }];
  const out = rankChainsByProfile(chains, ['quote']);
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].plugins, ['charencode']);
});

// ── profileBlockedTokens ──────────────────────────────────────────────────

test('逐词画像：仅被硬拦的 token 进黑名单', async () => {
  // 第 3 个探针（comment）被 403，其余放行
  const client = seqClient(TOKEN_PROBES.map((_, i) => (i === 1 ? BLOCKED : OK)));
  const r = await profileBlockedTokens({ httpClient: client, target, point, baseLen: 300 });
  assert.equal(r.probed, TOKEN_PROBES.length);
  assert.deepEqual(r.blocked, [TOKEN_PROBES[1].id]);
});

test('★画像用 strict 判据：体缩水不算"被拦"（否则缩水型目标会让画像整体失真）', async () => {
  const client = seqClient([SHRUNK]); // 所有探针都"缩水"
  const r = await profileBlockedTokens({ httpClient: client, target, point, baseLen: 300 });
  assert.deepEqual(r.blocked, [], '体缩水不是"WAF 拦了某个词"，不应污染画像');
  assert.equal(r.probed, TOKEN_PROBES.length);
});

test('画像：探针请求抛错按被拦处理（保守）', async () => {
  const client = seqClient([new Error('ECONNRESET')]);
  const r = await profileBlockedTokens({ httpClient: client, target, point, baseLen: 300 });
  assert.equal(r.blocked.length, TOKEN_PROBES.length, '全部失败 → 全部记为被拦');
});

test('画像：maxProbes 预算封顶生效（不无限发探针）', async () => {
  let count = 0;
  const client = { async request() { count++; return OK(); } };
  const r = await profileBlockedTokens({ httpClient: client, target, point, baseLen: 300, maxProbes: 4 });
  assert.equal(r.probed, 4);
  assert.equal(count, 4, `实际发出 ${count} 个请求，应被预算封顶在 4`);
});

test('画像：缺 httpClient/target/point 时返回空并给 error（不抛）', async () => {
  const r = await profileBlockedTokens({ httpClient: null, target, point });
  assert.equal(r.probed, 0);
  assert.ok(r.error);
  assert.deepEqual(r.blocked, []);
});

// ── D38：关键词级黑名单下的对症排序（waf403 真回归）─────────────────────────
// 真机归因（e2e/pentest-lab 的 waf403，`must:['boolean']` 确定性红三轮）：
//   · 画像 [comment, and, or, union, select, sleep] —— 关键词占多数 ⇒ keyword-blacklist；
//   · 改前排序：`chardoubleencode`（D19 补的 COVERS 全覆盖 ⇒ hit 5）稳居第 0，
//     它是第一条被验证、也第一条放行的链 ⇒ 被选中重跑 ⇒ 双编码落库是碎片 ⇒ 只有 error；
//   · 唯一能拿到 boolean 的是 `symboliclogical`（AND→&& / OR→||，语义等价，真机 842ms），
//     但它 hit 2、`unionvaluesrow+dash2hash` 靠顺带覆盖 comment 拿到 hit 3 ⇒ 排在第 3，
//     而 slots=2 ⇒ **结构性进不了验证名单**。
// 三处配合才成立：① 关键词模式只数关键字；② 整串编码链的关键字覆盖不计分；③ 同分对症优先。
const KW_BLOCKED = ['comment', 'and', 'or', 'union', 'select', 'sleep'];
const REAL_POOL = () => [
  { vendor: 'generic_block', plugins: ['unionvaluesrow', 'dash2hash'] },
  { vendor: 'generic_block', plugins: ['unionvaluesrow', 'dash2hash', 'hexliterals'] },
  { vendor: 'encoding_fallback', plugins: ['chardoubleencode'] },
  { vendor: 'generic_block', plugins: ['dash2hash', 'hexliterals'] },
  { vendor: 'generic_block', plugins: ['dash2hash'] },
  { vendor: 'generic_block', plugins: ['symboliclogical'] },
  { vendor: 'generic_block', plugins: ['hexliterals', 'dash2hash'] },
];

test('D38 拦截模式判定：关键字占多数才算 keyword-blacklist（拿不准返回 null，不做加权）', () => {
  assert.equal(blockedPatternOf(KW_BLOCKED), 'keyword-blacklist');
  assert.equal(blockedPatternOf(['comment', 'hash', 'space', 'and']), null, '标点为主 ⇒ 不判定');
  assert.equal(blockedPatternOf([]), null);
  assert.equal(blockedPatternOf(null), null);
});

test('★ D38：关键词黑名单下，语义等价的 symboliclogical 必须排到能被验证的位置', () => {
  const names = rankChainsByProfile(REAL_POOL(), KW_BLOCKED).map((c) => c.plugins.join('+'));
  assert.equal(names[0], 'symboliclogical', `第 1 条应是对症的算子替换链：${names}`);
  // 它必须在前 slots（= 2）内，否则 chainVerify 根本不会验证它（waf403 就拿不到 boolean）
  assert.ok(
    names.slice(0, 2).includes('symboliclogical'),
    `symboliclogical 掉出前 2 ⇒ 进不了验证名单：${names}`,
  );
});

test('D38：整串编码链的关键字覆盖在关键词模式下不计分（不再稳居第 0）', () => {
  const names = rankChainsByProfile(REAL_POOL(), KW_BLOCKED).map((c) => c.plugins.join('+'));
  assert.ok(
    names.indexOf('chardoubleencode') > names.indexOf('symboliclogical'),
    `编码链靠"全覆盖"压过语义等价链 ⇒ waf403 会选中过得了 WAF 却语义破碎的链：${names}`,
  );
});

test('D38 反向钉子：非关键词模式（标点/注释为主）行为与改动前一致', () => {
  // 改动只在 pattern === 'keyword-blacklist' 时生效：那时 scored 仍是完整 set、fit 恒 0
  // ⇒ 排序与改动前**逐字等价**。标点模式下覆盖最广的仍是整串编码链（quote/space）⇒ 它排第 1，
  // 这正是改动前的既有行为（不能因为"编码链在关键词模式下被折价"就顺手改掉这里）。
  const punctBlocked = ['comment', 'hash', 'space', 'quote'];
  const names = rankChainsByProfile(REAL_POOL(), punctBlocked).map((c) => c.plugins.join('+'));
  assert.equal(names[0], 'chardoubleencode', `标点模式下排序必须与改动前一致：${names}`);
  assert.equal(blockedPatternOf(punctBlocked), null, '标点为主 ⇒ 不进入关键词模式');
});
