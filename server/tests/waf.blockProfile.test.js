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
