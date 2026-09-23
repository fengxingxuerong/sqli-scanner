// waf.bypassWiring.test.js —— T1/T2 接线到 chainVerify 的行为验证
// ============================================================================
// 两条主线：
//   ① **保守回退**：静态推荐链必须整体保持在生成链之前 —— 新逻辑无效时，
//      前 MAX_CHAINS 条与改造前完全一致（这是接线敢上的前提）。
//   ② **真的有用**：静态链全被拦时，定向生成的链必须能顶上并被采纳。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyTamperChains } from '../src/core/waf/chainVerify.js';
import { buildCandidateChains, planChainsByProfile } from '../src/core/waf/bypass/searcher.js';
import { TOKEN_PROBES } from '../src/core/waf/blockProfile.js';

const target = { url: 'http://mock.test/?id=1', baseUrl: 'http://mock.test/?id=1', method: 'GET' };
const point = { id: 'p1', location: 'url', param: 'id', originalValue: '1' };

const OK = () => ({ status: 200, data: 'ok page ' + 'x'.repeat(200) });
const BLOCKED = () => ({ status: 403, data: 'blocked' });

/** 请求分类：按 payload 形态区分（沿用 waf.chainVerify.test.js 的 mock 约定） */
function classify(opts) {
  const url = String(opts.url || '');
  const dec = decodeURIComponent(url).replace(/\+/g, ' ');
  if (/&&|%26%26/.test(dec)) return 'gen-and';       // symboliclogical 形态
  if (dec.includes('LIKE')) return 'static';          // equaltolike 形态
  if (dec.includes('AND 1=1') || dec.includes("AND '1'='1")) return 'raw';
  if (/\bOR\b/i.test(dec)) return 'tok-or';
  if (/\bAND\b/i.test(dec)) return 'tok-and';
  return 'baseline';
}

/** 记录调用序列的 mock client（fallback 默认放行，可显式改成"其余一律被拦"） */
function makeClient(map, fallback = OK) {
  const calls = [];
  return {
    calls,
    async request(opts) {
      const kind = classify(opts);
      calls.push(kind);
      const r = map[kind] ?? fallback;
      return typeof r === 'function' ? r() : r;
    },
  };
}

// —— 纯函数层：buildCandidateChains ——

test('无画像（目标不敏感 / 未画像）→ 原样返回静态链，与改造前逐字一致', () => {
  const chains = [
    { vendor: 'cloudflare', plugins: ['equaltolike'] },
    { vendor: 'cloudflare', plugins: ['charencode'] },
  ];
  const out = buildCandidateChains(chains, []);
  assert.deepEqual(out, chains, '无被拦词时不得改变候选池（含顺序）');
  assert.equal(buildCandidateChains(chains, null).length, 2);
});

test('有画像 → 静态链整体保持在生成链之前（保守回退的核心不变量）', () => {
  const chains = [{ vendor: 'cloudflare', plugins: ['equaltolike'] }];
  const out = buildCandidateChains(chains, ['and', 'or'], { maxGenerated: 3 });
  assert.ok(out.length > 1, '应追加了生成链');
  assert.deepEqual(out[0], chains[0], '静态链必须仍是首位');
  // 生成链里应含 symboliclogical（声明 eliminates: and/or）
  const generated = out.slice(1);
  assert.ok(
    generated.some((c) => c.plugins.includes('symboliclogical')),
    `生成链应含 symboliclogical，实际：${JSON.stringify(generated.map((c) => c.plugins))}`,
  );
});

test('生成链数量受 maxGenerated 约束（不无限膨胀候选池）', () => {
  const chains = [{ vendor: 'cf', plugins: ['equaltolike'] }];
  const out = buildCandidateChains(chains, ['and', 'or'], { maxGenerated: 2 });
  const genCount = out.length - 1; // 去掉静态链
  assert.ok(genCount <= 2, `生成链 ${genCount} 条超过 maxGenerated=2`);
});

test('dbms 参数透传：指定 MySQL 时不会选出明显不适用于该库的组合', () => {
  const chains = [{ vendor: 'cf', plugins: ['equaltolike'] }];
  const out = buildCandidateChains(chains, ['and', 'or'], { dbms: 'MySQL' });
  // 至少不该抛错，且每条链的插件都已注册（由 mergeCandidateChains 内部的 validateChain 保证）
  for (const c of out) assert.ok(Array.isArray(c.plugins) && c.plugins.length);
});

// [2026-09-23] 下面这条是**上一条的补丁**，起因是一次真实的假绿：
// 上一条喂的是 1 条静态链，而生产路径喂 `OPERATOR_SWAP_CHAINS`（4 条）。
// `chainVerify` 只验前 MAX_CHAINS=3 条，生成链被追加在静态链之后 → 落在第 5 位、
// **一次也不会被验证**；1 条静态链的场景恰好让生成链排在第 2 位，盲区被完全绕开。
// 教训（本仓第二次同类）：**单测的输入规模必须等于生产输入规模**，否则"生成链能顶上"
// 这种断言在真实调用里可能永远不成立。
test('生产真实输入（4 条静态链）下，生成链也必须拿到验证名额', async () => {
  const { OPERATOR_SWAP_CHAINS } = await import('../src/core/waf/wafRecommend.js');
  assert.ok(
    OPERATOR_SWAP_CHAINS.length > 3,
    `本用例的前提是静态链多于 MAX_CHAINS(3)；当前 ${OPERATOR_SWAP_CHAINS.length} 条。` +
      '若哪天减到 3 条以内，本用例的盲区前提消失，请改写它而不是删掉。',
  );

  // 全部非基线请求一律被拦：裸探针被拦（进入画像分支）→ 所有词被拦（生成链有弹药）
  // → 所有链验证也失败（返回 null），但**被验证过**这件事由回调记录下来，正是判据所在。
  const client = makeClient({ baseline: OK }, BLOCKED);
  const probes = [];
  const picked = await verifyTamperChains({
    httpClient: client,
    target,
    point,
    chains: OPERATOR_SWAP_CHAINS.map((c) => ({ vendor: 'generic-block', plugins: [...c] })),
    config: { wafEvasion: { bypassSearch: true } },
    onChainProbe: (e) => probes.push(e),
  });

  // ⚠️ 不断言 picked === null：classify() 只按明文形态分类，而生成链（如编码族）变换后的
  // 请求在它眼里就是 'baseline'（放行）。**采纳了生成链同样是"生成链被验证过"的证据** ——
  // 硬钉 null 会把这条好不容易暴露出来的成功路径判成失败（把判据钉在环境巧合上 = 脆弱断言）。
  // 采纳的链必须是**真被验证过**的链（不允许凭空返回一条没发过请求的链）
  if (picked) {
    assert.ok(
      probes.some((p) => p.plugins.join('+') === picked.plugins.join('+')),
      `采纳的链 ${picked.plugins.join('+')} 不在被验证过的集合里`,
    );
  }
  const generated = probes.filter((p) => p.generated);
  assert.ok(
    generated.length >= 1,
    `4 条静态链占满前 3 个名额时，生成链仍应至少被验证 1 次；实际被验证的链：` +
      `${JSON.stringify(probes.map((p) => ({ plugins: p.plugins, generated: p.generated })))}`,
  );
  // 预算纪律：开启定向搜索不得增加验证条数（仍是 MAX_CHAINS 条链 × 探针数）
  const chainsTried = new Set(probes.map((p) => p.plugins.join('+')));
  assert.ok(chainsTried.size <= 3, `验证链条数 ${chainsTried.size} 超过 MAX_CHAINS=3`);
});

test('关闭开关（bypassSearch=false）→ 生成链不进池（回归到 2026-09-21 行为）', async () => {
  const { OPERATOR_SWAP_CHAINS } = await import('../src/core/waf/wafRecommend.js');
  const client = makeClient({ baseline: OK }, BLOCKED);
  const probes = [];
  await verifyTamperChains({
    httpClient: client,
    target,
    point,
    chains: OPERATOR_SWAP_CHAINS.map((c) => ({ vendor: 'generic-block', plugins: [...c] })),
    config: { wafEvasion: { bypassSearch: false } },
    onChainProbe: (e) => probes.push(e),
  });
  assert.equal(
    probes.filter((p) => p.generated).length,
    0,
    `关闭档不得出现生成链，实际：${JSON.stringify(probes.filter((p) => p.generated).map((p) => p.plugins))}`,
  );
  assert.ok(probes.length > 0, '关闭档仍应验证静态链（不能变成什么都不做）');
});

// —— 集成层：verifyTamperChains 真的会用上生成链 ——

test('接线生效：静态链全被拦时，定向生成的链能顶上并被采纳', async () => {
  // 场景：裸探针全被拦（触发画像）→ 画像只拦 and/or → 静态链 equaltolike 也被拦
  //       → 生成链 symboliclogical（含 &&）放行 → 应被采纳
  const client = makeClient({
    baseline: OK,
    raw: BLOCKED,      // 两条裸探针都被拦
    'tok-and': BLOCKED, // and 被拦
    'tok-or': BLOCKED,  // or 被拦
    static: BLOCKED,    // 静态链被拦
    'gen-and': OK,      // 生成链放行
  });

  const picked = await verifyTamperChains({
    httpClient: client,
    target,
    point,
    chains: [{ vendor: 'cloudflare', plugins: ['equaltolike'] }],
    config: {},
  });

  assert.ok(picked, '应当选出一条链（生成链应顶上）');
  assert.ok(
    picked.plugins.includes('symboliclogical'),
    `应采纳定向生成的 symboliclogical，实际：${JSON.stringify(picked.plugins)}`,
  );
  assert.ok(
    String(picked.vendor || '').startsWith('bypass:'),
    `生成链的 vendor 应带 bypass: 标记（便于报告里区分来源），实际：${picked.vendor}`,
  );
});

test('保守回退：静态链先被验证，生成链只在之后（顺序不颠倒）', async () => {
  const client = makeClient({
    baseline: OK,
    raw: BLOCKED,
    'tok-and': BLOCKED,
    'tok-or': BLOCKED,
    static: OK,        // 静态链这次能过 → 应直接采纳，不该再试生成链
    'gen-and': OK,
  });

  const picked = await verifyTamperChains({
    httpClient: client,
    target,
    point,
    chains: [{ vendor: 'cloudflare', plugins: ['equaltolike'] }],
    config: {},
  });

  assert.ok(picked);
  assert.deepEqual(picked.plugins, ['equaltolike'], '静态链能过时应直接采纳它');
  assert.equal(
    client.calls.filter((c) => c === 'gen-and').length,
    0,
    '静态链已通过就不该再花请求验证生成链',
  );
});

test('画像结果与探针 id 对齐：TOKEN_PROBES 的 id 可直接喂给 planChainsByProfile', () => {
  const ids = TOKEN_PROBES.map((p) => p.id);
  const r = planChainsByProfile({ blockedTokens: ids, maxChains: 3 });
  // 全拦的极端场景：至少不应抛错；有候选则每条的插件都已注册
  for (const c of r.chains) assert.ok(c.plugins.length > 0);
  assert.ok(Array.isArray(r.blocked) && r.blocked.length > 0);
});
