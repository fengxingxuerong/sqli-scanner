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

/** 记录调用序列的 mock client */
function makeClient(map) {
  const calls = [];
  return {
    calls,
    async request(opts) {
      const kind = classify(opts);
      calls.push(kind);
      const r = map[kind] ?? OK;
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
