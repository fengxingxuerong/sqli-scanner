#!/usr/bin/env node
// ============================================================================
// e2e/waf-real/probe-channel-profile.mjs —— A3 画像链路的 CRS 实测探针（诊断工具）
// ============================================================================
// 存在的理由（2026-09-25 新增，起因是一次差点漏掉的降级过激）：
//   A3 的通道降级只在 `chainVerify` 走**画像分支**时才可能生效，而进入该分支的前提是
//   「两条裸探针**全部**被拦」。这个前提成立与否、以及画像最终长什么样，
//   **完全取决于 WAF 规则集** —— 靠读代码推不出来，必须实测。
//   首版 `CHANNEL_TOKENS` 把 error 的必需记号写成 `[['quote']]`，而 CRS 实测
//   `quote` 被 942330 拦、重跑链 symboliclogical 又不消除它 → error 会被判死跳过。
//   error 是 CRS 场景下的主力通道（"error 命中但数据面全 miss" 正是 filterAdaptive
//   的触发前提），跳过它等于用请求预算换检出能力 —— 与本仓口径相悖。
//   本探针就是用来定期复现这个事实的：**改判据前先跑它**。
//
// 用法：node e2e/waf-real/probe-channel-profile.mjs
// 输出：裸探针拦截情况 + 逐词画像 + 该画像喂进 planChannels 后的通道决策。
// 口径：CRS 规则由本目录 `crs-engine.js` 执行（自实现规则执行器，非真 ModSecurity），
//       与全仓 WAF 数字同一口径。档位见输出的 `PL=`。
// ============================================================================
import { pathToFileURL, fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');

const { evaluate, EFFECTIVE_PL } = await import(pathToFileURL(resolve(HERE, 'crs-engine.js')).href);
const { planChannels } = await import(
  pathToFileURL(resolve(ROOT, 'server/src/core/waf/channelPolicy.js')).href
);
const { TOKEN_PROBES } = await import(
  pathToFileURL(resolve(ROOT, 'server/src/core/waf/blockProfile.js')).href
);

/** 构造一个最小请求对象（与 fromExpress 的输出同形，不经 express） */
const mk = (value) => ({
  method: 'GET',
  uri: `/item?id=${encodeURIComponent(value)}`,
  queryString: `id=${encodeURIComponent(value)}`,
  args: { id: value },
  cookies: {},
  headers: { host: 'local', 'user-agent': 'Mozilla/5.0' },
});

const ORIG = '1';
// chainVerify 的裸探针族（顺序与源码一致）
const RAW = [`${ORIG}' AND 1=1-- -`, `${ORIG}' AND '1'='1`];

console.log(`CRS 生效档位 PL=${EFFECTIVE_PL}`);

console.log('\n[1] 裸探针（chainVerify 要求**两条都被拦**才走画像分支）');
let allRawBlocked = true;
for (const v of RAW) {
  const r = evaluate(mk(v));
  if (!r.blocked) allRawBlocked = false;
  console.log(`  ${JSON.stringify(v)} → blocked=${r.blocked}${r.blocked ? ` rule=${r.ruleId}` : ''}`);
}
console.log(
  `  ⇒ allRawBlocked=${allRawBlocked}` +
    (allRawBlocked ? '（画像分支会进入）' : '（**早退**，画像为空数组 → A3 不生效）')
);

console.log('\n[2] 逐词画像（profileBlockedTokens 的实测量）');
const blocked = [];
for (const p of TOKEN_PROBES) {
  const v = p.value(ORIG);
  const r = evaluate(mk(v));
  if (r.blocked) blocked.push(p.id);
  console.log(
    `  ${p.id.padEnd(8)} ${JSON.stringify(v).padEnd(22)} → blocked=${r.blocked}${r.blocked ? ` rule=${r.ruleId}` : ''}`
  );
}
console.log(`  ⇒ blocked=[${blocked.join(',')}]`);

// symboliclogical = 拦截驱动重跑（blockAdaptive）实际使用的算子替换族，覆盖 and/or
console.log('\n[3] 该画像喂进 planChannels（链=symboliclogical，覆盖 and/or）');
const plan = planChannels({
  techniques: ['union', 'error', 'boolean'],
  blocked,
  covered: ['and', 'or'],
});
console.log(`  run     = [${plan.run.join(',')}]`);
console.log(`  skipped = [${plan.skipped.map((s) => `${s.technique}(${s.deadTokens.join('|')})`).join(', ')}]`);
console.log(
  `\n  判读要点：error 若出现在 skipped 里，说明降级过激 —— error 是 CRS 下的主力通道，\n` +
    `  跳过它会丢检出。改 CHANNEL_TOKENS 前先跑本脚本确认。`
);
