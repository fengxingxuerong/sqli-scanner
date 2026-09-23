#!/usr/bin/env node
// ============================================================================
// e2e/waf-real/waf-bypass-search.e2e.mjs —— A2「定向变异搜索」端到端验收
// ============================================================================
// 要回答的问题（一句话）：**引擎真的会去试「按被拦词组合出来的链」吗？**
//
// 为什么必须有这份 e2e（此前缺的就是它）：
//   单测 `server/tests/waf.bypassWiring.test.js` 已经断言「静态链全被拦时生成链能顶上」，
//   但它喂的是 **1 条**静态链 —— 而生产路径喂的是 `OPERATOR_SWAP_CHAINS`（**4 条**）。
//   `chainVerify` 只验前 `MAX_CHAINS=3` 条，而生成链被**追加在静态链之后**（保守回退的设计），
//   于是它永远落在第 5 位、一次也不会被发请求验证 —— 单测用 1 条静态链恰好绕开了这个盲区。
//   这正是本项目反复踩的形态：**测试场景与真实输入不符 → 绿灯照常**。
//
// 判据选择（关键，别选错）：
//   不看「最终采纳了哪条链」。采纳结果取决于 CRS 具体拦了什么，是**环境相关的巧合**；
//   A2 的验收判据应是「生成链有没有**进入验证流程**」——它有没有被真正发出去过一次请求。
//   故本脚本用 `onChainProbe` 回调收集被验证过的链，按 `generated` 标记分类计数。
//
// A/B 双向断言（自带反向对照，不需要改生产代码做缺陷注入）：
//   A 档 `bypassSearch=true`  → 被验证的链里**至少 1 条**是生成链
//   B 档 `bypassSearch=false` → 被验证的链里**0 条**是生成链（= 2026-09-21 的行为）
//   两档若都出现生成链 → 开关失效；两档都没有 → A2 仍未生效。任一情况都必须红。
//   另断言两档**验证总条数相同**：定向搜索不得偷偷增加请求预算。
//
// 诚实边界：
//   本脚本验的是「选链层」端到端（真 HTTP + 真 CRS v4.1.0 规则 + 真 tamper 变换）。
//   **不**验「绕过后的检出率」——那是 `waf-auto` / `waf-real` 套件的职责。
//   WAF 是自实现执行器（`crs-engine.js`，非真实 ModSecurity），与全仓 WAF 数字同一口径。
//
// 用法：node e2e/waf-real/waf-bypass-search.e2e.mjs
// 退出码：0 = 通过；1 = 断言失败；0 + [BLOCKED] = 环境不满足（未执行断言，由门禁判 BLOCKED）
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync } from 'node:fs';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');

const PORT = Number(process.env.BYPASS_SEARCH_LAB_PORT) || 8157;

let express;
try {
  express = require('express');
} catch (e) {
  console.log(`[BLOCKED] 缺少 express（${e.message}）—— 本套件未执行任何断言`);
  process.exit(0);
}

const { evaluate, fromExpress } = await import(pathToFileURL(resolve(HERE, './crs-engine.js')).href);
const { verifyTamperChains } = await import(
  pathToFileURL(resolve(ROOT, 'server/src/core/waf/chainVerify.js')).href
);
const { OPERATOR_SWAP_CHAINS } = await import(
  pathToFileURL(resolve(ROOT, 'server/src/core/waf/wafRecommend.js')).href
);
const { httpClient } = await import(
  pathToFileURL(resolve(ROOT, 'server/src/core/httpClient.js')).href
);

// ── 靶场：纯 HTTP 层（不需要 DB —— 本套件验的是选链，不是检出） ──
// 响应体固定长度：避免「响应变短」被误判成拦截（looksBlocked 的非 strict 分支）。
const PAGE = `<!DOCTYPE html><html><body><h1>item</h1><p>${'x'.repeat(400)}</p></body></html>`;
let WAF_HITS = 0;
const app = express();
app.use((req, res, next) => {
  const verdict = evaluate(fromExpress(req));
  if (verdict.blocked) {
    WAF_HITS++;
    res.status(403).send(`<!DOCTYPE html><html><body><p>blocked by CRS rule ${verdict.ruleId}</p></body></html>`);
    return;
  }
  next();
});
app.get('/item', (_req, res) => {
  res.status(200).type('html').send(PAGE);
});
const server = app.listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const BASE = `http://127.0.0.1:${PORT}`;

const target = { url: `${BASE}/item?id=1`, baseUrl: `${BASE}/item`, method: 'GET' };
const point = { id: 'p1', location: 'url', param: 'id', originalValue: '1' };

/**
 * 跑一档：返回被验证过的链（含 generated 标记）与最终采纳的链。
 * @param {boolean} bypassSearch
 */
async function runOnce(bypassSearch) {
  const probes = [];
  const picked = await verifyTamperChains({
    httpClient,
    target,
    point,
    // ⚠️ 必须喂**生产真实的 4 条**静态链（单测只喂 1 条，正是盲区来源）
    chains: OPERATOR_SWAP_CHAINS.map((c) => ({ vendor: 'generic-block', plugins: [...c] })),
    config: { wafEvasion: { bypassSearch } },
    timeoutMs: 8000,
    onChainProbe: (e) => probes.push(e),
  });
  return { probes, picked };
}

// 敏感分支判据：裸探针被拦是后续画像/选链的**前提**。没进这个分支 = 本套件没验到东西，
// 绝不能报成通过（也不能报成失败 —— 那是 WAF 口径变了，不是产品缺陷）。
async function wafSensitive() {
  const send = async (v) => {
    try {
      return await httpClient.request({
        url: `${BASE}/item?id=${encodeURIComponent(v)}`,
        method: 'GET',
        timeoutMs: 8000,
        retry: 0,
      });
    } catch {
      return null;
    }
  };
  const base = await send('1');
  if (!base || base.status !== 200) return { ok: false, why: `基线请求不可用（status=${base?.status}）` };
  const raw = await send("1' AND 1=1-- -");
  const blocked = !raw || raw.status === 403 || /blocked by/i.test(String(raw.data ?? ''));
  return { ok: blocked, why: blocked ? '' : `裸探针未被拦（status=${raw?.status}）—— CRS 未生效，本套件未验到 A2` };
}

const facts = { wafHits: 0, generatedProbed: 0, offGeneratedProbed: 0, probeCounts: {}, pickedOn: null, pickedOff: null };
let blockedReason = '';
try {
  const sens = await wafSensitive();
  if (!sens.ok) {
    blockedReason = sens.why;
  } else {
    const on = await runOnce(true);
    const off = await runOnce(false);
    facts.generatedProbed = on.probes.filter((p) => p.generated).length;
    facts.offGeneratedProbed = off.probes.filter((p) => p.generated).length;
    facts.probeCounts = { on: on.probes.length, off: off.probes.length };
    facts.pickedOn = on.picked ? on.picked.plugins.join('+') : null;
    facts.pickedOff = off.picked ? off.picked.plugins.join('+') : null;
  }
} catch (e) {
  blockedReason = `执行异常：${e.message}`;
} finally {
  facts.wafHits = WAF_HITS;
  server.close();
}

if (blockedReason) {
  console.log(`[BLOCKED] ${blockedReason}`);
  console.log('[bypass-search] 本套件未执行任何断言（环境/前提不满足，不得计为通过）');
  mkdirSync(resolve(HERE, 'results'), { recursive: true });
  writeFileSync(
    resolve(HERE, 'results', 'waf-bypass-search.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), blocked: blockedReason, ...facts }, null, 2)
  );
  process.exit(0);
}

const checks = [
  { name: 'A 档至少验证到 1 条生成链', ok: facts.generatedProbed >= 1, got: facts.generatedProbed },
  { name: 'B 档（关闭）不得出现生成链', ok: facts.offGeneratedProbed === 0, got: facts.offGeneratedProbed },
  {
    name: '两档验证总条数相同（预算纪律）',
    ok: facts.probeCounts.on === facts.probeCounts.off,
    got: `on=${facts.probeCounts.on} off=${facts.probeCounts.off}`,
  },
];
const failed = checks.filter((c) => !c.ok);

console.log(
  `[bypass-search] 生成链验证 A档=${facts.generatedProbed} 条 / B档=${facts.offGeneratedProbed} 条` +
    `　验证总数 on=${facts.probeCounts.on} off=${facts.probeCounts.off}` +
    `　采纳链 on=${facts.pickedOn || '-'} off=${facts.pickedOff || '-'}　WAF 拦截 ${facts.wafHits} 次`
);
for (const c of checks) console.log(`  ${c.ok ? '✅' : '❌'} ${c.name}（实测 ${c.got}）`);

mkdirSync(resolve(HERE, 'results'), { recursive: true });
writeFileSync(
  resolve(HERE, 'results', 'waf-bypass-search.json'),
  JSON.stringify({ generatedAt: new Date().toISOString(), ...facts, checks }, null, 2)
);
console.log(`[bypass-search] 结论：${failed.length ? `❌ ${failed.map((f) => f.name).join('；')}` : '✅ A2 定向变异在真实验链流程中生效'}`);
process.exit(failed.length ? 1 : 0);
