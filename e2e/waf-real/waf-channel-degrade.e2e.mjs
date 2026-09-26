#!/usr/bin/env node
// ============================================================================
// e2e/waf-real/waf-channel-degrade.e2e.mjs —— A3「通道降级编排」端到端验收
// ============================================================================
// 要回答的问题（一句话）：**真实 HTTP 请求测出来的拦截画像，能不能正确驱动通道降级？**
//
// 为什么单测不够（必须补这份 e2e）：
//   `server/tests/waf.channelPolicy.test.js` 里的画像是 **mock 出来的**（直接返回
//   `{status:200/403}`）。它证明的是「决策逻辑对」，证明不了「画像对」——
//   而画像错了，决策再对也是对着错误事实做正确推理。画像要真发 12 个探针、
//   真走 URL 编码、真被 WAF 拦，才能算验过（本仓口径：安全能力结论必须来自真实链路）。
//
// 判据选择（关键）：
//   不看「最终少发了多少请求」（那是优化指标，且受并发/早停影响），
//   看 **画像是否与靶场 ground truth 一致** + **决策是否随之正确**。
//   靶场的拦截规则是**我自己写死的**，所以「哪些词被拦」有唯一正确答案 —— 这就是 ground truth。
//
// 两个靶场（双向对照，覆盖降级与不降级两种语义）：
//   靶场①「双拦」：拦 union + select + and + or  → union 与 boolean 都应降级，只剩 error
//   靶场②「单拦」：拦 union + and + or，放行 select → union **不得**降级（OR 组语义：
//      必需组内只拦一个不代表通道死）。这条是防「降级过激」的反向对照。
//
// 诚实边界：
//   · 本套件**不验检出率**（不回答「降级后是不是真的没漏检」）—— 那是 acceptance 的
//     CRS 套件（技术位 ≥8）的职责，两者互为补充而非替代。
//   · WAF 是**自建规则**而非 CRS：本套件需要「拦哪些词」完全可控的 ground truth，
//     CRS 的规则集无法精确指定「只拦 union 不拦 select」。故与 A2 套件（用 crs-engine）
//     分工不同，数字不可直接横向比较。
//
// 用法：node e2e/waf-real/waf-channel-degrade.e2e.mjs
// 退出码：0 = 通过；1 = 断言失败；0 + [BLOCKED] = 环境不满足（未执行断言，由门禁判 BLOCKED）
// ============================================================================
import { pathToFileURL, fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync } from 'node:fs';

const require = createRequire(new URL('../../server/package.json', import.meta.url));
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '../..');

const PORT_DUAL = Number(process.env.CHANNEL_DEGRADE_PORT_DUAL) || 8158;
const PORT_SINGLE = Number(process.env.CHANNEL_DEGRADE_PORT_SINGLE) || 8159;

let express;
try {
  express = require('express');
} catch (e) {
  console.log(`[BLOCKED] 缺少 express（${e.message}）—— 本套件未执行任何断言`);
  process.exit(0);
}

const { verifyTamperChains } = await import(
  pathToFileURL(resolve(ROOT, 'server/src/core/waf/chainVerify.js')).href
);
const { planChannels } = await import(
  pathToFileURL(resolve(ROOT, 'server/src/core/waf/channelPolicy.js')).href
);
const { coveredTokens, TOKEN_PROBES } = await import(
  pathToFileURL(resolve(ROOT, 'server/src/core/waf/blockProfile.js')).href
);
const { httpClient } = await import(
  pathToFileURL(resolve(ROOT, 'server/src/core/httpClient.js')).href
);

// ── 靶场：纯 HTTP 层（不需要 DB —— 本套件验的是画像与决策，不是检出）──
// 响应体固定长度：避免「响应变短」被误判成拦截（looksBlocked 的非 strict 分支）。
const PAGE = `<!DOCTYPE html><html><body><h1>item</h1><p>${'x'.repeat(400)}</p></body></html>`;

/**
 * 建一个「按词拦截」的靶场。
 * @param {number} port
 * @param {string[]} blockedWords 命中其中任一词（解码后、大小写不敏感）即 403
 * @param {{hits: number}} counter 拦截计数（引用传入，跨靶场累计）
 */
function makeLab(port, blockedWords, counter) {
  const app = express();
  app.use((req, res, next) => {
    // ⚠️ 折叠 `+`（表单式空格）后再解码 —— 与真实 WAF 一致，也与本仓 CRS 执行器同口径
    // （e2e/waf-real/crs-engine.js 的 t:urlDecodeUni 同样先 `\+`→空格）。
    // 不折叠会静默废掉整套件：httpClient/axios 把空格编成 `+`，于是线上形态是
    // `id=1%27+AND+1%3D1--+-`，只 percent-decode 的靶场看不到 `' and '` 这个**带空格**的
    // 黑名单词 → 裸探针全放行 → verifyTamperChains 走「目标不敏感」早退分支
    // → 画像为空（blocked=[]、probed=0）→ 本套件的画像断言全部无事实可断。
    // 2026-09-25 首次真实执行时实测到这一步（探针逐个打状态码定位）。
    const dec = decodeURIComponent(String(req.originalUrl || '').replace(/\+/g, ' ')).toLowerCase();
    if (blockedWords.some((w) => dec.includes(w))) {
      counter.hits++;
      res.status(403).send('<!DOCTYPE html><html><body><p>request blocked by lab waf</p></body></html>');
      return;
    }
    next();
  });
  app.get('/item', (_req, res) => {
    res.status(200).type('html').send(PAGE);
  });
  const server = app.listen(port, '127.0.0.1');
  return { server, base: `http://127.0.0.1:${port}` };
}

const counter = { hits: 0 };
// ⚠️ 裸探针 `' AND 1=1-- -` / `' AND '1'='1` 必须被拦 —— 否则 chainVerify 在
// 「目标不敏感」分支就早退了，根本不会画像（那必须报 BLOCKED，不能算通过）。
const dual = makeLab(PORT_DUAL, ['union', 'select', ' and ', ' or '], counter);
const single = makeLab(PORT_SINGLE, ['union', ' and ', ' or '], counter);
// 等两个靶场就绪：必须**一次 await 等全部**，不是两条 await。
//   两条 await 是本套件 2026-09-25 之前的写法，它会在等第二个时永久挂死：两个 listen 几乎
//   同时完成，`listening` 事件在 `await dual` 期间就发完了，之后才给 single 挂 once() →
//   事件不重放 → 永不 resolve。整套件表现为「零输出直到超时」（它第一行正常输出在第 164 行），
//   因此此前 CI 只看到「取不到画像/决策行」。A3 接线后首次真实执行才暴露这里。
let labErr = '';
await Promise.all(
  [dual, single].map(
    (lab) =>
      new Promise((resolve, reject) => {
        lab.server.once('listening', resolve);
        lab.server.once('error', (e) => reject(new Error(`${lab.base} 未就绪：${e.code ?? e.message}`)));
      })
  )
).catch((e) => {
  labErr = e.message;
});
if (labErr) {
  console.log(
    `[BLOCKED] 靶场未就绪（${labErr}）—— 本套件未执行任何断言` +
      `（端口 ${PORT_DUAL}/${PORT_SINGLE} 疑被占，可用 CHANNEL_DEGRADE_PORT_DUAL/SINGLE 换端口）`
  );
  process.exit(0);
}

/** 跑一档：真发请求做验链（内部会真做逐词画像），再把画像喂给 planChannels */
async function runOnce(base, plugins) {
  const point = { id: 'p1', location: 'url', param: 'id', originalValue: '1' };
  const picked = await verifyTamperChains({
    httpClient,
    target: { url: `${base}/item?id=1`, baseUrl: `${base}/item`, method: 'GET' },
    point,
    // 必须喂**非空**候选链，否则 verifyTamperChains 直接返回 null、不走画像
    chains: [{ vendor: 'lab', plugins: [...plugins] }],
    config: {},
    timeoutMs: 8000,
  });
  if (!picked) return { picked: null, blocked: [], probed: 0, plan: null };
  const plan = planChannels({
    techniques: ['union', 'error', 'boolean'],
    blocked: picked.blocked,
    covered: coveredTokens(picked.plugins),
  });
  return { picked, blocked: picked.blocked, probed: picked.probed, plan };
}

const facts = {
  wafHits: 0,
  dual: null,
  single: null,
  noProfile: null,
};
let blockedReason = '';

try {
  // 前提自检：裸探针必须被拦（否则画像分支不会进入，本套件验不到东西）
  const rawRes = await httpClient.request({
    url: `${dual.base}/item?id=${encodeURIComponent("1' AND 1=1-- -")}`,
    method: 'GET',
    timeoutMs: 8000,
    retry: 0,
  });
  const rawBlocked = !rawRes || rawRes.status === 403 || /blocked by/i.test(String(rawRes.data ?? ''));
  if (!rawBlocked) {
    blockedReason = `裸探针未被拦（status=${rawRes?.status}）—— 靶场规则未生效，本套件未验到 A3`;
  } else {
    // ⚠️ 链必须用**算子替换族**（symboliclogical：AND→&&），不能用编码族（charencode/percentage）：
    // 靶场与真实 WAF 一样只解一次码，编码后的 `%61%6e%64` 解码回来仍是 `and` → 照样被拦，
    // 于是所有链都验不过 → verifyTamperChains 走「全部被拦」分支返回 null → **画像带不出来**
    // （该分支本就不需要画像：重跑会被跳过），本套件就拿不到任何可断言的事实。
    // 算子替换是真能绕过关键词黑名单的形态（本项目实战实测结论），用它才能让验链走到成功分支。
    // 副作用（正合需要）：symboliclogical 覆盖 and/or → boolean 不会被降级，
    // 而它**不覆盖** union/select → union 的降级判据不被抹掉，降级才观测得到。
    facts.dual = await runOnce(dual.base, ['symboliclogical']);
    facts.single = await runOnce(single.base, ['symboliclogical']);
    // 反向对照：无画像（blocked 为空）时不得做任何决策
    facts.noProfile = planChannels({ techniques: ['union', 'error', 'boolean'], blocked: [] });
  }
} catch (e) {
  blockedReason = `执行异常：${e.message}`;
} finally {
  facts.wafHits = counter.hits;
  dual.server.close();
  single.server.close();
}

if (blockedReason) {
  console.log(`[BLOCKED] ${blockedReason}`);
  console.log('[channel-degrade] 本套件未执行任何断言（环境/前提不满足，不得计为通过）');
  mkdirSync(resolve(HERE, 'results'), { recursive: true });
  writeFileSync(
    resolve(HERE, 'results', 'waf-channel-degrade.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), blocked: blockedReason, ...facts }, null, 2)
  );
  process.exit(0);
}

const d = facts.dual;
const s = facts.single;
const has = (arr, t) => Array.isArray(arr) && arr.includes(t);

const checks = [
  // —— 画像真实性（对照靶场 ground truth）——
  {
    name: '双拦靶场画像必须含 union 与 select',
    ok: has(d.blocked, 'union') && has(d.blocked, 'select'),
    got: `[${d.blocked.join(',')}]`,
  },
  {
    name: '双拦靶场画像不得把未拦的词误判为被拦（quote/comment 必须放行）',
    ok: !has(d.blocked, 'quote') && !has(d.blocked, 'comment'),
    got: `[${d.blocked.join(',')}]`,
  },
  {
    name: '单拦靶场画像含 union 但不含 select（验证探针确实逐词区分）',
    ok: has(s.blocked, 'union') && !has(s.blocked, 'select'),
    got: `[${s.blocked.join(',')}]`,
  },
  {
    name: '画像恰好一轮探针（预算纪律：降级不得额外发请求）',
    ok: d.probed === TOKEN_PROBES.length && s.probed === TOKEN_PROBES.length,
    got: `dual=${d.probed} single=${s.probed} 期望=${TOKEN_PROBES.length}`,
  },
  // —— 决策正确性 ——
  {
    // boolean 不降级：symboliclogical 覆盖 and/or → 链能消除必需记号
    name: '双拦 → union 降级、error 与 boolean 保留（链覆盖保住 boolean）',
    ok: d.plan && !d.plan.run.includes('union') && d.plan.run.includes('boolean') && d.plan.run.includes('error'),
    got: d.plan ? `run=[${d.plan.run.join(',')}] skipped=[${d.plan.skipped.map((x) => x.technique).join(',')}]` : 'null',
  },
  {
    name: '单拦（只拦 union）→ union **不得**降级（OR 组语义）',
    ok: s.plan && s.plan.run.includes('union'),
    got: s.plan ? `run=[${s.plan.run.join(',')}]` : 'null',
  },
  {
    name: '无画像 → 不决策（三通道全保留）',
    ok: facts.noProfile.run.length === 3 && facts.noProfile.skipped.length === 0,
    got: `run=[${facts.noProfile.run.join(',')}]`,
  },
];
const failed = checks.filter((c) => !c.ok);

console.log(
  `[channel-degrade] 画像 双拦=[${d.blocked.join(',')}] 单拦=[${s.blocked.join(',')}]` +
    `　决策 双拦 run=[${d.plan?.run.join(',')}] 单拦 run=[${s.plan?.run.join(',')}]` +
    `　探针各 ${d.probed}/${s.probed} 次　WAF 拦截 ${facts.wafHits} 次`
);
for (const c of checks) console.log(`  ${c.ok ? '✅' : '❌'} ${c.name}（实测 ${c.got}）`);

mkdirSync(resolve(HERE, 'results'), { recursive: true });
writeFileSync(
  resolve(HERE, 'results', 'waf-channel-degrade.json'),
  JSON.stringify({ generatedAt: new Date().toISOString(), ...facts, checks }, null, 2)
);
console.log(
  `[channel-degrade] 结论：${failed.length ? `❌ ${failed.map((f) => f.name).join('；')}` : '✅ A3 通道降级在真实 HTTP 画像下决策正确'}`
);
process.exit(failed.length ? 1 : 0);
