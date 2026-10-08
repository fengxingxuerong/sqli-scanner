#!/usr/bin/env node
/**
 * waf-ammunition-audit.mjs —— WAF 弹药库体检（纯本地，零网络、零 DB）
 *
 * 回答三个问题，全靠**插件自己的 transform 实测**，不采信任何声明：
 *   ① 弹药库里有多少是"没名分"的（unclassified）—— 它们旧纪律下整批进不了候选池；
 *   ② 其中有多少其实是真弹药（实测派生出 token 信息 ⇒ 现在进得了池）；
 *   ③ 有多少是"过了 WAF 但 SQL 必挂"的假弹药（命中结构不变量 ⇒ 已请出池）。
 *
 * ⚠️ 口径纪律：
 *   · 本脚本**不判**能否过 WAF、能否取到数据 —— 那是真机（modsec-live + 真 MySQL）的事。
 *   · "语义保持"不是本脚本的输出：它只判**结构有没有被破坏**（词内切分 / 注释未闭合）。
 *
 * 用法：
 *   npm run waf:audit
 *   node scripts/waf-ammunition-audit.mjs --md docs/WAF-弹药库审计-2026-10-08.md
 */
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');

const argv = process.argv.slice(2);
const arg = (k, d) => (argv.find((a) => a.startsWith(`--${k}=`)) || '').slice(k + 3) || d;
// 兼容两种写法：`--md <path>` 与 `--md=<path>`
const MD_OUT = arg('md', '') || (argv.includes('--md') ? (argv[argv.indexOf('--md') + 1] || '') : '');

const { semanticUnsafeRegistry, INVARIANTS } = await import(
  pathToFileURL(resolve(ROOT, 'server/src/core/waf/bypass/semanticIntegrity.js')).href
);
const { buildSemanticIndex, indexCoverage } = await import(
  pathToFileURL(resolve(ROOT, 'server/src/core/waf/bypass/semantics.js')).href
);

const unsafe = semanticUnsafeRegistry();
const idx = buildSemanticIndex();
const cov = indexCoverage();

/** 有 token 信息 ⇒ 选弹时可用（不再是"盲试噪声"） */
const hasInfo = (m) =>
  (m.eliminates || []).length + (m.introduces || []).length + (m.mutates || []).length +
  (m.eliminatesAll ? 1 : 0) + (m.reducesPunct ? 1 : 0) > 0;

const unclassified = [...idx.values()].filter((m) => m.category === 'unclassified');
const rescued = unclassified.filter((m) => hasInfo(m) && !unsafe.has(m.name));
const stillBlind = unclassified.filter((m) => !hasInfo(m) && !unsafe.has(m.name));

const lines = [];
const say = (s = '') => { lines.push(s); console.log(s); };

say('# WAF 弹药库体检');
say();
say(`总插件 **${cov.total}** · 人工精标 ${cov.curated} · 族派生 ${cov.family} · 未分类 ${cov.unclassified}`);
say();

say('## ① 未分类弹药的抢救情况');
say();
say('| 类别 | 件数 | 说明 |');
say('|---|---:|---|');
say(`| 实测派生后**进池** | ${rescued.length} | 有了机器可用的 token 信息，定向搜索能选到 |`);
say(`| 判为**语义不可用**出局 | ${unsafe.size} | 结构性破坏 SQL，过了 WAF 也拼不出可执行语句 |`);
say(`| 仍无信息（盲试，排除） | ${stillBlind.length} | 对全部语料无作用且无声明 ⇒ 保持排除 |`);
say();

say('## ② 语义不可用名单（假弹药）');
say();
say(`共 **${unsafe.size}** 件。判据：${INVARIANTS.map((i) => `\`${i.id}\`（${i.title}）`).join(' · ')}`);
say();
say('| 插件 | 不变量 | 证据 |');
say('|---|---|---|');
for (const [name, vs] of unsafe) {
  say(`| \`${name}\` | ${vs.map((v) => v.id).join(', ')} | ${vs.flatMap((v) => v.evidence).slice(0, 3).map((e) => `\`${e}\``).join(' ')} |`);
}
say();

say('## ③ 被抢救回来的弹药（按消除词数排序）');
say();
say('| 插件 | 消除 | 引入 |');
say('|---|---|---|');
for (const m of rescued.sort((a, b) => (b.eliminates || []).length - (a.eliminates || []).length)) {
  const el = (m.eliminates || []).join(', ') || '—';
  const intro = (m.introduces || []).join(', ') || '—';
  say(`| \`${m.name}\`${m.eliminatesAll ? '（整串编码）' : ''} | ${el} | ${intro} |`);
}
say();
say('> 「消除」只说明该词在输出里**字面消失**，不证明语义等价 —— 等价性由插件单测与真机对拍负责。');

if (MD_OUT) {
  const { writeFileSync } = await import('node:fs');
  writeFileSync(resolve(ROOT, MD_OUT), lines.join('\n') + '\n', 'utf8');
  console.log(`\n已写出：${MD_OUT}`);
}
