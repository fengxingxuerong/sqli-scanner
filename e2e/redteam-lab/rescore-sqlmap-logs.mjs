// ============================================================================
// e2e/redteam-lab/rescore-sqlmap-logs.mjs —— [D102 2026-10-18] 修正正则重算既有 sqlmap 日志
//
// 背景（见 sqlmap-bench.mjs 内 [D102] 注释）：2026-10-04 版 bench 的命中正则裸词
// /injectable/ 把 sqlmap 未检出时的 `[CRITICAL] ... do not appear to be injectable`
// 判成命中 ⇒ results-sqlmap-runs3.json 里 safe 侧 6/7「误报」是判定脚本自伤。
//
// 口径：不重跑 sqlmap（原日志即原始证据），只换判定正则重判同一批日志 ⇒ 修正后的计数
// 可与旧文件逐点对照。旧文件不重写（留痕）；产出 results-sqlmap-runs3.rescored.json。
// 用法：node e2e/redteam-lab/rescore-sqlmap-logs.mjs
// ============================================================================
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const OUTDIR = fileURLToPath(new URL('./sqlmap-out/', import.meta.url));
const OLD = fileURLToPath(new URL('./results-sqlmap-runs3.json', import.meta.url));
const NEW = fileURLToPath(new URL('./results-sqlmap-runs3.rescored.json', import.meta.url));
const RUNS = 3;

// 判定改用「肯定式专有短语」：sqlmap 的终审判定行只有这三种形态——
//   parameter 'x' is vulnerable.          （经典终审）
//   ... is 'Generic UNION query ...' injectable   （技术确认行，引号内含技术名）
//   identified/resumed the following injection point
// 否定句（"do not appear to be injectable" / "might not be injectable"）天然不含这些短语；
// ⚠ 不用「pos && !neg」：多参数目标下日志会同时含「参数 A is vulnerable」与
// 「参数 B does not seem to be injectable」⇒ neg-AND 会把真命中误杀成 miss
// （本脚本第一版实测：D14/D15 因该逻辑反向翻转）。
const pos = /parameter '[^']+' is vulnerable|is '[^']+' injectable|identified the following injection point|resumed the following injection point/i;

const old = JSON.parse(readFileSync(OLD, 'utf8'));

const results = [];
const changes = [];
for (const r of old.results) {
  const runHits = [];
  for (let i = 1; i <= RUNS; i++) {
    const p = `${OUTDIR}${r.id}.r${i}.log`;
    if (!existsSync(p)) { runHits.push(null); continue; }
    const out = readFileSync(p, 'utf8');
    const inj = pos.test(out);
    const fp = /false positive|unexploitable|looks like.*false/i.test(out);
    runHits.push(inj && !fp);
  }
  const available = runHits.filter((h) => h !== null);
  if (!available.length) { results.push({ ...r, rescore: 'no-logs' }); continue; }
  const hits = available.filter(Boolean).length;
  const hit = hits > available.length / 2;
  results.push({ id: r.id, kind: r.kind, hit, hitCount: hits, runs: available.length, ms: r.ms });
  if (r.hit !== hit) changes.push({ id: r.id, kind: r.kind, old: r.hit, now: hit });
}

const vuln = results.filter((r) => r.kind === 'vuln');
const safe = results.filter((r) => r.kind === 'safe');
const summary = {
  runs: RUNS, at: new Date().toISOString(),
  note: 'D102 修正正则重算（不重跑 sqlmap）：旧文件 safe 侧 6/7「误报」为裸词正则自伤',
  total: results.length, vulnCount: vuln.length, safeCount: safe.length,
  vulnHitRate: `${vuln.filter((r) => r.hit).length}/${vuln.length}`,
  falsePositives: `${safe.filter((r) => r.hit).length}/${safe.length}`,
  oldFalsePositives: old.summary.falsePositives,
  changed: changes.length,
};
writeFileSync(NEW, JSON.stringify({ summary, changes, results }, null, 2), 'utf8');
console.log(`[rescore] 修正后：检出 ${summary.vulnHitRate}，误报 ${summary.falsePositives}（旧文件记 ${old.summary.falsePositives}）`);
console.log(`[rescore] 判定翻转 ${changes.length} 点：`);
for (const c of changes) console.log(`  ${c.id} [${c.kind}] ${c.old ? 'hit' : 'miss'} → ${c.now ? 'hit' : 'miss'}`);
