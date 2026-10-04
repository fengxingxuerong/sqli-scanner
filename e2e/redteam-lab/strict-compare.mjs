// ============================================================================
// strict-compare.mjs —— 红队靶场「严格同题对照」定版报告生成器（批次 D2）
//
// 输入（都是本目录下的既有产物，不新跑任何东西）：
//   · results-sqlmap-runsN.json —— sqlmap 侧 N 轮（sqlmap-bench.mjs --runs=N）
//   · results-m1.json / results-m2.json / results-m3.json —— 引擎侧 3 轮默认档
//     （run-scan.mjs <round>；刻意不用 r1/r2 —— r2 会自动升 --level 3 --risk 2，
//      与 sqlmap 的 --level=1 档位不对等，混入等于换档作弊）
// 输出：docs/sqlmap-benchmark/redteam-strict-<tag>.md —— 同分母、多轮中位的定版对照。
// ============================================================================
import { writeFileSync, readFileSync, existsSync } from 'node:fs';

const RUNS = Number((process.argv.find((a) => a.startsWith('--runs=')) || '--runs=3').split('=')[1]) || 3;
const read = (f) => JSON.parse(readFileSync(new URL(f, import.meta.url), 'utf8'));

const smapPath = `./results-sqlmap-runs${RUNS}.json`;
if (!existsSync(new URL(smapPath, import.meta.url))) {
  console.error(`缺 ${smapPath} —— 先跑 node e2e/redteam-lab/sqlmap-bench.mjs --runs=${RUNS}`);
  process.exit(1);
}
const smap = read(smapPath);
const engineRounds = ['m1', 'm2', 'm3'].map((r) => {
  const f = `./results-${r}.json`;
  if (!existsSync(new URL(f, import.meta.url))) {
    console.error(`缺 ${f} —— 先跑 node e2e/redteam-lab/run-scan.mjs ${r}`);
    process.exit(1);
  }
  return read(f);
});

const gt = read('./ground-truth.json');

const perTarget = gt.map((g) => {
  const s = smap.results.find((r) => r.id === g.id) || { hit: false, hitCount: 0, ms: null };
  const eRounds = engineRounds.map((round) => {
    const r = round.find((x) => x.id === g.id);
    return r ? { hit: r.hit, ms: r.ms } : { hit: false, ms: null };
  });
  const eHits = eRounds.filter((r) => r.hit).length;
  const eMs = eRounds.filter((r) => r.ms != null).map((r) => r.ms).sort((a, b) => a - b);
  const eMedian = eMs.length ? eMs[Math.floor(eMs.length / 2)] : null;
  return {
    id: g.id, kind: g.kind,
    truth: g.kind === 'vuln',
    engine: { hit: eHits > 0, hitCount: eHits, ms: eMedian },
    sqlmap: { hit: s.hit, hitCount: s.hitCount, ms: s.ms },
  };
});

const agg = (side) => {
  const vuln = perTarget.filter((t) => t.kind === 'vuln');
  const safe = perTarget.filter((t) => t.kind === 'safe');
  const hitV = vuln.filter((t) => t[side].hit).length;
  const fpS = safe.filter((t) => t[side].hit).length;
  const msHit = perTarget.filter((t) => t[side].hit && t[side].ms != null).map((t) => t[side].ms);
  return {
    vulnHit: `${hitV}/${vuln.length}`,
    falsePos: `${fpS}/${safe.length}`,
    medianMs: msHit.length ? Math.round(msHit.sort((a, b) => a - b)[Math.floor(msHit.length / 2)]) : null,
  };
};
const eAgg = agg('engine');
const sAgg = agg('sqlmap');

const fmtMs = (ms) => (ms == null ? '-' : ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`);
const rows = perTarget.map((t) =>
  `| ${t.id} | ${t.kind} | ${t.engine.hit ? '✅' : '❌'}(${t.engine.hitCount}/3) | ${fmtMs(t.engine.ms)} | ${t.sqlmap.hit ? '✅' : '❌'}(${t.sqlmap.hitCount}/${RUNS}) | ${fmtMs(t.sqlmap.ms)} |`);

const md = [
  '# 红队靶场严格同题对照（26 靶点 × 多轮，定版口径）',
  '',
  `- 日期：${new Date().toISOString().slice(0, 10)}｜方法论：同靶点双方各跑 ${RUNS} 轮，检出多数决、耗时中位`,
  '- 引擎档位：默认档（与 sqlmap `--level=1 --risk=1` 同为浅档；引擎侧刻意不用 r2 的高档结果）',
  '- 分母：vuln 19 + safe 7 = **26**，两侧完全一致（同题守卫在 bench 启动时钉死）',
  '',
  '| 靶点 | 类型 | 引擎检出(轮) | 引擎中位 | sqlmap 检出(轮) | sqlmap 中位 |',
  '|---|---|---|---|---|---|',
  ...rows,
  '',
  '## 汇总（同分母，比率可直比）',
  '',
  `| 指标 | 本引擎 | sqlmap 1.10.7 |`,
  `|---|---|---|`,
  `| 漏洞检出（19 漏洞点） | **${eAgg.vulnHit}** | ${sAgg.vulnHit} |`,
  `| 安全点误报（7 安全点） | **${eAgg.falsePos}** | ${sAgg.falsePos} |`,
  `| 命中场景中位耗时 | **${fmtMs(eAgg.medianMs)}** | ${fmtMs(sAgg.medianMs)} |`,
  '',
  '> 口径边界：SQLite 靶场 + 浅档对照；本表取代旧「18/14 分母不同」的单轮对照，',
  '> 旧结论中「比率不可直接类比」的保留意见自本表起作废。',
  '',
].join('\r\n');

const tag = `runs${RUNS}`;
writeFileSync(new URL(`../../docs/sqlmap-benchmark/redteam-strict-${tag}.md`, import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'), md, 'utf8');
writeFileSync(new URL(`./results-strict-${tag}.json`, import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'),
  JSON.stringify({ runs: RUNS, summary: { engine: eAgg, sqlmap: sAgg }, perTarget }, null, 2), 'utf8');
console.log(`引擎: 检出 ${eAgg.vulnHit} 误报 ${eAgg.falsePos} 中位 ${fmtMs(eAgg.medianMs)}`);
console.log(`sqlmap: 检出 ${sAgg.vulnHit} 误报 ${sAgg.falsePos} 中位 ${fmtMs(sAgg.medianMs)}`);
console.log('定版报告已写入 docs/sqlmap-benchmark/');
