// ============================================================================
// sqlmap-bench —— 红队靶场「同题对照」基准（对标口径的定版工具）
//
// [批次 D2 2026-10-04] 项目评价（2026-10-03）§三.B 的两个缺口一次收口：
//   ① **分母不同**：旧版 18 用例 ⊂ 权威 26 靶点，「比率不可直接类比」—— 本版扩到
//      **26/26 全覆盖**，并在启动时用**同题守卫**把 CASES 与 ground-truth.json 的
//      id 集合钉死（任一侧漂移直接退出，分母耦合不再靠自觉）；
//   ② **单轮数字**：单机抖动撑不起强断言 —— `--runs=N`（默认 3）多轮复跑，
//      检出取多数决、耗时取中位数、命中轮次入表（与 sqli-labs 基准同一方法论）。
//
// 口径：--batch --level 1 --risk 1 --flush-session（与 sqli-scanner 默认档对齐）。
// 用法：
//   node e2e/redteam-lab/sqlmap-bench.mjs [--runs=3] [--only=A1-int-union,C7-boolean]
// 前置：靶场环境已常驻（node e2e/redteam-lab/env.mjs，靶站 8231）。
// ============================================================================
import { spawn } from 'node:child_process';
import { writeFileSync, readFileSync, mkdirSync } from 'node:fs';

const SQLMAP = process.env.SQLMAP_BIN || 'C:\\Users\\Admin（无密码）\\AppData\\Local\\Programs\\Python\\Python39\\Scripts\\sqlmap.exe';
const LAB_PORT = Number(process.env.REDTEAM_LAB_PORT) || 8231;
const LAB = `http://127.0.0.1:${LAB_PORT}`;
const OUTDIR = new URL('./sqlmap-out/', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');

const RUNS = Math.max(1, Number((process.argv.find((a) => a.startsWith('--runs=')) || '').split('=')[1]) || 3);
const TAG = RUNS > 1 ? `runs${RUNS}` : 'single';
const winPath = (url) => url.pathname.replace(/^\/([A-Za-z]:)/, '$1');

const CASES = [
  { id: 'A1-int-union', args: ['-u', `${LAB}/shop/item?id=1`] },
  { id: 'A2-str-union', args: ['-u', `${LAB}/shop/search?name=alice`] },
  { id: 'A3-like', args: ['-u', `${LAB}/shop/find?q=a`] },
  { id: 'A4-orderby', args: ['-u', `${LAB}/shop/sort?by=id`] },
  { id: 'A5-dual-param', args: ['-u', `${LAB}/shop/detail?id=1&cat=0`] },
  { id: 'B6-error', args: ['-u', `${LAB}/shop/err?id=1`] },
  { id: 'C7-boolean', args: ['-u', `${LAB}/shop/blind?id=1`] },
  { id: 'C8-time', args: ['-u', `${LAB}/shop/time?id=1`, '--technique=T'] },
  { id: 'D9-post-form', args: ['-r', winPath(new URL('./reqs/login.txt', import.meta.url))] },
  { id: 'D10-json', args: ['-r', winPath(new URL('./reqs/json.txt', import.meta.url))] },
  // Cookie 注入：--test-headers 让 sqlmap 把 header 值纳入探测
  { id: 'D11-cookie', args: ['-u', `${LAB}/shop/cookie`, '--header', 'cookie: uid=1', '--test-headers'] },
  { id: 'D12-xff-header', args: ['-r', winPath(new URL('./reqs/xff.txt', import.meta.url)), '--level=3'] },
  { id: 'D13-path', args: ['-u', `${LAB}/shop/user/1*`] },
  // 真实 base64 值（MQ== = '1'）：短值 MQ 长度 <4 不会触发编码识别（run-scan 同款注释）
  { id: 'D14-base64', args: ['-u', `${LAB}/shop/b64?id=MQ==`] },
  // 自定义参数分隔符（; ）：必须配 --param-del 才会正确切分 query
  { id: 'D15-param-del', args: ['-u', `${LAB}/shop/semi?a=1;id=1`, '--param-del', ';'] },
  { id: 'D16-collate-mix', args: ['-u', `${LAB}/shop/mix?kw=alpha`] },
  // 每轮唯一会话 id：靶场把写入值存在内存 store[sid]，复用 sid 会让基线触发页读到上一轮
  // 残留探针（run-scan 同款注释）；二阶需要 --second-order + 写确认位（--no-production-mode 靶场豁免）。
  {
    id: 'E15-second-order',
    argsFn: () => ['-u', `${LAB}/account/update`, '--method', 'POST', '--body', '{"name":"alice"}',
      '--header', `cookie: sid=rt${Date.now().toString(36)}${Math.random().toString(36).slice(2, 6)}`, '--test-headers',
      '--second-order', `${LAB}/account/me`, '--allow-second-order-writes', '--no-production-mode'],
  },
  { id: 'E16-stacked', args: ['-u', `${LAB}/shop/stack?id=1`] },
  { id: 'E17-waf-guarded', args: ['-u', `${LAB}/waf/item?id=1`] },
  { id: 'F18-safe-item', args: ['-u', `${LAB}/safe/item?id=1`] },
  { id: 'F19-safe-search', args: ['-u', `${LAB}/safe/search?q=a`] },
  { id: 'F20-safe-rand', args: ['-u', `${LAB}/safe/rand?x=1`] },
  { id: 'F21-safe-500', args: ['-u', `${LAB}/safe/boom?id=1`] },
  { id: 'F22-safe-403', args: ['-u', `${LAB}/safe/blocked?id=1`] },
  { id: 'F23-safe-redirect', args: ['-u', `${LAB}/safe/redirect?id=1`] },
  { id: 'F24-safe-static', args: ['-u', `${LAB}/safe/static?id=1`] },
];

// ── 同题守卫：CASES 的 id 集合必须**等于** ground-truth.json ──
// 「分母不同、比率不可直接类比」曾是 README 的诚实标注；同题化之后这层耦合改由机械判据
// 把守：多一个（幽灵靶点）少一个（静默缩分母）都在启动时退出，而不是等报告出来才发现。
const GT = JSON.parse(readFileSync(new URL('./ground-truth.json', import.meta.url), 'utf8'));
const gtById = new Map(GT.map((g) => [g.id, g]));
const caseIds = CASES.map((c) => c.id);
const dup = caseIds.filter((id, i) => caseIds.indexOf(id) !== i);
if (dup.length) { console.error(`[同题守卫] CASES 有重复 id：${dup.join('、')}`); process.exit(2); }
const missing = [...gtById.keys()].filter((id) => !caseIds.includes(id));
if (missing.length) { console.error(`[同题守卫] CASES 缺权威靶点：${missing.join('、')}`); process.exit(2); }
const ghost = caseIds.filter((id) => !gtById.has(id));
if (ghost.length) { console.error(`[同题守卫] CASES 含权威之外的靶点：${ghost.join('、')}`); process.exit(2); }

const median = (arr) => {
  const s = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : Math.round((s[mid - 1] + s[mid]) / 2);
};

const run = (c) => new Promise((resolve) => {
  const args = [
    ...(typeof c.argsFn === 'function' ? c.argsFn() : c.args),
    '--batch', '--flush-session', '-v', '0', '--ignore-proxy',
    '--output-dir', OUTDIR, '--answers=follow=Y',
  ];
  const t0 = Date.now();
  // 清除环境代理：sqlmap 会读 *_PROXY；--ignore-proxy 再兜一层（二者叠加是刻意冗余）
  const env = { ...process.env };
  for (const k of Object.keys(env)) if (/^(http|https|all)_proxy$/i.test(k)) delete env[k];
  const p = spawn(SQLMAP, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  p.stdout.on('data', (d) => { out += d; });
  p.stderr.on('data', (d) => { out += d; });
  const guard = setTimeout(() => { try { p.kill('SIGKILL'); } catch { /* noop */ } }, 240000);
  p.on('close', () => {
    clearTimeout(guard);
    const note = (out.match(/parameter '[^']+' is vulnerable[^\n]*/i)
      || out.match(/sqlmap identified the following injection point[^\n]*/i) || [''])[0].slice(0, 140);
    resolve({ id: c.id, ms: Date.now() - t0, out, note });
  });
});

const only = process.argv.find((a) => a.startsWith('--only='))?.split('=')[1]?.split(',') || null;
const selected = CASES.filter((c) => !only || only.includes(c.id));
mkdirSync(OUTDIR, { recursive: true });

const results = [];
for (const c of selected) {
  const runs = [];
  for (let i = 0; i < RUNS; i++) {
    process.stdout.write(`[sqlmap] ${c.id} (${i + 1}/${RUNS}) ... `);
    const r = await run(c);
    const inj = /is vulnerable|parameter '[^']*' is vulnerable|injectable/i.test(r.out);
    const fp = /false positive|unexploitable|looks like.*false/i.test(r.out);
    writeFileSync(`${OUTDIR}${c.id}.r${i + 1}.log`, r.out);
    runs.push({ hit: inj && !fp, ms: r.ms, note: r.note });
    process.stdout.write(`${inj ? 'HIT' : 'miss'} ${r.ms}ms\n`);
  }
  const hitRuns = runs.filter((r) => r.hit);
  const hit = hitRuns.length > RUNS / 2; // 多数决（N 取奇数最稳）
  const kind = gtById.get(c.id)?.kind || 'unknown';
  const entry = {
    id: c.id, kind, hit, hitCount: hitRuns.length, runs: RUNS,
    ms: median(runs.map((r) => r.ms)),
    note: (hitRuns[0] || runs[0]).note,
  };
  results.push(entry);
  console.log(`  ⇒ ${c.id}: ${hit ? 'HIT' : 'miss'}（命中 ${hitRuns.length}/${RUNS}，中位 ${entry.ms}ms，kind=${kind}）`);
}

// ── 汇总：检出率只算 vuln 子集、误报只算 safe 子集 —— 同题之后这两个比率才可直比 ──
const vuln = results.filter((r) => r.kind === 'vuln');
const safe = results.filter((r) => r.kind === 'safe');
const vulnHit = vuln.filter((r) => r.hit).length;
const falsePos = safe.filter((r) => r.hit).length;
const summary = {
  runs: RUNS, generatedAt: new Date().toISOString(),
  total: results.length, vulnCount: vuln.length, safeCount: safe.length,
  vulnHitRate: `${vulnHit}/${vuln.length}`,
  falsePositives: `${falsePos}/${safe.length}`,
};
const outPath = (name) => new URL(name, import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
writeFileSync(outPath(`./results-sqlmap-${TAG}.json`), JSON.stringify({ summary, results }, null, 2), 'utf8');
// 单轮模式继续维护旧文件名（报告层/历史对照的既有消费方不受影响）
if (RUNS === 1) {
  writeFileSync(outPath('./results-sqlmap.json'),
    JSON.stringify(results.map(({ id, hit, ms, note }) => ({ id, hit, ms, note })), null, 2), 'utf8');
}

console.log(`\n==== 同题对照汇总（${results.length} 靶点 × ${RUNS} 轮，检出多数决/耗时中位）====`);
console.log(`sqlmap 漏洞检出: ${vulnHit}/${vuln.length} | 安全点误报: ${falsePos}/${safe.length}`);
for (const r of results) {
  console.log(`  ${r.hit ? 'HIT ' : 'miss'} ${r.id.padEnd(18)} 命中${r.hitCount}/${RUNS} 中位${r.ms}ms [${r.kind}]`);
}
