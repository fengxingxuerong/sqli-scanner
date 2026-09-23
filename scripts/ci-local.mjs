#!/usr/bin/env node
// ============================================================================
// scripts/ci-local.mjs —— 把 .github/workflows/ci.yml 的门禁清单在本机按同一顺序跑一遍
//
// 为什么要它：本仓**没有远端**（只有一个本地裸仓 backup），GitHub Actions 从未执行过，
// 于是 ci.yml 里那 12 个 job 全是"写了但没跑过"的声明。上一轮复查就撞过这个后果：
// ci.yml 的服务端类型检查步骤（checkJs，覆盖 36.7k 行 JS）在任何开发机上都不跑
// —— 本地 `npm run typecheck` 只查前端，一处 TS2339 因此进了提交。
// 「CI 绿」这件事不能靠口口相传，也不能靠人肉记 15 条命令（记不全就一定漏）。
//
// 与 CI 的关系（重要，别把它当 CI 的替身）：
//   · 覆盖：与平台无关的那 9 个 job 的命令序列，逐条取真实退出码；
//   · 不覆盖的 3 个 job，**逐个在 EXCLUDED_JOBS 里登记并写理由**（见下方常量）：
//       docker              —— 本机无 docker
//       test-matrix         —— 跨平台矩阵，命令集已覆盖，但「另一个操作系统」本机不可替代
//       tamper-waf-matrix   —— schedule-only 实验矩阵，本机要起 mysqld 沙箱（会弹窗）故交 CI
//     这份清单不是注释而是**可跑判据**：ci.yml 新增 job 而这里没跟上时会直接报错退出，
//     不会静默漏跑（详见 auditJobCoverage）。
//   · 另注：`docker` job 与 `acceptance` 的 MySQL+secure_file_priv 前置、以及 acceptance
//     在 CI 里"新克隆 + 空 datadir"的干净环境，本机都不等价；缺依赖会如实标 SKIP/BLOCKED，
//     **SKIP 不计入通过**（与 e2e/run-all.mjs 同一口径）。
//
// 用法：
//   node scripts/ci-local.mjs              # 全跑
//   node scripts/ci-local.mjs --quick      # 跳过耗时的三段（覆盖率门禁 / run-all / acceptance）
//   node scripts/ci-local.mjs --only=lint,typecheck,audit
//   SKIP_ACCEPTANCE=1 node scripts/ci-local.mjs   # 只跳 acceptance
//
// 前置（可选，缺了只会让对应套件变 SKIP，不会假绿）：
//   · MySQL 127.0.0.1:3306（root/root，库 sqli_lab 等由 e2e/*/init-db.mjs 建）
//   · `node e2e/redteam-lab/env.mjs`（拉起 PG + 8231 红队靶场，acceptance 的 redteam 套件要用）
//
// 已知环境性坑（不是代码问题，别去改源码）：
//   · Windows 上 cargo clippy 偶发 **ICE**（exit 101 +「the compiler unexpectedly panicked」，
//     伴随 `拒绝访问 (os error 5)` 的 incremental 复制警告）—— 是 target/debug/incremental
//     缓存损坏（多被中途 kill 的构建进程/杀软占用触发）。实测处理：
//     `cd src-tauri && cargo clean -p sqli-scanner && rm -rf target/debug/incremental`
//     后重跑即 0 错误。CI 是冷 target，不会碰到；只有本机跑会撞上。
// ============================================================================
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const quick = argv.includes('--quick');
const onlyArg = argv.find((a) => a.startsWith('--only='));
const only = onlyArg ? onlyArg.slice(7).split(',').map((s) => s.trim()).filter(Boolean) : null;

const probePort = (port, timeout = 700) =>
  new Promise((res) => {
    const s = net.connect(port, '127.0.0.1');
    const done = (v) => { try { s.destroy(); } catch { /* noop */ } res(v); };
    s.on('connect', () => done(true));
    s.on('error', () => done(false));
    setTimeout(() => done(false), timeout);
  });

/**
 * 一条门禁命令。
 * @param {string} id 归属的 CI job 名（用于 --only 过滤与报告）
 * @param {string} cmd 完整命令行（用 shell 执行：npm 在 Windows 上是 npm.cmd，
 *   非 shell 直调会 ENOENT。传**单串**而不是 cmd+args 是为了不踩 Node 的 DEP0190——
 *   「带 args 的 shell:true」才是那条警告说的东西。）
 * @param {{slow?:boolean, needsPorts?:number[], needs?:string[]}} [opt]
 */
const GATES = [
  { id: 'typecheck', name: 'TypeScript 前后端（= CI 两条类型步骤）', cmd: 'npm run typecheck' },
  { id: 'lint', name: 'ESLint', cmd: 'npm run lint' },
  { id: 'lint', name: '架构门禁（体积/循环依赖/console）', cmd: 'node scripts/arch-guard.mjs' },
  // 引用完整性：ci.yml / package.json / run-all.mjs 里写的本地路径必须真实存在。
  // 起因：ci.yml 两个 job 写着不存在的 run.js，又带 continue-on-error → 静默失败、从不拦人，
  // 那两个 job 从未验证过任何东西，靠人工 grep 才发现。这道闸门防的就是同类复发。
  { id: 'lint', name: '引用完整性（CI/scripts/e2e 入口路径存在性）', cmd: 'node scripts/ref-integrity.mjs' },
  // 靶点清单一致性：redteam-lab 的检出率/误报结论依赖一条**真值链**
  // （run-scan 决定扫哪些 ↔ selftest 决定标定哪些 ↔ ground-truth.json 真值表），
  // 而三份清单各自手写、彼此之间没有判据。不同步的后果**不对称**：
  // run-scan 多一个点而 selftest 少一个 → 该点不进真值表 → 完全不计入分母 → 静默
  // （结论看着更漂亮）；反向则会被拉低而变红。故与引用完整性并列成一条可跑判据。
  { id: 'lint', name: '红队靶点清单一致性（真值链）', cmd: 'npm run targets:check' },
  { id: 'lint', name: '文档数字口径（README ↔ _facts.json）', cmd: 'npm run facts:check' },
  // README **内部**口径自洽：同一事实被写多处时必须互相一致（与上一条互补 ——
  // facts:check 管的是「README ↔ 实测采集」，本条管的是「README 内部各处之间」）。
  // 实测第一例：方言分层的三处表述在 Oracle/MSSQL 升级后只改了两处，概览行残留
  // 「4 种真实 + 11 种模板」→ 对外低估自己，且两个三元组和都等于 18，肉眼看不出破绽。
  { id: 'lint', name: 'README 内部口径自洽（方言分层三处表述）', cmd: 'node scripts/readme-consistency.mjs' },
  // CRS 执行器保真度：本仓 WAF 数字全部出自自实现 SecRule 执行器（本机无 Docker/Go，跑不了真
  // ModSecurity/Coraza），所以"执行器像不像 CRS"必须有外部真值兜住 —— 这里用 CRS 官方回归集。
  // 不需要 MySQL，故与 lint 同组（真 CI 里也应放在 lint job）。
  { id: 'lint', name: 'CRS 执行器保真度（官方回归集 805 例）', cmd: 'npm run waf-fidelity' },
  { id: 'lint', name: 'CRS 规则原文与上游逐字节一致', cmd: 'node scripts/fetch-crs-assets.mjs --verify-rules' },
  // tamper 覆盖率同样是对外口径：README 写"覆盖 sqlmap 官方 tamper 全集"，那就对上游清单核一次
  // （清单快照已入库，离线可跑；缺失集合走"只减不增"基线）。
  { id: 'lint', name: 'tamper 对齐 sqlmap 官方清单', cmd: 'npm run tamper:parity' },
  // [DECISION-2026-09-22] e2e 辅助模块单测：决定「红」记到环境还是代码头上，判错代价不对称。
  // e2e/ 下的 *.test.mjs 不在 server/tests / src/tests 的发现范围里 —— 不接线就等于没写。
  // 必须用 glob：Node 的 `--test <目录>/` 会把目录当模块 require（实测 1 fail），不是扫描目录。
  { id: 'lint', name: 'e2e 辅助模块单测（状态判定等）', cmd: 'node --test "e2e/lib/*.test.mjs"' },
  { id: 'lint', name: 'cargo fmt --check', cmd: 'cd src-tauri && cargo fmt --check' },
  { id: 'lint', name: 'cargo clippy -D warnings', cmd: 'cd src-tauri && cargo clippy -- -D warnings' },
  { id: 'test-frontend', name: '前端测试 + 覆盖率门禁', cmd: 'npx vitest run --coverage --reporter=dot', slow: true },
  { id: 'test-frontend', name: '前端构建', cmd: 'npm run build' },
  { id: 'test-server', name: '服务端单测', cmd: 'cd server && npm test' },
  { id: 'test-server', name: '服务端覆盖率门禁', cmd: 'cd server && npm run test:coverage', slow: true },
  { id: 'audit', name: 'npm audit（前端 prod）', cmd: 'npm audit --omit=dev --audit-level=high' },
  { id: 'audit', name: 'npm audit（服务端）', cmd: 'cd server && npm audit --audit-level=high' },
  { id: 'e2e-self-contained', name: 'run-all（自足靶场 + 依赖探测）', cmd: 'node e2e/run-all.mjs', slow: true },
  { id: 'recall-lab', name: 'recall-lab e2e', cmd: 'node e2e/recall-lab/recall.e2e.js' },
  { id: 'release-smoke', name: '发布冒烟（生产配置组合）', cmd: 'node e2e/release/release-smoke.mjs' },
  { id: 'sidecar-build', name: 'sidecar SEA 构建 + 空目录真扫冒烟', cmd: 'npm run build:sidecar', slow: true },
  { id: 'acceptance', name: 'acceptance（13 套件，需 3306；redteam/文件读写会自己起环境）',
    cmd: 'npm run acceptance', needsPorts: [3306], slow: true },
  // 随机化真值电池：召回率报 Wilson 95%CI 下界（40 例 ≈6-8 分钟）。见 ci.yml 同名步骤的理由。
  { id: 'acceptance', name: '随机化真值电池（召回 CI 下界 + 良性零误报）',
    cmd: 'node e2e/random-lab/battery.mjs --cases=40 --seed=20260919', needsPorts: [3306], slow: true },
];

const SKIP_IN_QUICK = new Set(['test-frontend', 'test-server', 'e2e-self-contained', 'acceptance', 'sidecar-build']);

// ── 覆盖完整性自检：ci.yml 的每个 job 必须有人管（本地覆盖 or 显式排除 + 理由）───────
// 与 scripts/ref-integrity.mjs（TODO §J）同源：那道闸门查「引用的**文件**存不存在」，
// 这道查「ci.yml 里的 **job** 有没有人执行」—— 都是「配置里写了、实际没人跑」的静默缺口。
//
// 起因：本文件头部原写「不覆盖：需要 docker 的 job（docker、…）」，只提了 1 个，
// 而实际未覆盖的是 **3 个**（test-matrix / tamper-waf-matrix / docker）。声明与实际不符，
// 且没有任何东西会因此变红 —— 读者只会以为除 docker 外都覆盖了。
// 更实际的后果在将来：ci.yml 新加一个 job，本地门禁**静默少跑一段**，谁也不会发现。
//
// 口径：不留「默认跳过」的口子 —— 没登记就报错退出，逼人当场二选一：
// ① 在 GATES 里补命令；② 在 EXCLUDED_JOBS 里写清「为什么本机替代不了」。
const EXCLUDED_JOBS = {
  'test-matrix':
    '跨平台矩阵（windows-latest / macos-latest）：命令集（typecheck + vitest + 服务端单测）已由 ' +
    'lint / test-frontend / test-server 在本机覆盖；「另一个操作系统」这个维度本机替代不了（只有 Windows）',
  'tamper-waf-matrix':
    'schedule-only 的实验矩阵（TODO §K）：本机跑它要起隔离 mysqld 沙箱（会弹控制台窗口，' +
    '本机默认不起服务）→ 交 CI。注意 job 内两步性质不同（2026-09-22 订正）：' +
    'tamper-test.mjs 是纯测量（非门禁，保留 continue-on-error）；' +
    'compare-real.run.py 是真断言门禁（已去掉 continue-on-error，红会如实报告）。',
  docker: '本机无 docker（实测 `docker --version` exit 127）',
};

// GATES 覆盖到的 job 名（`typecheck` 不是 ci.yml 的 job 而是 lint job 内的步骤，一并计入无害）
const COVERED_JOBS = new Set(GATES.map((g) => g.id));

function auditJobCoverage() {
  const yml = readFileSync(resolve(ROOT, '.github/workflows/ci.yml'), 'utf8');
  const start = yml.search(/^jobs:\r?$/m);
  if (start < 0) throw new Error('ci.yml 里定位不到 `jobs:` 行（结构变了？本自检需要跟着改）');
  const tail = yml.slice(start + 'jobs:'.length);
  // 判据失效必须**显形**：jobs 段后若冒出新的顶级键，缩进匹配就可能收错/漏收。
  // 宁可报错要求同步本自检，也不静默漏检 —— 静默漏检正是这道闸门要防的东西。
  const topLevel = tail.match(/^[A-Za-z][\w-]*:/m);
  if (topLevel) throw new Error(`ci.yml 的 jobs: 段之后出现新的顶级键 \`${topLevel[0]}\` —— 本自检需要跟着改`);
  const jobs = [...tail.matchAll(/^ {2}([a-z][a-z0-9-]*):\r?$/gm)].map((m) => m[1]);
  if (!jobs.length) throw new Error('ci.yml 的 jobs: 段里一个 job 都没解析到（缩进变了？）');
  return {
    jobs,
    covered: jobs.filter((j) => COVERED_JOBS.has(j)),
    excluded: jobs.filter((j) => !COVERED_JOBS.has(j) && j in EXCLUDED_JOBS),
    unaccounted: jobs.filter((j) => !COVERED_JOBS.has(j) && !(j in EXCLUDED_JOBS)),
    // 反向：清单里登记了、ci.yml 已经没有的 job —— 清单会腐烂，同样要报
    stale: Object.keys(EXCLUDED_JOBS).filter((j) => !jobs.includes(j)),
  };
}

{
  const cov = auditJobCoverage();
  console.log(
    `job 覆盖自检：ci.yml ${cov.jobs.length} 个 job → 本地覆盖 ${cov.covered.length} / ` +
      `显式排除 ${cov.excluded.length} / ${cov.unaccounted.length ? `⚠️ 未声明 ${cov.unaccounted.length}` : '未声明 0'}`
  );
  if (cov.stale.length) {
    console.error(`\n❌ EXCLUDED_JOBS 里登记了 ci.yml 已不存在的 job：${cov.stale.join('、')}`);
    console.error('   排除清单腐烂了（那个 job 可能已删除或改名）—— 请同步更新本脚本的 EXCLUDED_JOBS。');
    process.exit(2);
  }
  if (cov.unaccounted.length) {
    console.error(`\n❌ ci.yml 里有 ${cov.unaccounted.length} 个 job 没有登记的归宿：${cov.unaccounted.join('、')}`);
    console.error('   每个 job 必须二选一：① 在 GATES 里补上它的命令（本地能跑）；');
    console.error('   ② 在 EXCLUDED_JOBS 里登记，并写清「为什么本机替代不了」。');
    console.error('   不给默认跳过 —— 否则 ci.yml 新增 job 时本地门禁会静默少跑一段，而没人会发现。');
    process.exit(2);
  }
}

console.log('=== ci-local：按 ci.yml 的 job 顺序在本机跑一遍 ===');
const ports = { 3306: await probePort(3306), 5432: await probePort(5432), 8231: await probePort(8231) };
console.log(`环境探测：MySQL 3306=${ports[3306] ? '在' : '不在'}  PG 5432=${ports[5432] ? '在' : '不在'}  红队靶场 8231=${ports[8231] ? '在' : '不在'}`);
if (!ports[3306]) console.log('  ⚠ 缺 MySQL → acceptance 会大面积 BLOCKED（不会假绿，但这一轮不算 CI 等价）');
if (!ports[8231]) console.log('  ⚠ 未起 e2e/redteam-lab/env.mjs → acceptance 的「红队实战评测」套件会 SKIP（SKIP 不计通过）');
console.log(quick ? '模式：--quick（跳过慢段）' : '模式：全跑');
console.log('');

const results = [];
for (const g of GATES) {
  if (only && !only.includes(g.id)) continue;
  if (quick && g.slow && SKIP_IN_QUICK.has(g.id)) {
    results.push({ ...g, state: 'SKIP', code: null, why: '--quick' });
    continue;
  }
  if (process.env.SKIP_ACCEPTANCE === '1' && g.id === 'acceptance') {
    results.push({ ...g, state: 'SKIP', code: null, why: 'SKIP_ACCEPTANCE=1' });
    continue;
  }
  const missing = (g.needsPorts || []).filter((p) => !ports[p]);
  if (missing.length) {
    results.push({ ...g, state: 'BLOCKED', code: null, why: `缺依赖：端口 ${missing.join('/')}` });
    console.log(`⛔ BLOCKED  ${g.name}　（${missing.join('/')} 未监听）`);
    continue;
  }
  const t0 = Date.now();
  process.stdout.write(`▶ ${g.name} ... `);
  // shell 执行单串命令（见 GATES 上方注释），输出落文件以免刷屏，失败时再回贴尾部
  const r = spawnSync(g.cmd, { cwd: ROOT, shell: true, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const code = r.status === null ? -1 : r.status;
  const out = `${r.stdout || ''}${r.stderr || ''}`;
  const secs = ((Date.now() - t0) / 1000).toFixed(1);
  if (code === 0) {
    console.log(`✅ ${secs}s`);
    results.push({ ...g, state: 'PASS', code });
  } else {
    console.log(`❌ exit=${code} ${secs}s`);
    const tail = out.split('\n').filter(Boolean).slice(-14).join('\n');
    console.log('  ┌ 失败输出尾部 ─────────────────────────────');
    for (const l of tail.split('\n')) console.log('  │ ' + l.slice(0, 200));
    console.log('  └──────────────────────────────────────────');
    results.push({ ...g, state: 'FAIL', code });
  }
}

const pass = results.filter((r) => r.state === 'PASS').length;
const fail = results.filter((r) => r.state === 'FAIL');
const blocked = results.filter((r) => r.state === 'BLOCKED');
const skipped = results.filter((r) => r.state === 'SKIP');
console.log('\n═══ 汇总 ═══');
for (const r of results) {
  const badge = { PASS: '✅', FAIL: '❌', BLOCKED: '⛔', SKIP: '⏭' }[r.state];
  console.log(`${badge} ${r.state.padEnd(8)} ${r.name}${r.why ? `　(${r.why})` : ''}`);
}
console.log(`\n${pass} PASS / ${fail.length} FAIL / ${blocked.length} BLOCKED / ${skipped.length} SKIP`);
// [2026-09-20] 原先这里写「CI 还有两个本机跑不了的 job —— `docker` 与 acceptance 的…前置」，
// 但「两个」里只有一个（docker）真是 job，且实际本机替代不了的 job 是 3 个（见 EXCLUDED_JOBS）。
// 散文式声明最容易与实际漂移，故此处不再复述数量，只指向启动时那行**可跑判据**的输出。
console.log('注：本机覆盖不到的部分以启动时「job 覆盖自检」那行为准（不在此复述，避免两处漂移）。');
console.log('    仍需真远端才能验证：docker job、test-matrix 的 macOS 腿、'
  + '以及 acceptance 在 CI 里「docker 起 MySQL + 放行 secure_file_priv」的干净环境前置。');
if (fail.length || blocked.length) console.log('SKIP 与 BLOCKED 都不算通过。');
process.exit(fail.length || blocked.length ? 1 : 0);
