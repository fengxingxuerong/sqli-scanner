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
//   · 不覆盖：需要 docker 的 job（`docker`、`acceptance` 的 MySQL+secure_file_priv 前置、
//     以及 acceptance 在 CI 里"新克隆 + 空 datadir"的干净环境），本机若缺依赖会如实标 SKIP，
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
  { id: 'lint', name: '文档数字口径（README ↔ _facts.json）', cmd: 'npm run facts:check' },
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
  { id: 'release-smoke', name: '发布冒烟（生产配置组合）', cmd: 'node e2e/diag/release-smoke.mjs' },
  { id: 'sidecar-build', name: 'sidecar SEA 构建 + 空目录真扫冒烟', cmd: 'npm run build:sidecar', slow: true },
  { id: 'acceptance', name: 'acceptance（11 套件，需 3306；redteam 套件需 env.mjs）',
    cmd: 'npm run acceptance', needsPorts: [3306], slow: true },
];

const SKIP_IN_QUICK = new Set(['test-frontend', 'test-server', 'e2e-self-contained', 'acceptance', 'sidecar-build']);

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
console.log('注：CI 还有两个本机跑不了的 job —— `docker`（build + 冒烟）与 acceptance 在 CI 里的'
  + '「docker 起 MySQL 并放行 secure_file_priv」前置。这两处只能等真远端接上才算验证过。');
if (fail.length || blocked.length) console.log('SKIP 与 BLOCKED 都不算通过。');
process.exit(fail.length || blocked.length ? 1 : 0);
