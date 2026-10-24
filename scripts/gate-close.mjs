#!/usr/bin/env node
// ============================================================================
// gate-close.mjs —— 收口门禁清单的**单一命令**（D71，2026-10-14）
//
// 为什么有这个脚本：**收口清单漏跑三次**，每次都是 CI 先抓到——
//   D66  漏 npm run typecheck      ⇒ #233 的 lint 红
//   D70  漏五道门禁（complexity 等）⇒ #243 的 lint 红
//   D70b 漏门禁 wiring 测试        ⇒ #246 的 test-server 红
// 靠记忆执行清单是不可靠的，这里把它固化成一条命令：**跑这一个 = 清单全过**。
//
// 清单与 AGENTS.md §3 的「收口清单」逐条对应；**新增门禁必须同时加到这里**
// （有 selftest 自证：清单条目数与关键项名对不上即红）。
//
// 用法：
//   node scripts/gate-close.mjs            # 跑全清单
//   node scripts/gate-close.mjs --quick    # 跳过最慢的 lint/typecheck（自查用）
//   node scripts/gate-close.mjs --list     # 只打印清单
//   node scripts/gate-close.mjs --selftest # 自证清单本身
// ============================================================================
import { spawnSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

/**
 * wiring 测试文件（门禁与接线测试；防虚高等判据只在测试里，不在门禁输出里）。
 * [2026-10-18 修正] 原匹配 `f.includes('Guard')` 大小写敏感，把 26 个 `*.guard.test.js`
 * （含 D89 wafExternalParity.guard / wafSamples.guard 等）漏在收口清单之外——它们只在
 * `cd server && npm test` 的全量里被兜底跑，gate:close 看不见。改成大小写不敏感，
 * 使“守卫类测试”与“wiring 类测试”全部被收口。基线从 16 个扩容到 40+ 个。
 */
function wiringTestFiles() {
  const dir = join(ROOT, 'server', 'tests');
  return readdirSync(dir)
    .filter((f) => {
      const lower = f.toLowerCase();
      return lower.endsWith('.test.js') && (lower.includes('guard') || lower.includes('wiring'));
    })
    .sort()
    .map((f) => join('server', 'tests', f));
}

const SLOW = new Set(['lint', 'typecheck']);

/**
 * 收口清单。顺序按「快 → 慢」，失败即停（与 CI 的 bash -e 语义一致）。
 * @returns {Array<{name:string, cmd:string[]}>}
 */
function closeGateList({ quick = false } = {}) {
  const guards = ['complexity', 'nesting', 'duplication', 'deadcode', 'debt', 'typecoverage'];
  const list = [
    { name: 'complexity', cmd: ['node', 'scripts/complexity-guard.mjs'] },
    ...guards.filter((g) => g !== 'complexity').map((g) => ({ name: g, cmd: ['node', `scripts/${g}-guard.mjs`] })),
    ...guards.map((g) => ({ name: `${g}:selftest`, cmd: ['node', `scripts/${g}-guard.mjs`, '--selftest'] })),
    { name: 'readme', cmd: ['node', 'scripts/readme-consistency.mjs'] },
    { name: 'readme:selftest', cmd: ['node', 'scripts/readme-consistency.mjs', '--selftest'] },
    { name: 'flag:selftest', cmd: ['node', 'scripts/readme-flag-coverage.mjs', '--selftest'] },
    // [D145 2026-10-24] greenguard 此前只在 CI lint 跑、收口清单没有它：D143 的
    // scripts/build-portable.mjs（失败退出委托给 failWith）被判 only-exit-0 恒绿，
    // 本地 gate:close 全绿、CI lint 红。判据本身已修（识别委托 helper）+ 自证，
    // 这里把两道都接进收口，避免同一形态第三次重演。
    { name: 'greenguard', cmd: ['node', 'scripts/greenguard-check.mjs'] },
    { name: 'greenguard:selftest', cmd: ['node', 'scripts/greenguard-check.mjs', '--selftest'] },
    { name: 'wiring', cmd: ['node', '--test', ...wiringTestFiles()] },
    { name: 'facts', cmd: ['npm', 'run', '--silent', 'facts:check'] },
    { name: 'refs', cmd: ['node', 'scripts/ref-integrity.mjs'] },
    { name: 'e2e-wiring', cmd: ['node', 'scripts/e2e-wiring-check.mjs'] },
    { name: 'e2e-wiring:selftest', cmd: ['node', 'scripts/e2e-wiring-check.mjs', '--selftest'] },
    // [D143 2026-10-23] 便携包两个脚本的自证。为什么必须进收口清单：它们是 D142 新增的交付
    // 链路判据（Tauri 命名约定 / manifest sha256 / 健康断言），而收口纪律是「新增门禁必须
    // 同时加到这里」——否则又会变成「只在某处能跑、收口看不见」。这里只跑 --selftest（不碰产物）：
    // 真冒烟需要壳与 sidecar 产物，属交付件链路，由 CI 的 desktop-package job 负责；
    // 本项保证**判据本身没空转**。
    { name: 'portable-build:selftest', cmd: ['node', 'scripts/build-portable.mjs', '--selftest'] },
    { name: 'portable-smoke:selftest', cmd: ['node', 'scripts/portable-smoke.mjs', '--selftest'] },
    // [D144 2026-10-23] 本机靶场体检判据的自证。验收 25/25 依赖 6 个外部服务，而「没起的靶场」
    // 在验收里只表现为 SKIP/BLOCKED（假绿温床）⇒ scripts/labs.mjs 把「哪些没起、为什么、
    // 要设哪个环境变量」变成一条命令。这里只跑 --selftest（纯函数，不探测也不起进程）。
    { name: 'labs:selftest', cmd: ['node', 'scripts/labs.mjs', '--selftest'] },
  ];
  if (quick) return list.filter((g) => !SLOW.has(g.name));
  return [...list, { name: 'typecheck', cmd: ['npm', 'run', '--silent', 'typecheck'] }, { name: 'lint', cmd: ['npm', 'run', '--silent', 'lint'] }];
}

// ── 自证：清单必须覆盖 AGENTS.md 约定的每一项，且 wiring 条目非空 ──────────────
function selftest() {
  const bad = [];
  const list = closeGateList();
  const names = list.map((g) => g.name);
  const must = ['typecheck', 'lint', 'wiring', 'facts', 'refs', 'readme', 'complexity', 'nesting', 'duplication', 'deadcode', 'debt', 'typecoverage', 'e2e-wiring', 'e2e-wiring:selftest', 'portable-build:selftest', 'portable-smoke:selftest', 'labs:selftest', 'greenguard', 'greenguard:selftest'];
  for (const m of must) if (!names.includes(m)) bad.push(`清单缺「${m}」（AGENTS.md §3 收口清单要求项）`);
  for (const g of ['complexity', 'nesting', 'duplication', 'deadcode', 'debt', 'typecoverage']) {
    if (!names.includes(`${g}:selftest`)) bad.push(`清单缺「${g}:selftest」（每道门禁都要自证）`);
  }
  const w = wiringTestFiles();
  if (w.length < 5) bad.push(`wiring 测试只匹配到 ${w.length} 个文件，匹配口径可能坏了（期望 ≥5）`);
  // 顺序：快的在前，slow 的两个在末尾
  const iLint = names.indexOf('lint');
  const iWire = names.indexOf('wiring');
  if (iLint >= 0 && iWire >= 0 && iLint < iWire) bad.push('顺序错：最慢的 lint 应排在 wiring 之后（失败早停要省时间）');

  if (bad.length) {
    console.error('[gate-close] ✗ 自证失败：');
    for (const b of bad) console.error('    · ' + b);
    process.exit(1);
  }
  console.log(`[gate-close] ✓ 自证通过：清单 ${list.length} 项（含 wiring ${w.length} 个测试文件），关键项齐全、顺序正确`);
}

const args = process.argv.slice(2);
if (args.includes('--selftest')) {
  selftest();
  process.exit(0);
}

const quick = args.includes('--quick');
const list = closeGateList({ quick });
if (args.includes('--list')) {
  for (const g of list) console.log(`  ${g.name.padEnd(24)} ${g.cmd.join(' ')}`);
  process.exit(0);
}

console.log(`[gate-close] 收口清单 ${list.length} 项${quick ? '（quick：跳过 lint/typecheck）' : ''}：`);
const rows = [];
let failed = 0;
for (const g of list) {
  const t0 = Date.now();
  const r = spawnSync(g.cmd[0], g.cmd.slice(1), { cwd: ROOT, stdio: 'pipe', encoding: 'utf8', shell: process.platform === 'win32' });
  const code = r.status ?? 1;
  const ms = Date.now() - t0;
  rows.push({ name: g.name, code, ms });
  const mark = code === 0 ? '✔' : '✖';
  console.log(`  ${mark} ${g.name.padEnd(24)} exit=${code} ${(ms / 1000).toFixed(1)}s`);
  if (code !== 0) {
    failed++;
    const out = `${r.stdout || ''}\n${r.stderr || ''}`.trim().split(/\r?\n/).slice(-12).join('\n');
    console.error(`    ── ${g.name} 输出尾部 ──\n${out}`);
    console.error('    （收口清单要求：修复到绿再提交；门禁绿 ≠ 判据对，但门禁红一定不能提交）');
    break; // 与 CI 的 bash -e 一致：失败即停
  }
}
console.log(`\n[gate-close] ${rows.length - failed}/${list.length} 项通过${failed ? ' —— 收口未完成' : ' —— 收口完成'}`);
process.exit(failed ? 1 : 0);