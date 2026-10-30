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
// [D178 2026-10-26] 清单本身外移到 `scripts/lib/gate-list.mjs`：
// 质量台账要展示「当前多少项门禁」，复制一份清单必然漂移 ⇒ 一份清单、两个消费者
// （本脚本执行、quality-ledger 展示）。改清单请只改那个文件。
//
// 用法：
//   node scripts/gate-close.mjs            # 跑全清单
//   node scripts/gate-close.mjs --quick    # 跳过最慢的 lint/typecheck（自查用）
//   node scripts/gate-close.mjs --list     # 只打印清单
//   node scripts/gate-close.mjs --selftest # 自证清单本身
// ============================================================================
import { spawnSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { closeGateList, wiringTestFiles } from './lib/gate-list.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');

// ── 自证：清单必须覆盖 AGENTS.md 约定的每一项，且 wiring 条目非空 ──────────────
function selftest() {
  const bad = [];
  const list = closeGateList({ root: ROOT });
  const names = list.map((g) => g.name);
  const must = ['typecheck', 'lint', 'wiring', 'facts', 'refs', 'readme', 'complexity', 'nesting', 'duplication', 'deadcode', 'debt', 'typecoverage', 'e2e-wiring', 'e2e-wiring:selftest', 'portable-build:selftest', 'portable-smoke:selftest', 'labs:selftest', 'greenguard', 'greenguard:selftest', 'agent-manifest', 'agent-manifest:selftest', 'quality-ledger', 'quality-ledger:selftest', 'recipes', 'recipes:selftest', 'pack-check', 'pack-check:selftest'];
  for (const m of must) if (!names.includes(m)) bad.push(`清单缺「${m}」（AGENTS.md §3 收口清单要求项）`);
  for (const g of ['complexity', 'nesting', 'duplication', 'deadcode', 'debt', 'typecoverage']) {
    if (!names.includes(`${g}:selftest`)) bad.push(`清单缺「${g}:selftest」（每道门禁都要自证）`);
  }
  const w = wiringTestFiles(ROOT);
  if (w.length < 5) bad.push(`wiring 测试只匹配到 ${w.length} 个文件，匹配口径可能坏了（期望 ≥5）`);
  // 顺序：快的在前，slow 的两个在末尾
  const iLint = names.indexOf('lint');
  const iWire = names.indexOf('wiring');
  if (iLint >= 0 && iWire >= 0 && iLint < iWire) bad.push('顺序错：最慢的 lint 应排在 wiring 之后（失败早停要省时间）');
  // D178：清单里不允许出现重名（台账与执行都以 name 为键）
  if (new Set(names).size !== names.length) bad.push('清单里有重名项（name 必须唯一）');

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
const list = closeGateList({ root: ROOT, quick });
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
