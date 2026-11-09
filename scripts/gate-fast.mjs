#!/usr/bin/env node
// ============================================================================
// gate-fast.mjs —— 批内快门禁（D280，批次迭代用的**分层第一档**）
// ============================================================================
// 分层全景（为什么三个档都不互相替代）：
//   pre-commit   ≤1.2s   提交闸：纯静态五件套 + lint-staged（取舍标准见该文件头注）
//   gate:fast    ≤2.5min 批内闸（本脚本）：恒跑组（全仓静态判据）+ 受影响组（按改动推导）
//   gate:close   ~25min  收口闸：54+1 项全量，提级/提交前的最终authority——**它不可被本脚本替代**
//
// 为什么受影响组要自动推导而不是手抄命令：D279 实测，人手挑「受影响测试」必漏
// （csrfKeeper 重构波及 scanClient.branches，肉眼没料到）。推导规则是纯函数
// （scripts/lib/gateFastPlan.mjs），自证里钉死了映射行为与恒跑组不空转。
//
// 用法：
//   npm run gate:fast                    # 自动从 git 收集改动
//   node scripts/gate-fast.mjs --files server/src/core/csrfKeeper.js,server/tests/csrfKeeper.test.js
//   node scripts/gate-fast.mjs --list    # 只打印计划（恒跑 + 受影响 + 警告）
//   node scripts/gate-fast.mjs --selftest
// ============================================================================
import { spawnSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ALWAYS_MIN, alwaysSteps, collectChangedFiles, affectedSteps } from './lib/gateFastPlan.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
/** 快门禁预算（秒）：超过只打标不判红——机器差异不该把「快」变成一道会红的门禁 */
const BUDGET_SECONDS = 150;

/** 跑一步：真实退出码就是判据（不采信 stdout 自报） */
function runStep(cmd) {
  const r = spawnSync(cmd[0], cmd.slice(1), {
    cwd: ROOT, stdio: 'pipe', encoding: 'utf8', shell: process.platform === 'win32',
    maxBuffer: 64 * 1024 * 1024,
  });
  return { code: r.status ?? 1, out: `${r.stdout || ''}\n${r.stderr || ''}` };
}

function buildPlan(files) {
  const always = alwaysSteps(ROOT);
  const { affected, warnings } = affectedSteps(ROOT, files);
  return { always, affected, warnings };
}

/**
 * ⑧ 自证映射只认入口、不认命令字符串（D280 收口实测的两个真实反例，活体判牙）：
 *    ci-local.mjs 存了一堆 `--selftest` 命令字符串却没有入口 ⇒ 误映射会拉起全量 CI；
 *    gateFastPlan.mjs 是库模块，同样没有入口 ⇒ 误映射是「顶层零断言 exit 0」的恒绿假自证。
 * @param {string[]} bad 失败原因收集器
 */
function checkNoFalseSelftest(bad) {
  for (const [f, why] of [
    ['scripts/ci-local.mjs', '把整套 CI 当成一步自证拉起来'],
    ['scripts/lib/gateFastPlan.mjs', '恒绿假自证'],
  ]) {
    const p = buildPlan([f]);
    if (p.affected.some((x) => x.cmd.includes('--selftest'))) bad.push(`${f} 被误映射为 --selftest（${why}）`);
    if (!p.warnings.some((w) => w.includes(f))) bad.push(`${f} 缺自证入口却没有警告（静默跳过 = 假绿通道）`);
  }
}

// ── 自证：映射行为、不变式、退出码传播、恒跑组不空转 ──────────────────────────
function selftest() {
  const bad = [];
  // ① 恒跑组不空转：空改动集也必须 ≥ ALWAYS_MIN 项
  const empty = buildPlan([]);
  if (empty.always.length < ALWAYS_MIN) bad.push(`恒跑组只有 ${empty.always.length} 项（不变式要求 ≥${ALWAYS_MIN}）`);
  // ② 空改动集：受影响组必须给出文档一致性检查（facts/readme），不能既恒跑又无受影响地「静默全绿」
  if (!empty.affected.some((s) => s.cmd.includes('facts:check'))) bad.push('空改动集的受影响组没有文档一致性检查（空跑 = 门禁变装饰）');
  // ③ src → 测试映射：csrfKeeper 必须映射到它的直接测试（D279 真实批次回放）
  const m = buildPlan(['server/src/core/csrfKeeper.js']);
  const mTests = m.affected.find((s) => s.name === 'tests:src-mapped');
  if (!mTests || !mTests.cmd.some((c) => String(c).includes('csrfKeeper'))) {
    bad.push('csrfKeeper.js 未映射到任何 csrfKeeper 测试——src 映射口径坏了');
  }
  if (!m.affected.some((s) => s.name === 'typecheck:server')) bad.push('server/src 改动未触发 typecheck:server');
  // ④ 直接改测试文件 → 原样进计划
  const t = buildPlan(['server/tests/someNew.guard.test.js']);
  const tStep = t.affected.find((s) => s.name === 'tests:direct');
  if (!tStep || !tStep.cmd.some((c) => String(c).endsWith('someNew.guard.test.js'))) bad.push('直接改动的测试文件没有原样进计划');
  // ⑤ 无测试映射的 src 改动必须出警告（不许静默跳过）
  const u = buildPlan(['server/src/core/noTestCoversThisXYZ987.js']);
  if (!u.warnings.some((w) => w.includes('noTestCoversThisXYZ987'))) bad.push('无映射的 src 改动没有产生警告（静默跳过 = 假绿通道）');
  // ⑥ 退出码传播：判据是子进程真实退出码
  if (runStep(['node', '-e', 'process.exit(3)']).code !== 3) bad.push('runStep 未透传子进程退出码 3');
  if (runStep(['node', '-e', 'process.exit(0)']).code !== 0) bad.push('runStep 对退出码 0 判错');
  // ⑦ scripts 改动 → 自身的 --selftest
  const s = buildPlan(['scripts/gate-fast.mjs']);
  if (!s.affected.some((x) => x.name === 'selftest:gate-fast.mjs')) bad.push('scripts 改动未映射到自身 --selftest');
  checkNoFalseSelftest(bad);

  if (bad.length) {
    console.error('[gate-fast] ✗ 自证失败：');
    for (const b of bad) console.error('    · ' + b);
    process.exit(1);
  }
  console.log(`[gate-fast] ✓ 自证通过：恒跑 ${empty.always.length} 项不空转、映射/警告/入口反例/退出码传播判据齐全`);
}

const args = process.argv.slice(2);
if (args.includes('--selftest')) { selftest(); process.exit(0); }

// ── 计划 ────────────────────────────────────────────────────────────────────
const filesArg = args.find((a) => a.startsWith('--files'));
let files = filesArg
  ? filesArg.replace('--files', '').replace(/^=/, '').split(',').map((s) => s.trim()).filter(Boolean)
  : collectChangedFiles(ROOT);

// 未跟踪文件在 porcelain 里是 `?? path`，diff --name-only 无输出——collect 已并集；
// 若两条路都空且没有 --files，说明工作区干净：仍然跑恒跑组（回归防护），只是受影响组为空。
if (!args.includes('--list')) {
  console.log(`[gate-fast] 改动文件 ${files.length} 个${files.length ? '：' + files.slice(0, 8).join(', ') + (files.length > 8 ? ' …' : '') : '（工作区干净 ⇒ 只跑恒跑组）'}`);
}
const { always, affected, warnings } = buildPlan(files);

if (args.includes('--list')) {
  console.log('── 恒跑组 ──');
  for (const s of always) console.log(`  ${s.name.padEnd(22)} ${s.cmd.join(' ')}`);
  console.log('── 受影响组 ──');
  for (const s of affected) console.log(`  ${s.name.padEnd(22)} ${s.cmd.join(' ')}`);
  if (warnings.length) { console.log('── 警告 ──'); for (const w of warnings) console.log('  ⚠ ' + w); }
  process.exit(0);
}

// ── 执行：恒跑组在前（最便宜 + 抓跨文件），受影响组随后；失败即停 ─────────────
for (const w of warnings) console.log(`[gate-fast] ⚠ ${w}`);
const steps = [...always, ...affected];
console.log(`[gate-fast] 计划 ${steps.length} 步（恒跑 ${always.length} + 受影响 ${affected.length}）`);
const t0 = Date.now();
let failed = 0;
let done = 0;
for (const s of steps) {
  const st = Date.now();
  const { code, out } = runStep(s.cmd);
  done++;
  const mark = code === 0 ? '✔' : '✖';
  console.log(`  ${mark} ${s.name.padEnd(22)} exit=${code} ${((Date.now() - st) / 1000).toFixed(1)}s`);
  if (code !== 0) {
    failed++;
    console.error(`    ── ${s.name} 输出尾部 ──\n${out.trim().split(/\r?\n/).slice(-12).join('\n')}`);
    console.error('    （快门禁红 = 先修再提交；它不替代 gate:close，只是把等全量的时间提前变成修复时间）');
    break;
  }
}
const elapsed = (Date.now() - t0) / 1000;
console.log(`\n[gate-fast] ${done - failed}/${steps.length} 步通过，${elapsed.toFixed(1)}s${failed ? ' —— 快门禁未过' : ' —— 快门禁通过（收口仍以 gate:close 为准）'}`);
if (elapsed > BUDGET_SECONDS) {
  console.log(`[gate-fast] ⚠ 超预算：${elapsed.toFixed(1)}s > ${BUDGET_SECONDS}s（只打标不判红；若常态化超时，检查恒跑组是否混进了慢判据）`);
}
process.exit(failed ? 1 : 0);
