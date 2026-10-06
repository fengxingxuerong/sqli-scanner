// ============================================================================
// tests/preCommitGates.wiring.test.js —— pre-commit 的门禁接线必须自己被查到
// ============================================================================
// 本仓最反复的一格：**判据写好了，却没有任何东西保证它在开发机上真的被执行**。
// 已登记在案的形态：
//   · ci.yml 两个 job 引用不存在的入口 + continue-on-error ⇒ 那两个 job 从未验证过任何东西；
//   · `verify-dialect-templates.mjs` 文档写"退出码 0 = 全通过"，三天没进过任何清单；
//   · 灯塔/E2E 只手动跑过一次，产物入库但门禁清单里没有它。
//
// `.husky/pre-commit` 是同一族里最不起眼的一处：它坏掉（被改成只剩 lint-staged、
// 或某条 gate 被 `|| true` 吞掉）不会有任何报错——只是开发机少拦一道，
// 而现象要等到"某个只有本地才有的问题溜进提交"才显现。
//
// ── 本文件钉什么 ─────────────────────────────────────────────────────────────
//   ① 四条静态门禁都在钩子里，且**没有被 || true / continue-on-error 吞掉**；
//   ② 钩子引用的每个脚本都真实存在（否则 sh 会静默跳过或报错，取决于位置）；
//   ③ 逃生阀存在且仅检 SKIP_PRECOMMIT=1（不得变成"什么都能跳"）。
//
// ── 为什么还要 ④「只放廉价门禁」那条软约束 ──────────────────────────────────
// 它不判对错，只登记取舍依据：pre-commit 的价值全在"每次提交都愿意付"。
// 一旦有人往里塞需要数分钟的 coverage/全量 e2e，钩子就会被 --no-verify 常态化绕过，
// 于是四条秒级门禁也跟着一起失效——**退化是连带的**，所以要让它可见。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK = join(REPO, '.husky', 'pre-commit');
const hookSrc = readFileSync(HOOK, 'utf8');

/** 钩子里真正登记的门禁脚本（从 run_gate 调用行提取） */
function gateScripts() {
  const out = [];
  const re = /^run_gate\s+"[^"]*"\s+node\s+([^\s]+)/gm;
  let m;
  while ((m = re.exec(hookSrc)) !== null) out.push(m[1]);
  return out;
}

const gates = gateScripts();

test('接线-1) 钩子登记了预期的四条静态门禁（少一条即退化）', () => {
  const expected = [
    'scripts/arch-guard.mjs',
    'scripts/ref-integrity.mjs',
    'scripts/module-loadable.mjs',
    'scripts/version-sync.mjs',
  ];
  for (const s of expected) {
    assert.ok(gates.includes(s),
      `pre-commit 未登记 ${s}（实际登记：${JSON.stringify(gates)}）\n` +
      '钩子退化是连带的：少拦一道 ⇒ 有人加 --no-verify ⇒ 四条一起失效。');
  }
});

test('接线-2) 每条 gate 都真的被检查（不得被 || true 之类吞掉）', () => {
  // 逐行扫：每个 `run_gate ...` 调用行后面必须跟着 `|| exit 1`。
  // 不这样判会漏掉"看起来接上了、实际被吞"的形态 —— 那正是本仓栽过的那一格。
  const lines = hookSrc.split(/\r?\n/);
  let found = 0;
  for (const line of lines) {
    if (!/^\s*run_gate\s/.test(line)) continue;
    found++;
    assert.ok(/\|\|\s*exit\s+1\s*$/.test(line.trim()) || /&&\s*/.test(line),
      `这一行 run_gate 没有以 || exit 1 收尾，会放行失败：\n  ${line.trim()}`);
    assert.ok(!/\|\|\s*true\b/.test(line),
      `这条 gate 被 || true 吞掉了（失败不阻止提交）：\n  ${line.trim()}`);
  }
  assert.ok(found >= 4, `钩子里只找到 ${found} 条 run_gate，预期 ≥4`);
});

test('接线-3) 钩子引用的每个脚本都真实存在（sh 找不到时行为不可预期）', () => {
  for (const s of gates) {
    assert.ok(existsSync(join(REPO, s)), `pre-commit 引用了不存在的脚本：${s}`);
  }
});

test('接线-4) lint-staged 仍在钩子里（不能被新增门禁挤掉）', () => {
  assert.ok(/npx\s+lint-staged/.test(hookSrc), 'pre-commit 不再跑 lint-staged —— 原有行为被挤掉了');
});

test('接线-5) 逃生阀存在、显式等于 1 才生效（不得放宽成任意真值）', () => {
  // 有逃生阀是必要的（明知会红时需要能落盘）；但必须窄——
  // 变成"什么都能跳"等于把四条门禁一次性作废。
  assert.ok(/SKIP_PRECOMMIT/.test(hookSrc), '钩子没有逃生阀，明知误报时无法落盘');

  // 语义检查（不靠拼字符串猜转义）：钩子必须**同时**满足
  //   ① 用 `:-` 默认值语法取值 ⇒ 未设置时有确定的空值；
  //   ② 与字面量 "1" 作**相等**比较 ⇒ 只有显式 =1 才跳过。
  // 写成 `-n "$SKIP_PRECOMMIT"` / `-eq 1` 等形态都会放宽到任意真值，必须变红。
  const usesDefault = /\$\{SKIP_PRECOMMIT:-[^}]*\}/.test(hookSrc);
  assert.ok(usesDefault,
    '未用 ${SKIP_PRECOMMIT:-...} 取值 —— 改成 `if [ -n "$SKIP_PRECOMMIT" ]` 会把任意非空值都当跳过');

  const strictEq = /\[\s*"\$\{SKIP_PRECOMMIT[^}]*\}"\s*=\s*"1"\s*\]/.test(hookSrc);
  assert.ok(strictEq,
    '未用与字面量 "1" 的相等比较 —— 逃生阀被放宽成任意真值，四条门禁可被一次赋值全部作废');

  // 不得出现"默认跳过"分支
  assert.ok(!/默认为开|默认跳过|默认即跳过/.test(hookSrc), '逃生阀疑似默认为开');
});

test('接线-6) 不得把慢门禁塞进 pre-commit（取舍依据须可见）', () => {
  // 软约束：这些是分钟级判据，进了钩子必然被 --no-verify 绕过。
  const heavy = ['vitest', 'test:coverage', 'cargo clippy', 'ci-local', 'run-all.mjs', 'npm audit'];
  for (const h of heavy) {
    assert.ok(!gates.some((g) => g.includes(h)),
      `pre-commit 里出现了重门禁 ${h} —— 它会让整个钩子被 --no-verify 常态化绕过`);
  }
});
