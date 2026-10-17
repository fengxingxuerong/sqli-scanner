// ============================================================================
// tests/complexityGuard.wiring.test.js —— 函数级复杂度门禁必须真的接上（D53）
//
// 与 nestingGuard.wiring.test.js 同族：每加一道门禁，必须同时加接线守卫，
// 断言它出现在 CI / pre-commit / ci-local / check:all / package.json 里。
// 缺了就等于没加 —— 本仓已两次栽在"判据写好了但没人执行"上。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readCode } from './_srcScan.mjs';
import { readFileSync } from 'node:fs';

const repo = (p) => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8');

// parseRunBodies：抽出 CI yaml 里每个 `- run:` 的命令体（与 nestingGuard.wiring 同款）。
const RUN_RE = /^([ \t]*)(?:-[ \t]+)*run:[ \t]*(\|[-+]?)?[ \t]*(.*)$/;
function parseRunBodies(yaml) {
  const out = [];
  const lines = yaml.split(/\r?\n/);
  let base = -1, body = [];
  for (const raw of lines) {
    const line = raw.replace(/\s+#.*$/, '');
    if (/^\s*#/.test(line) || !line.trim()) continue;
    const m = line.match(RUN_RE);
    if (m) {
      if (base >= 0) out.push(body.join('\n'));
      base = m[1].length;
      body = [m[3]];
      if (!m[2]) out.push(body.join('\n')), (base = -1), (body = []);
      continue;
    }
    if (base >= 0 && line.length > base && /^\s+\S/.test(line)) body.push(line.slice(base));
  }
  if (base >= 0) out.push(body.join('\n'));
  return out;
}

test('接线-1) CI workflow 必须执行 complexity-guard（检查 + 自证各一步）', () => {
  const yaml = repo('.github/workflows/ci.yml');
  const runs = parseRunBodies(yaml);
  assert.ok(runs.length > 0, '解析不到任何 run 步骤 —— 解析器本身有问题，先自证');

  const check = runs.filter((r) => /complexity-guard\.mjs\s*$/.test(r.trim()));
  const self = runs.filter((r) => /complexity-guard\.mjs\s+--selftest\s*$/.test(r.trim()));
  assert.equal(check.length, 1, `CI 应恰好有 1 步执行 complexity-guard 检查，实际 ${check.length} 步`);
  assert.equal(self.length, 1, 'CI 必须同时跑 --selftest（钉住"判据不空转"）');
});

test('接线-2) pre-commit 必须包含函数级复杂度门禁', () => {
  const hook = repo('.husky/pre-commit');
  assert.match(hook, /run_gate\s+"函数级复杂度[^"]*"\s+node\s+scripts\/complexity-guard\.mjs/,
    'pre-commit 里应有一条 run_gate 调用 complexity-guard');
});

test('接线-3) ci-local 清单必须包含函数级复杂度门禁（自证 + 检查）', () => {
  const src = repo('scripts/ci-local.mjs');
  assert.match(src, /complexity-guard\.mjs\s+--selftest/, 'ci-local 应含 selftest 项');
  assert.match(src, /cmd:\s*'node scripts\/complexity-guard\.mjs'/, 'ci-local 应含检查项');
});

test('接线-4) package.json 提供可单独调用的脚本，且 check:all 串入检查', () => {
  const pkg = JSON.parse(repo('package.json'));
  assert.equal(pkg.scripts['complexity:guard'], 'node scripts/complexity-guard.mjs');
  assert.equal(pkg.scripts['complexity:guard:selftest'], 'node scripts/complexity-guard.mjs --selftest');
  assert.equal(pkg.scripts['complexity:baseline'], 'node scripts/complexity-guard.mjs --fix-baseline');
  assert.ok(pkg.scripts['check:all'].includes('complexity:guard'),
    'check:all 必须串入 complexity:guard');
  assert.ok(pkg.scripts['check:all'].includes('complexity:guard:selftest'),
    'check:all 也应含 selftest（与 nesting:selftest 的既有做法一致）');
});

// ── 门禁脚本本身的形态守卫 ─────────────────────────────────────────────────
test('形态-5) 脚本不得在 import 时执行 CLI（否则 measureFunctions/judge 无法被测试导入）', () => {
  const code = readCode(new URL('../../scripts/complexity-guard.mjs', import.meta.url));
  assert.ok(
    /isMain[\s\S]*if\s*\(\s*isMain\s*\)/.test(code),
    '应先判断是否被直接执行再跑 CLI —— 无条件执行会让 import 杀掉测试进程'
  );
  assert.ok(
    !/^process\.exit\(main\(\)\);/m.test(code),
    '存在无条件的顶层 process.exit(main())，模块无法被安全 import'
  );
});

test('形态-6) 基线文件存在且结构合法（门禁不得因基线缺失而空转）', () => {
  const b = JSON.parse(repo('docs/_complexity-baseline.json'));
  assert.ok(b && typeof b === 'object', '基线应为对象');
  assert.ok(b.functions && typeof b.functions === 'object', '基线应含 functions 字段');
  const entries = Object.entries(b.functions);
  assert.ok(entries.length > 0, '基线不应为空（存量确有超软上限的函数）');
  for (const [k, d] of entries) {
    assert.equal(typeof d.lines, 'number', `${k} 的 lines 应为数字`);
    assert.equal(typeof d.complexity, 'number', `${k} 的 complexity 应为数字`);
    assert.ok(d.lines > 100 || d.complexity > 15,
      `${k} 既不超行数软上限也不超复杂度软上限，收进基线无意义`);
  }
});

test('形态-7) 基线里的每项都应被当前仓库"测到"（防基线虚高）', async () => {
  const b = JSON.parse(repo('docs/_complexity-baseline.json'));
  const { measureFunctions } = await import('../../scripts/complexity-guard.mjs');
  let checked = 0;
  for (const [key, d] of Object.entries(b.functions)) {
const sep = key.lastIndexOf('::');
    const file = key.slice(0, sep);
    const measured = measureFunctions([file]);
    const m = measured[key];
    assert.ok(m, `${key}：基线里有但当前代码测不到 —— 函数可能已改名或删除（基线腐烂）`);
    assert.ok(m.lines <= d.lines,
      `${key}：基线记 ${d.lines} 行，实际 ${m.lines} 行 —— 基线虚高（可下调）`);
    assert.ok(m.complexity <= d.complexity,
      `${key}：基线记复杂度 ${d.complexity}，实际 ${m.complexity} —— 基线虚高（可下调）`);
    checked++;
  }
  assert.ok(checked > 0, '应至少校验一项');
});