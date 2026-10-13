// ============================================================================
// tests/deadcodeGuard.wiring.test.js —— 死代码门禁必须真的接上（D58）
//
// 与 duplicationGuard.wiring.test.js 同族：每加一道门禁，必须同时加接线守卫，
// 断言它出现在 CI / pre-commit / ci-local / check:all / package.json 里。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readCode } from './_srcScan.mjs';
import { readFileSync } from 'node:fs';

const repo = (p) => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8');

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

test('接线-1) CI workflow 必须执行 deadcode-guard（检查 + 自证各一步）', () => {
  const yaml = repo('.github/workflows/ci.yml');
  const runs = parseRunBodies(yaml);
  assert.ok(runs.length > 0, '解析不到任何 run 步骤 —— 解析器本身有问题，先自证');

  const check = runs.filter((r) => /deadcode-guard\.mjs\s*$/.test(r.trim()));
  const self = runs.filter((r) => /deadcode-guard\.mjs\s+--selftest\s*$/.test(r.trim()));
  assert.equal(check.length, 1, `CI 应恰好有 1 步执行 deadcode-guard 检查，实际 ${check.length} 步`);
  assert.equal(self.length, 1, 'CI 必须同时跑 --selftest（钉住"判据不空转"）');
});

test('接线-2) pre-commit 必须包含死代码门禁', () => {
  const hook = repo('.husky/pre-commit');
  assert.match(hook, /run_gate\s+"死代码[^"]*"\s+node\s+scripts\/deadcode-guard\.mjs/,
    'pre-commit 里应有一条 run_gate 调用 deadcode-guard');
});

test('接线-3) ci-local 清单必须包含死代码门禁（自证 + 检查）', () => {
  const src = repo('scripts/ci-local.mjs');
  assert.match(src, /deadcode-guard\.mjs\s+--selftest/, 'ci-local 应含 selftest 项');
  assert.match(src, /cmd:\s*'node scripts\/deadcode-guard\.mjs'/, 'ci-local 应含检查项');
});

test('接线-4) package.json 提供可单独调用的脚本，且 check:all 串入自证', () => {
  const pkg = JSON.parse(repo('package.json'));
  assert.equal(pkg.scripts['deadcode:guard'], 'node scripts/deadcode-guard.mjs');
  assert.equal(pkg.scripts['deadcode:guard:selftest'], 'node scripts/deadcode-guard.mjs --selftest');
  assert.equal(pkg.scripts['deadcode:baseline'], 'node scripts/deadcode-guard.mjs --fix-baseline');
  assert.ok(pkg.scripts['check:all'].includes('deadcode:guard:selftest'),
    'check:all 必须串入 deadcode:guard:selftest');
});

test('形态-5) 脚本不得在 import 时执行 CLI（否则 findUnusedExports/judge 无法被测试导入）', () => {
  const code = readCode(new URL('../../scripts/deadcode-guard.mjs', import.meta.url));
  assert.ok(
    /isMain[\s\S]*if\s*\(\s*isMain\s*\)/.test(code),
    '应先判断是否被直接执行再跑 CLI —— 无条件执行会让 import 杀掉测试进程'
  );
});

test('形态-6) 基线文件存在且结构合法（门禁不得因基线缺失而空转）', () => {
  const b = JSON.parse(repo('docs/_deadcode-baseline.json'));
  assert.ok(b && typeof b === 'object', '基线应为对象');
  assert.ok(b.symbols && typeof b.symbols === 'object', '基线应含 symbols 对象字段');
  const keys = Object.keys(b.symbols);
  assert.ok(keys.length > 0, '基线不应为空（存量确有未使用导出）');
  for (const k of keys) {
    const v = b.symbols[k];
    assert.ok(v.reason, `基线条目 ${k} 必须有 reason`);
    assert.ok(v.status, `基线条目 ${k} 必须有 status`);
  }
});