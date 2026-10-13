// ============================================================================
// tests/typecoverageGuard.wiring.test.js —— JSDoc 类型覆盖门禁必须真的接上（D55）
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

test('接线-1) CI workflow 必须执行 typecoverage-guard（检查 + 自证各一步）', () => {
  const yaml = repo('.github/workflows/ci.yml');
  const runs = parseRunBodies(yaml);
  assert.ok(runs.length > 0, '解析不到任何 run 步骤');

  const check = runs.filter((r) => /typecoverage-guard\.mjs\s*$/.test(r.trim()));
  const self = runs.filter((r) => /typecoverage-guard\.mjs\s+--selftest\s*$/.test(r.trim()));
  assert.equal(check.length, 1, `CI 应恰好有 1 步执行 typecoverage-guard 检查，实际 ${check.length} 步`);
  assert.equal(self.length, 1, 'CI 必须同时跑 --selftest');
});

test('接线-2) pre-commit 必须包含 JSDoc 类型覆盖门禁', () => {
  const hook = repo('.husky/pre-commit');
  assert.match(hook, /run_gate\s+"JSDoc 类型覆盖[^"]*"\s+node\s+scripts\/typecoverage-guard\.mjs/,
    'pre-commit 里应有一条 run_gate 调用 typecoverage-guard');
});

test('接线-3) ci-local 清单必须包含 JSDoc 类型覆盖门禁（自证 + 检查）', () => {
  const src = repo('scripts/ci-local.mjs');
  assert.match(src, /typecoverage-guard\.mjs\s+--selftest/, 'ci-local 应含 selftest 项');
  assert.match(src, /cmd:\s*'node scripts\/typecoverage-guard\.mjs'/, 'ci-local 应含检查项');
});

test('接线-4) package.json 提供可单独调用的脚本，且 check:all 串入检查', () => {
  const pkg = JSON.parse(repo('package.json'));
  assert.equal(pkg.scripts['typecoverage:guard'], 'node scripts/typecoverage-guard.mjs');
  assert.equal(pkg.scripts['typecoverage:guard:selftest'], 'node scripts/typecoverage-guard.mjs --selftest');
  assert.equal(pkg.scripts['typecoverage:baseline'], 'node scripts/typecoverage-guard.mjs --fix-baseline');
  assert.ok(pkg.scripts['check:all'].includes('typecoverage:guard'),
    'check:all 必须串入 typecoverage:guard');
  assert.ok(pkg.scripts['check:all'].includes('typecoverage:guard:selftest'),
    'check:all 也应含 selftest');
});

test('形态-5) 脚本不得在 import 时执行 CLI', () => {
  const code = readCode(new URL('../../scripts/typecoverage-guard.mjs', import.meta.url));
  assert.ok(
    /isMain[\s\S]*if\s*\(\s*isMain\s*\)/.test(code),
    '应先判断是否被直接执行再跑 CLI'
  );
});

test('形态-6) 基线文件存在且结构合法', () => {
  const b = JSON.parse(repo('docs/_typecoverage-baseline.json'));
  assert.ok(b && typeof b === 'object', '基线应为对象');
  assert.ok(b.batches && typeof b.batches === 'object', '基线应含 batches 字段');
  const entries = Object.entries(b.batches);
  assert.ok(entries.length > 0, '基线不应为空');
  for (const [batch, d] of entries) {
    assert.equal(typeof d.coverage, 'number', `${batch} 的 coverage 应为数字`);
    assert.ok(d.coverage >= 0 && d.coverage <= 100, `${batch} coverage 应在 [0,100]`);
  }
});