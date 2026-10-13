// ============================================================================
// server/tests/crossModuleE2E.wiring.test.js —— 跨模块 E2E 接线守卫（模块 7.6）
// ============================================================================
// 验证 e2e/cross-module-lab/run.e2e.mjs 存在且引用的测试文件全部真实存在。
// 这是「写了 E2E 但文件路径漂移」的防回归——对标 acceptanceExpect.wiring.test.js。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..');

test('cross-module E2E 脚本存在', () => {
  const p = resolve(REPO, 'e2e/cross-module-lab/run.e2e.mjs');
  assert.ok(existsSync(p), 'e2e/cross-module-lab/run.e2e.mjs 应存在');
});

test('cross-module E2E 引用的测试文件全部存在', () => {
  const p = resolve(REPO, 'e2e/cross-module-lab/run.e2e.mjs');
  const src = readFileSync(p, 'utf8');
  const matches = [...src.matchAll(/'(server\/tests\/[^']+)'/g)];
  assert.ok(matches.length > 0, '应至少引用一个测试文件');
  for (const m of matches) {
    const fullPath = resolve(REPO, m[1]);
    assert.ok(existsSync(fullPath), `引用的测试文件应存在: ${m[1]}`);
  }
});

test('cross-module E2E 覆盖 5 个场景', () => {
  const p = resolve(REPO, 'e2e/cross-module-lab/run.e2e.mjs');
  const src = readFileSync(p, 'utf8');
  const ids = [...src.matchAll(/id:\s*'([^']+)'/g)].map((m) => m[1]);
  assert.ok(ids.length >= 5, `应至少 5 个场景，实际 ${ids.length}`);
  const expected = ['7.1', '7.2', '7.3', '7.4', '7.5'];
  for (const ex of expected) {
    assert.ok(ids.some((id) => id.startsWith(ex)), `应包含场景 ${ex}`);
  }
});