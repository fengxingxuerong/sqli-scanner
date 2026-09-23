// ============================================================================
// server/tests/ciWiring.guard.test.js —— 「e2e 测试写了但没接线」守卫
//
// 为什么必须有（本仓已踩过多次）：
//   `e2e/**/*.test.mjs` **不在** test-server(`server/tests`) / test-frontend(`src/tests`)
//   的发现范围里 —— 想让它跑，必须在 `.github/workflows/ci.yml` 与 `scripts/ci-local.mjs`
//   里**各**写一行 `node --test "<glob>"`。只写一处 = 另一处空转；两处都不写时，
//   文件静静躺着、永远不会跑第二次：**没有红，也没有提示**。
//   2026-09-23 核实时全仓只有 1 个此类文件（`e2e/lib/suiteVerdict.test.mjs`）——
//   此刻补守卫成本最低：需要登记的"存量缺口"为空，守卫天然是双向的。
//
// 判据（三向，缺一不可）：
//   ① 覆盖：每个真实存在的 e2e 测试文件，必须在 ci.yml **与** ci-local.mjs 里各被
//      一个 `node --test` 模式命中；
//   ② 不空转：两处声明的每个 e2e 模式必须至少命中 1 个真实文件 —— 否则那行门禁
//      「声称在跑测试」却一个也不存在（2026-09-20 那两个指向不存在文件的 job 就是这形态）；
//   ③ 自证：先钉住 mode→RegExp 的转换语义 + 断言文件集合非空，避免①② 因为
//      「守卫自己解析写错」而假绿（本项目反复出现的"守卫看不见它声称在管的东西"）。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');

const E2E_DIR = path.join(REPO, 'e2e');
const CI_YML = path.join(REPO, '.github', 'workflows', 'ci.yml');
const CI_LOCAL = path.join(REPO, 'scripts', 'ci-local.mjs');

/** 递归收集 e2e 下的 *.test.mjs，返回仓库根相对、posix 分隔的路径。 */
function listE2eTests(dir = E2E_DIR, out = []) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    if (ent.name === 'node_modules' || ent.name.startsWith('.')) continue;
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) listE2eTests(full, out);
    else if (ent.name.endsWith('.test.mjs')) out.push(path.relative(REPO, full).split(path.sep).join('/'));
  }
  return out.sort();
}

/**
 * 从文本里抽 `node --test <args>` 的 e2e 相关模式。
 * 关键点：引号优先取 token —— ci-local.mjs 是 JS 源码，模式后面还跟着 `',`
 * （形如 `cmd: 'node --test "e2e/lib/*.test.mjs"'`），不优先吃引号会把尾巴带进来。
 */
function extractE2eTestGlobs(text) {
  const out = [];
  for (const m of text.matchAll(/--test\b([^\n\r]*)/g)) {
    for (const raw of m[1].match(/"[^"]*"|'[^']*'|[^\s,]+/g) ?? []) {
      const tok = raw.replace(/^["']|["']$/g, '');
      if (!tok.includes('e2e/')) continue; // 只关心 e2e 侧的接线
      if (/[\s"'`]/.test(tok)) continue; // 尾巴没清干净的一律不认，宁可漏也不误判
      out.push(tok);
    }
  }
  return [...new Set(out)];
}

/** 把 `--test` 支持的 glob 转成锚定正则；`*` 不跨 `/`，`**` 跨。 */
function globToRegExp(glob) {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const pattern = escaped.replace(/\*\*/g, '\u0000').replace(/\*/g, '[^/]*').replace(/\u0000/g, '.*');
  return new RegExp(`^${pattern}$`);
}

const CI_YML_GLOBS = extractE2eTestGlobs(readFileSync(CI_YML, 'utf8'));
const CI_LOCAL_GLOBS = extractE2eTestGlobs(readFileSync(CI_LOCAL, 'utf8'));
const E2E_TESTS = listE2eTests();

test('自证：glob→RegExp 转换语义正确（否则下面的"无命中"可能是守卫自己的锅）', () => {
  assert.equal(globToRegExp('e2e/lib/*.test.mjs').test('e2e/lib/suiteVerdict.test.mjs'), true);
  assert.equal(globToRegExp('e2e/lib/*.test.mjs').test('e2e/waf-real/x.test.mjs'), false, '`*` 不得跨目录');
  assert.equal(globToRegExp('e2e/lib/*.test.mjs').test('e2e/lib/suiteVerdict.mjs'), false);
  assert.equal(globToRegExp('e2e/**/*.test.mjs').test('e2e/a/b/c.test.mjs'), true, '`**` 应跨目录');
  assert.equal(globToRegExp('e2e/lib/suiteVerdict.test.mjs').test('e2e/lib/suiteVerdict.test.mjs'), true, '具体路径也要能命中');
  assert.equal(globToRegExp('e2e/lib/*.test.mjs').test('e2e/lib/aXtestXmjs'), false, '`.` 应被转义');
});

test('自证：两侧都解析到了 e2e 接线，且 e2e 下确有测试文件（防空转）', () => {
  assert.ok(CI_YML_GLOBS.length > 0, `未从 ${path.relative(REPO, CI_YML)} 解析到任何 e2e 的 node --test 模式（解析逻辑或接线变更需同步）`);
  assert.ok(CI_LOCAL_GLOBS.length > 0, `未从 ${path.relative(REPO, CI_LOCAL)} 解析到任何 e2e 的 node --test 模式`);
  assert.ok(E2E_TESTS.length > 0, 'e2e 下应有至少一个 *.test.mjs —— 若真的全删了，请连同本守卫一起删');
});

test('① 覆盖：每个 e2e 测试文件都必须在 ci.yml 与 ci-local.mjs 两侧接线', () => {
  const sites = [
    { label: '.github/workflows/ci.yml', globs: CI_YML_GLOBS },
    { label: 'scripts/ci-local.mjs', globs: CI_LOCAL_GLOBS },
  ];
  const missing = [];
  for (const file of E2E_TESTS) {
    for (const site of sites) {
      if (!site.globs.some((g) => globToRegExp(g).test(file))) missing.push(`${site.label} 未接线  ${file}`);
    }
  }
  assert.deepEqual(
    missing,
    [],
    `发现 ${missing.length} 处未接线的 e2e 测试（写了但永远不会跑第二次）：\n  ${missing.join('\n  ')}\n` +
      '修法：在两侧各加/扩一行 `node --test "<glob>"`（必须 glob，不能传目录 —— Node 会把目录当待 require 的模块）。',
  );
});

test('② 不空转：两侧声明的每个 e2e 模式都必须至少命中 1 个真实文件', () => {
  const sites = [
    { label: '.github/workflows/ci.yml', globs: CI_YML_GLOBS },
    { label: 'scripts/ci-local.mjs', globs: CI_LOCAL_GLOBS },
  ];
  const inert = [];
  for (const site of sites) {
    for (const g of site.globs) {
      const re = globToRegExp(g);
      if (!E2E_TESTS.some((f) => re.test(f))) inert.push(`${site.label}: "${g}"`);
    }
  }
  assert.deepEqual(
    inert,
    [],
    `发现 ${inert.length} 条空转接线（声称在跑测试，实际匹配 0 个文件）：\n  ${inert.join('\n  ')}\n` +
      '这类门禁永远不会红 —— 要么修正模式，要么删掉该行。',
  );
});
