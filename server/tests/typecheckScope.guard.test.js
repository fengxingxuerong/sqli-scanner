// ============================================================================
// server/tests/typecheckScope.guard.test.js —— 守卫「前端测试文件在不在类型检查范围内」
//
// 为什么必须有（2026-10-09，批次 D26 的实测）：
//   `tsconfig.json` 的 include 是 `src`、**exclude 是 `src/tests`**，而 vitest 走 esbuild
//   转译、不做类型判定 ⇒ 64 个前端测试文件**从没被任何静态检查看过**。
//   一打开就暴 45 处漂移，其中三类是"测试还在跑、但已经不测它声称测的东西"：
//     · 12 处 `expect(x).toBe(v, '说明')` —— vitest 只认第一个参数，那些解释文字从未出现
//       （实测两个哨兵：`expect(v,msg)` 会打印，`.toBe(v,msg)` 不会）；
//     · ScanWizard 夹具缺组件后来新增的必填 props（onPause/onResume），还多传了两个
//       早已不存在的 prop（report / scanId）—— 全靠 makeProps 返回宽松类型没报；
//     · ProgressView 用引擎根本不会发的事件类型 `'detect'` 和 `points:[{},{},{}]` 喂组件。
//   本条守卫防的是"这份覆盖又被谁关掉"：exclude 是一行配置，删掉门禁只需要一次顺手改动。
//
// 判据（双向 + 分母）：
//   ① 每个入库的前端代码/测试文件（src/**、vitest.setup.ts）必须至少被仓库里**某一份**
//      根级 tsconfig 的类型检查覆盖 —— 允许多份（主配置管产物、tests 配置管测试），
//      但合起来不许有洞；
//   ② `typecheck` 组合脚本必须真的把每一份都跑上，且 CI 与 ci-local 两侧都有对应步骤
//      （只写一处 = 另一处空转，见 ciWiring.guard.test.js 的同款教训）；
//   ③ 分母：被覆盖的文件数必须成规模，防止 include 被改成空集后恒绿；解析失败必须显式红，
//      不许 catch 掉当"没洞"。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const NUL = String.fromCharCode(0);

const CODE_FILE = /\.(ts|tsx|js|jsx)$/;
// 需要被类型检查覆盖的前端范围
const MUST_COVER = (f) => f.startsWith('src/') || f === 'vitest.setup.ts';

let tracked = [];
let gitSkip = false;
try {
  tracked = execFileSync('git', ['-C', REPO, 'ls-files', '-z'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  }).split(NUL).filter(Boolean);
} catch (e) {
  gitSkip = 'git ls-files 不可用：' + (e && e.message ? e.message : String(e));
}

/** tsconfig 是 JSONC：这里只处理"整行 // 注释"这一种（本仓配置的实际用法）。 */
function readJsonc(rel) {
  const raw = readFileSync(path.join(REPO, rel), 'utf8');
  const stripped = raw
    .split('\n')
    .filter((l) => !l.trim().startsWith('//'))
    .join('\n');
  try {
    return JSON.parse(stripped);
  } catch (e) {
    // 静默跳过 = 洞。解析不了就红，让人来改判据。
    // （本文件曾被 D25 抬起来的 `preserve-caught-error` 抓到：rethrow 不带 cause 会把
    //   JSON.parse 的原始位置信息丢掉 —— 那条规则第一次就落在了作者自己新写的代码上。）
    throw new Error(`${rel} 解析失败（判据无法确认它的覆盖范围）：${e.message}`, { cause: e });
  }
}

function tsconfigs() {
  return tracked.filter((f) => /^tsconfig[^/]*\.json$/.test(f));
}

/** 一条 include/exclude 前缀是否管到这个文件（`src` 视作 `src/`）。 */
function coversEntry(entry, file) {
  if (typeof entry !== 'string') return false;
  if (entry === '*') return true;
  const base = entry.replace(/\/\*\*$/, '').replace(/\*\*$/, '');
  if (base.endsWith('/')) return file.startsWith(base);
  return file === base || file.startsWith(base + '/');
}

function coveredBy(cfg, cfgDir, file) {
  const rel = path.relative(cfgDir || '.', file).split(path.sep).join('/');
  const target = rel.startsWith('..') ? file : rel; // 根级配置：直接用仓库相对路径
  const inc = Array.isArray(cfg.include) && cfg.include.length ? cfg.include : ['**/*'];
  const exc = Array.isArray(cfg.exclude) ? cfg.exclude : [];
  return inc.some((e) => coversEntry(e, target)) && !exc.some((e) => coversEntry(e, target));
}

test('自证：coversEntry 的目录/文件语义（写错就会恒绿或恒红）', () => {
  assert.ok(coversEntry('src', 'src/tests/a.test.ts'), 'src 应管到 src/ 下任意深度');
  assert.ok(coversEntry('src/**', 'src/a.ts'));
  assert.ok(!coversEntry('src', 'server/src/a.js'), 'src 不该管到 server/');
  assert.ok(coversEntry('vitest.setup.ts', 'vitest.setup.ts'), '单文件条目要能精确命中');
  assert.ok(!coversEntry('vitest.setup.ts', 'vitest.setup.extra.ts'));
});

test('① 每个入库前端文件都至少被一份根级 tsconfig 覆盖', { skip: gitSkip }, () => {
  const cfgs = tsconfigs().map((f) => ({ f, cfg: readJsonc(f) }));
  assert.ok(cfgs.length >= 2, `只有 ${cfgs.length} 份根级 tsconfig —— 判据的假设已经变了`);
  // 只管前端范围（MUST_COVER）——服务端 JS 由 server/tsconfig.json 负责，别把两边混成一条判据
  const uncovered = tracked.filter((f) => CODE_FILE.test(f) && MUST_COVER(f)).filter(COVER_OR_NOT(cfgs));
  assert.deepEqual(
    uncovered,
    [],
    `${uncovered.length} 个入库前端文件不被任何 tsconfig 覆盖 ⇒ 零类型检查` +
      `（vitest 用 esbuild 转译不做类型判定，所以类型错了测试照样绿）。` +
      `要么加进主配置的 include，要么单开一份 tests 配置并接进 npm run typecheck。\n` +
      uncovered.join('\n')
  );
});

// 单独抽出来写，避免把 filter 回调写成"永远返回 false"的形态却没人发现
function COVER_OR_NOT(cfgs) {
  return (file) => !cfgs.some(({ f, cfg }) => coveredBy(cfg, path.dirname(f), file));
}

test('② 覆盖必须真的被跑上：typecheck 组合脚本 + CI 与 ci-local 两侧', () => {
  const pkg = JSON.parse(readFileSync(path.join(REPO, 'package.json'), 'utf8'));
  const scripts = pkg.scripts || {};
  const composite = scripts['typecheck'] || '';
  const parts = Object.keys(scripts).filter((k) => /^typecheck(:|$)/.test(k));
  assert.ok(parts.length >= 2, `typecheck 脚本只剩 ${parts.length} 个，静态检查面被收窄了`);

  // 每一份"独立存在"的 typecheck:* 都必须被组合脚本引用 —— 否则它就只是没人跑的脚本
  const missingInComposite = parts.filter((k) => k !== 'typecheck' && !composite.includes(k));
  assert.deepEqual(missingInComposite, [], `这些类型检查脚本没被 npm run typecheck 串上：${missingInComposite.join(', ')}`);

  const ci = readFileSync(path.join(REPO, '.github', 'workflows', 'ci.yml'), 'utf8');
  const local = readFileSync(path.join(REPO, 'scripts', 'ci-local.mjs'), 'utf8');
  // 组合脚本存在 ⇒ CI 与本地门禁至少要各跑一次 typecheck（直接跑组合，或把每一支都列出来）
  const ciRuns = /npm run typecheck\b/.test(ci) || parts.every((k) => ci.includes('npm run ' + k));
  const localRuns = /npm run typecheck\b/.test(local) || parts.every((k) => local.includes('npm run ' + k));
  assert.ok(ciRuns, 'ci.yml 里没有覆盖全部 typecheck 步骤');
  assert.ok(localRuns, 'scripts/ci-local.mjs 里没有对应步骤（本地绿 ≠ CI 绿）');
});

test('③ 分母：tests 配置确实吃到成规模的文件', { skip: gitSkip }, () => {
  const f = 'tsconfig.tests.json';
  assert.ok(existsSync(path.join(REPO, f)), `${f} 不存在 —— 前端测试的类型检查配置被删了`);
  const cfg = readJsonc(f);
  const covered = tracked.filter((f) => CODE_FILE.test(f)).filter((file) => coveredBy(cfg, '', file));
  const testsCovered = covered.filter((x) => x.startsWith('src/tests/'));
  assert.ok(testsCovered.length >= 50, `tsconfig.tests.json 只覆盖 ${testsCovered.length} 个测试文件（应有 50+）`);
  assert.ok(covered.length >= 100, `总覆盖只有 ${covered.length} 个文件，include 可能被改坏`);
});
