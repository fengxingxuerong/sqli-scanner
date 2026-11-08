#!/usr/bin/env node
// ============================================================================
// server-coverage-gate.mjs —— 服务端覆盖率门禁的确定性包装（D260，2026-11-06）
//
// 问题（实测，非推断）：Node 的 `--experimental-test-coverage` 在**存在 `?query`
// 模块实例**时，同一源文件的多进程快照合并会退化成「只取一个进程快照」：
//   · Node 22.22.2：最小样本连跑 5 次，同一文件 branch 在 66.67% / 57.14% 之间跳；
//   · Node 24.22.1（CI 同款）：稳定取单快照（66.67% / funcs 33.33%），不再 union；
//   · 去掉 `?query` 实例后，两个版本都稳定 union（57.14% / funcs 100%）。
// 本仓 6 个测试文件用 `?tag` 动态 import 拿模块隔离实例（env 在 import 期读取），
// 正是它们让 CI 的 `Server coverage gate` 从 77% 掉到 73.18% branch（< 74 阈值）。
//
// 修法（校准**合并口径**，不动阈值、不动 include、不放宽任何断言）：
//   覆盖率测量排除这 6 个文件；它们仍在 `cd server && npm test` 全量执行。
//   排除名单由静态扫描 + 双向校验钉死：新增 `?query` 导入而没进名单会当场判红，
//   名单里的文件不再含 `?query` 也会判红（防名单静默腐烂）。
//   Node 24 实测：479 个文件 / 4129 用例 / 0 fail，all files 95.08 / 81.75 / 88.93（exit 0）。
//
// 用法：
//   node scripts/server-coverage-gate.mjs --test-coverage-lines=85 \
//        --test-coverage-branches=74 --test-coverage-functions=77   # 门禁（有阈值）
//   node scripts/server-coverage-gate.mjs --report-only              # 只出报表（facts 采集）
//   node scripts/server-coverage-gate.mjs --selftest                 # 判据自证
// 其余未识别参数（如 `--test-reporter=tap`）原样转发给 node --test。
// ============================================================================
import { readdirSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SERVER = join(ROOT, 'server');
const TEST_DIR = join(SERVER, 'tests');
const REL_SCRIPT = 'scripts/server-coverage-gate.mjs';

/** 用 `?query` 隔离实例的测试文件：不参与覆盖率测量，仍参与 `npm test` 全量。 */
const EXCLUDED = Object.freeze([
  'exploitRoutes.edge.test.js',
  'reportAI.service.test.js',
  'reportAi.boundary.guard.test.js',
  'reportAi.budget.guard.test.js',
  'reportAi.shortRetry.guard.test.js',
  'reportAi.stepwise.d275.guard.test.js',
  'reportAi.stepwise.guard.test.js',
  'ssrf.ipv6.test.js',
].sort());

/** 只认「指向 src/ 且带 ? 后缀」的 import 说明符，注释里的泛泛提及不算。 */
const QUERY_IMPORT_RE = /src\/[^'"`\s]*\.js\?/;
const THRESHOLDS = { lines: 85, branches: 74, functions: 77 };

/** @param {Map<string,string>} contents 文件名 → 源码 */
function findQueryImportFiles(contents) {
  return [...contents.entries()]
    .filter(([, src]) => QUERY_IMPORT_RE.test(src))
    .map(([name]) => name)
    .sort();
}

/**
 * 双向校验排除名单：多排（会少测）、漏排（会破坏合并）都判红。
 * @param {Map<string,string>} contents
 * @returns {{files: string[], queryFiles: string[]}}
 */
function validateExclusions(contents) {
  const queryFiles = findQueryImportFiles(contents);
  const excludedSet = new Set(EXCLUDED);
  const extra = queryFiles.filter((f) => !excludedSet.has(f));
  const stale = EXCLUDED.filter((f) => !queryFiles.includes(f));
  const absent = EXCLUDED.filter((f) => !contents.has(f));
  const bad = [];
  if (extra.length) bad.push(`含 ?query 导入但未排除（会破坏覆盖率合并）：${extra.join(', ')}`);
  if (stale.length) bad.push(`排除名单已过期（文件不再含 ?query 导入，应恢复测量）：${stale.join(', ')}`);
  if (absent.length) bad.push(`排除名单里的文件不存在：${absent.join(', ')}`);
  if (bad.length) throw new Error(bad.join('\n  · '));
  const files = [...contents.keys()].filter((f) => !excludedSet.has(f)).sort();
  if (files.length < 400) throw new Error(`参与测量的测试文件仅 ${files.length} 个，收集口径可能坏了`);
  return { files, queryFiles };
}

/** 解析本脚本参数：阈值、report-only、其余转发给 node --test。 */
function parseArgs(argv) {
  const out = { reportOnly: false, selftest: false, dryRun: false, thresholds: { ...THRESHOLDS }, forward: [] };
  for (const a of argv) {
    if (a === '--report-only') out.reportOnly = true;
    else if (a === '--selftest') out.selftest = true;
    else if (a === '--dry-run') out.dryRun = true;
    else if (/^--test-coverage-(lines|branches|functions)=[\d.]+$/.test(a)) {
      const [, key, val] = /^--test-coverage-(lines|branches|functions)=([\d.]+)$/.exec(a);
      out.thresholds[key] = Number(val);
    } else out.forward.push(a);
  }
  return out;
}

/** 纯函数，便于自证：组装 node --test 参数。 */
function buildChildArgs({ reportOnly, thresholds, forward, files }) {
  const args = [
    '--env-file=.env.test',
    '--import=./tests/_setup.mjs',
    '--experimental-test-coverage',
    '--test',
    '--test-coverage-include=src/**/*.js',
    '--test-concurrency=3',
    ...forward,
  ];
  if (!reportOnly) {
    args.push(
      `--test-coverage-lines=${thresholds.lines}`,
      `--test-coverage-branches=${thresholds.branches}`,
      `--test-coverage-functions=${thresholds.functions}`,
    );
  }
  return [...args, ...files.map((f) => `tests/${f}`)];
}

function selftest() {
  const mk = (names, queryNames) => new Map(names.map((n) => [n, queryNames.includes(n) ? "import('../src/x.js?tag')" : '// plain']));
  const base = Array.from({ length: 405 }, (_, i) => `t${i}.test.js`);
  const all = [...base, ...EXCLUDED];
  const failures = [];
  const check = (name, fn) => { try { if (fn() !== true) failures.push(`${name}：判据未命中`); } catch (e) { failures.push(`${name}：${e.message}`); } };

  check('合法样本通过', () => {
    const r = validateExclusions(mk(all, EXCLUDED));
    return r.files.length === 405 && r.queryFiles.length === EXCLUDED.length;
  });
  check('新增 ?query 导入未排除会判红', () => {
    try { validateExclusions(mk(all, [...EXCLUDED, 't0.test.js'])); return false; } catch { return true; }
  });
  check('排除名单过期会判红', () => {
    try { validateExclusions(mk(all, EXCLUDED.slice(1))); return false; } catch { return true; }
  });
  check('排除名单文件缺失会判红', () => {
    const m = mk(all, EXCLUDED); m.delete(EXCLUDED[0]);
    try { validateExclusions(m); return false; } catch { return true; }
  });
  check('门禁模式带三个阈值', () => {
    const a = buildChildArgs({ reportOnly: false, thresholds: THRESHOLDS, forward: [], files: ['a.test.js'] });
    return a.includes('--test-coverage-branches=74') && a.includes('tests/a.test.js');
  });
  check('report-only 不带阈值', () => {
    const a = buildChildArgs({ reportOnly: true, thresholds: THRESHOLDS, forward: ['--test-reporter=tap'], files: [] });
    return !a.some((x) => x.startsWith('--test-coverage-lines=')) && a.includes('--test-reporter=tap');
  });
  check('阈值可由 argv 覆盖', () => parseArgs(['--test-coverage-branches=90']).thresholds.branches === 90);

  if (failures.length) {
    console.error('[server-coverage] ✗ 自证失败：');
    for (const f of failures) console.error('  · ' + f);
    process.exit(1);
  }
  console.log(`[server-coverage] ✓ 自证通过（7 条；排除名单 ${EXCLUDED.length} 个、双向校验 + 阈值/report-only 判据均有效）`);
}

const args = parseArgs(process.argv.slice(2));
if (args.selftest) { selftest(); process.exit(0); }

const contents = new Map(
  readdirSync(TEST_DIR)
    .filter((f) => f.endsWith('.test.js'))
    .map((f) => [f, readFileSync(join(TEST_DIR, f), 'utf8')]),
);
let files;
try {
  files = validateExclusions(contents).files;
} catch (e) {
  console.error(`[server-coverage] ✗ 排除名单校验失败（${REL_SCRIPT}）：\n  · ${e.message}`);
  process.exit(1);
}

console.error(`[server-coverage] 测量 ${files.length} 个测试文件；排除 ${EXCLUDED.length} 个含 ?query 隔离实例的文件（仍由 npm test 全量执行）：${EXCLUDED.join(', ')}`);
if (args.dryRun) {
  console.log(`[server-coverage] dry-run：child args = ${buildChildArgs({ ...args, files }).slice(0, 9).join(' ')} …（共 ${files.length} 个文件）`);
  process.exit(0);
}
const child = spawnSync(process.execPath, buildChildArgs({ ...args, files }), {
  cwd: SERVER, stdio: 'inherit', env: process.env, windowsHide: true,
});
process.exit(child.status ?? 1);
