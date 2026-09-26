// ============================================================================
// tests/artifactDrift.wiring.test.js —— 漂移门禁"接没接线"必须自己被查到
// ============================================================================
// 本仓反复栽在同一格：判据写好了，但没有任何东西保证它被**执行**。
//   · `verify-dialect-templates.mjs` 文档写着"退出码 0 = 全通过"，从 09-22 到 09-25 没进过任何清单；
//   · `multi-engine-lab` 的 NO_WAF 档只手动跑过一次，产物入了库、门禁里没有它；
//   · CI 真跑的那档实测 0 检出，判定行还印 `on(0) ≥ off(0)=✅`。
// 所以 `scripts/artifact-drift.mjs` 自己也要过这一关：三处接线（package.json / ci.yml /
// ci-local）少任何一处，它就只是"本地能手动跑的一个脚本"，而不是门禁。
//
// 另一半：被检查的产物必须是**CI 真的重跑的那些档**生成的。否则漂移检查会拿一份
// 永远不会再生的旧产物去比，第一次红之后只能被 `continue-on-error` 掉。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPT = 'scripts/artifact-drift.mjs';
const scriptSrc = readFileSync(join(REPO, SCRIPT), 'utf8');
const pkg = JSON.parse(readFileSync(join(REPO, 'package.json'), 'utf8'));
const ciYml = readFileSync(join(REPO, '.github/workflows/ci.yml'), 'utf8');
const ciLocal = readFileSync(join(REPO, 'scripts/ci-local.mjs'), 'utf8');
const runAll = readFileSync(join(REPO, 'e2e/run-all.mjs'), 'utf8');

/** 解析脚本里的 DEFAULT_PATHS 数组（只看声明那一段，避免把注释里的例子算进来）。 */
function defaultPaths(src) {
  const at = src.indexOf('const DEFAULT_PATHS = [');
  assert.ok(at >= 0, `${SCRIPT} 里找不到 DEFAULT_PATHS —— 本守卫的解析要跟着改`);
  const body = src.slice(at, src.indexOf(']', at));
  return [...body.matchAll(/'([^']+\.md)'/g)].map((m) => m[1]);
}

const paths = defaultPaths(scriptSrc);
const labLines = runAll.split(/\r?\n/).filter((l) => /^\s*\{ name: '/.test(l));

test('漂移清单不许多空转：至少 3 份产物，且每份都被 git 跟踪、都真的含表格行', () => {
  assert.ok(paths.length >= 3, `只登记了 ${paths.length} 份产物 ⇒ 这道门禁几乎没有覆盖面`);
  for (const p of paths) {
    const tracked = spawnSync('git', ['ls-files', '--error-unmatch', p], { cwd: REPO, encoding: 'utf8' }).status === 0;
    assert.ok(tracked, `${p} 未入库 —— HEAD 侧没有可比的那份，漂移检查对它不成立`);
    assert.ok(existsSync(join(REPO, p)), `${p} 工作区里不存在`);
    const rows = readFileSync(join(REPO, p), 'utf8').split(/\r?\n/).filter((l) => l.trim().startsWith('|')).length;
    assert.ok(rows >= 3, `${p} 只有 ${rows} 行表格 —— 没有可比的测量行，判据会恒真`);
  }
});

test('每份被检查的产物，都必须对应 run-all 里一个真的会重跑的档（否则比的是不会变的旧文件）', () => {
  // 产物目录 → 生成它的入口。默认清单目前只有 multi-engine 的三个档；
  // 往 DEFAULT_PATHS 里加别的目录的产物时，**必须同时在这里补映射**，
  // 否则本用例会给出误导性的"找不到条目"（宁可红得明确，也不要红得奇怪）。
  const ENTRY_BY_DIR = { 'e2e/multi-engine-lab/results': 'e2e/multi-engine-lab/verify.mjs' };
  const need = (p) => (p.includes('.no-waf') ? /NO_WAF: '1'/ : p.includes('.pl1') ? /CRS_PL: '1'/ : null);
  for (const p of paths) {
    const dir = p.slice(0, p.lastIndexOf('/'));
    const entryFile = ENTRY_BY_DIR[dir];
    assert.ok(entryFile, `${p} 出自 ${dir}，但本用例没有该目录的"哪个脚本生成它"映射 —— 先补映射再登记产物`);
    const candidates = labLines.filter((l) => l.includes(entryFile));
    assert.ok(candidates.length, `run-all 里没有 ${entryFile} 的条目 ⇒ ${p} 永远不会被重跑`);
    const re = need(p);
    const hit = re ? candidates.filter((l) => re.test(l)) : candidates.filter((l) => !/NO_WAF|CRS_PL/.test(l));
    assert.equal(hit.length, 1,
      `${p} 对应的档在 run-all 里应当恰好一条（实得 ${hit.length} 条：${hit.map((l) => /^\s*\{ name: '([^']+)/.exec(l)[1]).join(', ') || '无'}）`);
  }
});

test('三处接线缺一不可：package.json 脚本 / ci.yml 步骤 / ci-local GATES', () => {
  assert.equal(pkg.scripts['artifact:drift'], `node ${SCRIPT}`,
    'package.json 没有 artifact:drift（或指向别处）⇒ 这道门禁没法被统一入口调用');

  // ci.yml：必须挂在**真的重跑过这些产物**的那个 job 里，而不是随便一个 job。
  const jobAt = ciYml.search(/^ {2}e2e-self-contained:$/m);
  assert.ok(jobAt >= 0, 'ci.yml 里找不到 e2e-self-contained job');
  const rest = ciYml.slice(jobAt);
  const nextJob = rest.search(/^\r?\n {2}[a-z0-9-]+:$/m);
  const jobBody = nextJob >= 0 ? rest.slice(0, nextJob) : rest;
  assert.ok(/run: node e2e\/run-all\.mjs/.test(jobBody),
    'e2e-self-contained 里没有 run-all 步骤 —— 产物不会被重跑，漂移检查放这儿没意义');
  assert.ok(/run: node scripts\/artifact-drift\.mjs/.test(jobBody),
    'e2e-self-contained 缺漂移检查步骤（脚本写好了但 CI 不跑 = 又一次"注册了没接线"）');

  assert.match(ciLocal, /cmd: 'node scripts\/artifact-drift\.mjs'/,
    'scripts/ci-local.mjs 的 GATES 缺同一条：本地门禁会静默少跑这一段（见其头部 job 覆盖自检的理由）');
  assert.match(ciLocal, /id: 'e2e-self-contained',[^\n]*\n?[^\n]*artifact-drift|artifact-drift[^\n]*e2e-self-contained|id: 'e2e-self-contained', name: '入库基线漂移检查/,
    'ci-local 里这条的 job id 必须是 e2e-self-contained（挂错 job 时本地跑到了、远端没跑）');
});
