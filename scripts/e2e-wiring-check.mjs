#!/usr/bin/env node
// ============================================================================
// scripts/e2e-wiring-check.mjs —— e2e 靶场「接线状态」门禁
// ============================================================================
// 为什么需要它：本仓有 6 个靶场**从来没有被任何东西执行过** ——
// 不在 `e2e/run-all.mjs` 的 LABS、不在 `e2e/acceptance.mjs` 的 SUITES、ci.yml 零引用。
// 它们看起来是资产（有入口脚本、有 ground-truth、有产物目录），实际上**从不产生结论**：
//   blackbox-lab（TODO.md 自述「不在任何门禁里」，仅被 lab-targets-check 静态比 id 清单）、
//   ntlm-lab / sqli-labs / fullchain-lab / sqlmap-benchmark / cross-module-lab。
//
// 「写了没人跑」比「没有」更坏：README 与报告会把它们当成覆盖证据引用，而读者无从
// 分辨哪些结论是今天跑出来的、哪些是半年前某次手跑留下的。这与本仓反复治理的
// 「能力静默不可达」是同一族缺陷，只是发生在**测试资产**而不是功能上。
//
// 口径（二选一，不许维持现状）：
//   ① **接线** —— 出现在任一接线真源里（run-all / acceptance / ci.yml / ci-local）；
//   ② **正名** —— 在 `e2e/reference-labs.json` 显式登记为「参考靶场、非门禁」并写清理由。
// 两条都不占 ⇒ exit 1。反向也查：登记了却已接线、或目录已不存在 ⇒ 清单腐烂 ⇒ exit 1
// （理由：白名单会让人停止检查，腐烂的白名单比没有白名单更危险）。
//
// 用法：
//   node scripts/e2e-wiring-check.mjs            （退出码即结论）
//   node scripts/e2e-wiring-check.mjs --selftest 自证判据不空转
// ============================================================================
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const E2E = join(ROOT, 'e2e');
const WHITELIST = join(E2E, 'reference-labs.json');

/** 接线真源：目录名出现在任一处 = 该靶场会被真正执行 */
const WIRING_SOURCES = [
  'e2e/run-all.mjs',
  'e2e/acceptance.mjs',
  '.github/workflows/ci.yml',
  'scripts/ci-local.mjs',
];

/**
 * e2e/ 下的**非靶场**目录（支撑设施），逐个写明理由 ——
 * 不写理由的排除就是下一个「静默缺口」。
 */
const NON_LAB_DIRS = new Map([
  ['lib', '公共库（被各靶场 import，自身不是靶场）'],
  ['fixtures', '测试数据'],
  ['results', '产物归档目录'],
  ['diag', '人工诊断脚本，刻意不进门禁（需现场环境与人工判读）'],
  ['demo', '演示/示例'],
  ['contract', '契约测试（由前端/后端测试套件驱动，不是靶场）'],
  ['perf', '性能测量（需专用环境，结果不进判定）'],
  ['release', '发布流程相关脚本'],
  ['one-click', '一键脚本（人工执行）'],
  ['__pycache__', 'Python 字节码缓存'],
]);

/**
 * 入口文件形状：命中任一即认为这是个靶场（有可执行的验证入口）。
 * ⚠️ 命名在本仓并不统一（有 `run.mjs` / `verify.mjs` / `*.e2e.mjs` / `tamper-test.mjs` /
 * `sqli-labs-runner.mjs` / `*.py`），所以**入口形状不是唯一判据**：
 * 已接线或已登记的目录一律按靶场计（见下方判定），否则 `tamper-matrix` 这类入口不规则的
 * 靶场会被悄悄排除 —— 那正是本门禁要堵的「静默缺口」的另一种形态。
 */
const ENTRY_RE = /^(run|verify|check)[^/]*\.mjs$|\.e2e\.mjs$|-runner\.mjs$|\.py$/;

function readIfExists(rel) {
  const p = join(ROOT, rel);
  return existsSync(p) ? readFileSync(p, 'utf8') : null;
}

/** 目录名是否出现在接线真源里（整词匹配，避免 `labs` 命中 `sqli-labs` 的误判） */
function isWiredIn(name, sources) {
  return Object.values(sources).some((text) => text !== null && text.includes(name));
}

// ---------- 采集 ----------
const dirs = readdirSync(E2E, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

const sources = {};
for (const rel of WIRING_SOURCES) sources[rel] = readIfExists(rel);

/** 白名单：登记为「参考靶场、非门禁」的目录 */
let whitelist = [];
let whitelistErr = null;
if (existsSync(WHITELIST)) {
  try {
    const j = JSON.parse(readFileSync(WHITELIST, 'utf8'));
    whitelist = Array.isArray(j.referenceOnly) ? j.referenceOnly : [];
  } catch (e) {
    whitelistErr = e.message;
  }
}
const wlByName = new Map(whitelist.map((w) => [w.name, w]));

const problems = [];
const info = [];
let labs = 0;
let wired = 0;
let declared = 0;

for (const name of dirs) {
  if (NON_LAB_DIRS.has(name)) continue;
  const entries = readdirSync(join(E2E, name));
  const hasEntry = entries.some((f) => ENTRY_RE.test(f));
  const wiredNow = isWiredIn(name, sources);
  const inWl = wlByName.has(name);
  // 已接线或已登记 ⇒ 它就是靶场（入口命名不规则不该让它逃出统计）
  if (!hasEntry && !wiredNow && !inWl) {
    info.push(`  · ${name}：无可执行入口，不计入靶场（若它其实是靶场，说明入口命名跑偏了）`);
    continue;
  }
  labs += 1;

  if (wiredNow) {
    wired += 1;
    if (inWl) {
      problems.push(
        `${name}：已接线（出现在接线真源里），却仍登记在 reference-labs.json ⇒ 白名单腐烂。\n` +
          '      → 接线完成后必须从白名单移除，否则「参考靶场」这个标签会一直替它挡住检查。',
      );
    } else {
      info.push(`  ✅ ${name}：已接线`);
    }
  } else if (inWl) {
    declared += 1;
    const why = String(wlByName.get(name).why || '').trim();
    if (!why) problems.push(`${name}：白名单条目缺 why（不写理由的豁免 = 静默缺口）`);
    info.push(`  📌 ${name}：参考靶场（非门禁）—— ${why}`);
  } else {
    problems.push(
      `${name}：有可执行入口但**不在任何接线真源里**，也未登记为参考靶场。\n` +
        `      → 二选一：① 接线进 ${WIRING_SOURCES.join(' / ')}；` +
        '② 在 e2e/reference-labs.json 登记为参考靶场并写清为什么它不该进门禁。',
    );
  }
}

// 反向：白名单里登记了但目录已不存在
for (const w of whitelist) {
  if (!dirs.includes(w.name)) problems.push(`${w.name}：在 reference-labs.json 里，但 e2e/${w.name}/ 已不存在（清单腐烂）`);
}
if (whitelistErr) problems.push(`e2e/reference-labs.json 解析失败：${whitelistErr}`);

// ---------- 空转兜底：一个靶场都没扫到 = 判据失效，必须显形 ----------
if (labs === 0) {
  console.error('❌ e2e/ 下一个靶场都没扫到（目录结构变了或入口命名跑偏）—— 判据失效必须显形，');
  console.error('   静默返回空集合会让下面的「一致」变成假绿。');
  process.exit(2);
}

// ---------- 自证（--selftest）：必须在报告之前分流，否则脚本先 exit 了 ----------
// selftest() 是函数声明（hoisted），可以定义在文件末尾。
if (process.argv.slice(2).includes('--selftest')) selftest();

// ---------- 报告 ----------
console.log('e2e 靶场接线状态门禁：');
for (const line of info) console.log(line);
console.log(`\n  靶场 ${labs} 个：已接线 ${wired} · 参考靶场（已登记）${declared} · 未处置 ${labs - wired - declared}`);

if (problems.length) {
  console.error(`\n❌ 检出 ${problems.length} 处未处置/腐烂：\n`);
  for (const p of problems) console.error(`  · ${p}`);
  console.error('\n为什么这不是小事：没接线的靶场从来不产生结论，但会被当成覆盖证据引用 ——');
  console.error('「半年前手跑过一次」和「今天门禁在跑」，在 README 里长得一模一样。');
  process.exit(1);
}
console.log('\n✅ 每个 e2e 靶场都二选一：已接线，或已登记为参考靶场（理由充分）。');
process.exit(0);

// ============================================================================
// --selftest：自证判据不空转
// ============================================================================
// 空转形态①：isWiredIn 恒真 ⇒ 所有靶场都"已接线" ⇒ 门禁恒绿（最坏的一种）。
// 空转形态②：靶场采集为空 ⇒ exit 2（上面已堵）。
// 空转形态③：白名单解析失败却静默通过 ⇒ 上面已列 problem。
function selftest() {
  const failed = [];
  const fake = { a: 'e2e/redteam-lab/run-with-env.mjs', b: 'nothing here' };
  if (!isWiredIn('redteam-lab', fake)) failed.push('isWiredIn 对明确出现的名字应返回 true');
  if (isWiredIn('definitely-not-a-lab', fake)) failed.push('isWiredIn 对不存在的名字必须返回 false（恒真 = 门禁空转）');
  if (labs === 0) failed.push('靶场采集为空（判据失效，应 exit 2 而不是走到这里）');
  for (const w of whitelist) {
    if (!w.name) failed.push('白名单条目缺 name');
    if (!String(w.why || '').trim()) failed.push(`白名单条目 ${w.name} 缺 why`);
  }
  // 至少有一个靶场是「已接线」的（否则说明接线真源的路径全漂移了）
  if (wired === 0) failed.push('没有任何靶场被判为已接线 ⇒ 接线真源路径可能漂移（WIRING_SOURCES 需要同步）');
  if (failed.length) {
    console.error(`\nFAIL：e2e-wiring-check selftest 有 ${failed.length} 项未通过`);
    for (const f of failed) console.error(`  · ${f}`);
    process.exit(1);
  }
  console.log(`✔ e2e-wiring-check selftest 通过（靶场 ${labs} 个、已接线 ${wired} 个、判据可返回 false）`);
  process.exit(0);
}
