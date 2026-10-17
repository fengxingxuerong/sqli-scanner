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
// ⚠️ 候选目录只取 **`git ls-files` 里已跟踪的**（2026-10-13 补）：未跟踪目录还在开发中，
// 不该被当成仓库资产 —— 详见 `trackedE2eDirs()` 的注释，那是本门禁作者自己踩过的坑。
//
// 用法：
//   node scripts/e2e-wiring-check.mjs            （退出码即结论）
//   node scripts/e2e-wiring-check.mjs --selftest 自证判据不空转
// ============================================================================
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
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

/** 注释起始符 → 注释态（查表替掉 if 链，控圈复杂度）。 */
const COMMENT_STATE = { '/': 'line', '*': 'block' };

/** 剥行注释/块注释（字符串感知：`//` 只有在代码态才是注释起点，URL/字符串里的不受影响）。 */
function stripJsComments(text) {
  let out = '';
  let state = 'code'; // code | line | block | str
  let quote = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const d = text[i + 1];
    if (state === 'code') {
      if (c === '/' && COMMENT_STATE[d]) { state = COMMENT_STATE[d]; i++; continue; }
      if ("'\"`".includes(c)) { state = 'str'; quote = c; }
      out += c;
    } else if (state === 'str') {
      if (c === '\\') { out += c + (d ?? ''); i++; } else { out += c; if (c === quote) state = 'code'; }
    } else if (state === 'line') {
      if (c === '\n') { state = 'code'; out += c; }
    } else if (c === '*' && d === '/') {
      state = 'code'; i++; // block 结束
    } else if (c === '\n') {
      out += c; // block 内部换行保留（防相邻 token 拼接）
    }
  }
  return out;
}

/** YAML：剥整行 `#` 注释（本项目三份真源里的提及都是整行注释；行尾注释保留原样）。 */
function stripYamlLineComments(text) {
  return text.split('\n').map((l) => (l.trimStart().startsWith('#') ? '' : l)).join('\n');
}

/**
 * 读接线真源并剥注释：名字出现在**注释**里 ≠ 会被执行。
 * [D95 实锤] acceptance.mjs 用一句散文注释提到 sqli-labs ⇒ 旧判据把它当「已接线」，
 * 与 reference-labs.json 的登记互撞报「白名单腐烂」——假阳性逼人删正确登记。
 */
function readWiringSource(rel) {
  const raw = readIfExists(rel);
  if (raw === null) return null;
  return rel.endsWith('.yml') ? stripYamlLineComments(raw) : stripJsComments(raw);
}

/** 目录名是否出现在接线真源里（整词匹配，避免 `labs` 命中 `sqli-labs` 的误判） */
function isWiredIn(name, sources) {
  return Object.values(sources).some((text) => text !== null && text.includes(name));
}

// ---------- 采集 ----------
/**
 * 只把**已跟踪**的目录当靶场。
 *
 * [2026-10-13 实测教训] 起因：并发会话的 WIP 目录 `e2e/cross-module-lab/` 在本机存在但
 * 未提交。把它登记进白名单 ⇒ **CI 报「清单腐烂」**（CI 上没有该目录）；不登记 ⇒ 本机报
 * 「未处置」。两边都是误导，因为**未跟踪的目录根本不是本仓库的资产** —— 读者在仓库里
 * 看不到它，也就不可能把它的结论当覆盖证据引用（本门禁的原始动机）。
 * 顺带：这正是 `refs:check` 治的那类「本机有、库里没有」错误形态，我在这里踩了一次 ——
 * 而今回过头看，门禁**抓到了它自己作者犯的错**，算是判据有效性的一个实证。
 *
 * git 不可用（非仓库环境）时返回 null ⇒ 回退全量扫描并打印说明，不静默放行。
 */
function trackedE2eDirs() {
  try {
    // 不传 encoding ⇒ 返回 Buffer（传 'buffer' 会 ERR_UNKNOWN_ENCODING，实测踩过）
    const out = execFileSync('git', ['ls-files', '-z', '--', 'e2e/'], { cwd: ROOT });
    const names = new Set();
    for (const p of out.toString('utf8').split('\0')) {
      const m = p.match(/^e2e\/([^/]+)\//);
      if (m) names.add(m[1]);
    }
    return names.size ? names : null;
  } catch {
    return null;
  }
}

const tracked = trackedE2eDirs();

const dirs = readdirSync(E2E, { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => d.name)
  .sort();

const sources = {};
for (const rel of WIRING_SOURCES) sources[rel] = readWiringSource(rel);

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

if (tracked === null) {
  console.log('  ℹ git 不可用（非仓库环境？）⇒ 未跟踪过滤已关闭，按磁盘全量扫描。');
}

for (const name of dirs) {
  if (NON_LAB_DIRS.has(name)) continue;
  if (tracked && !tracked.has(name)) {
    info.push(`  · ${name}：未跟踪（不在仓库里）⇒ 不作为本仓库的靶场资产检查`);
    continue;
  }
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

// 反向：白名单里登记了，但它在**仓库里**不存在（目录没了，或压根没提交）
// ⚠️ 判据同样基于 tracked（已跟踪）而不是磁盘：只按磁盘判会放过「本地有、库里没有」
// 的登记项 —— 那正是 2026-10-13 lint 在 CI 上红过的形态（本地绿、CI 红）。
for (const w of whitelist) {
  const existsInRepo = tracked ? tracked.has(w.name) : dirs.includes(w.name);
  if (!existsInRepo) {
    problems.push(
      `${w.name}：在 reference-labs.json 里，但 e2e/${w.name}/ 在仓库里不存在（清单腐烂或未提交）`,
    );
  }
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
  if (tracked === null) failed.push('git ls-files 不可用 ⇒ 未跟踪过滤被关闭（selftest 要求本次运行里它是可用的）');
  for (const w of whitelist) {
    if (!w.name) failed.push('白名单条目缺 name');
    if (!String(w.why || '').trim()) failed.push(`白名单条目 ${w.name} 缺 why`);
  }
  // 至少有一个靶场是「已接线」的（否则说明接线真源的路径全漂移了）
  if (wired === 0) failed.push('没有任何靶场被判为已接线 ⇒ 接线真源路径可能漂移（WIRING_SOURCES 需要同步）');
  selftestStripping(failed);
  if (failed.length) {
    console.error(`\nFAIL：e2e-wiring-check selftest 有 ${failed.length} 项未通过`);
    for (const f of failed) console.error(`  · ${f}`);
    process.exit(1);
  }
  console.log(`✔ e2e-wiring-check selftest 通过（靶场 ${labs} 个、已接线 ${wired} 个、判据可返回 false）`);
  process.exit(0);
}

/** 注释剥离自证（D95：注释提及 ≠ 接线；过猛剥掉代码 = 假阴性也要防）。 */
function selftestStripping(failed) {
  const jsComment = stripJsComments("// fake-lab：注释提及\nconst entry = 'e2e/other-lab/run.mjs'; // fake-lab\n");
  if (jsComment.includes('fake-lab')) failed.push('剥注释失败：注释里的名字幸存（假阳性会复发）');
  if (!stripJsComments("const p = 'e2e/fake-lab/run.mjs';").includes('fake-lab')) failed.push('剥注释过猛：代码字符串里的名字被误剥（假阴性）');
  if (!stripJsComments("const u = 'https://example.com/fake-lab';").includes('fake-lab')) failed.push('剥注释过猛：含 // 的 URL 字符串被误当注释');
  if (stripYamlLineComments('# fake-lab\nkey: value\n').includes('fake-lab')) failed.push('YAML 整行注释里的名字幸存');
  if (!stripYamlLineComments('run: node e2e/fake-lab/run.mjs\n').includes('fake-lab')) failed.push('YAML 代码行被误剥');
}
