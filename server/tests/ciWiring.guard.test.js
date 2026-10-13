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

// ============================================================================
// [D50 2026-10-12] PG 三套真机靶场的「进门禁」守卫（TODO 15.4 的剩账 ①）
//
// 背景：oob-real-lab / pg-osshell / concurrent-isolation 三套的 deps 含 pg，而 CI 从未起 PG
// ⇒ 自写下起**从未在任何自动门禁里执行过**。能隐形成功，是因为这里缺两道闸：
//   ① 没人要求它们在 ci.yml 里接线（本文件原来的 ①② 只盯 `*.test.mjs`，这三套是
//      `*.e2e.mjs` / `verify.mjs`，压根不在视野里）；
//   ② 就算接了线，其中两套的**退出码恒 0** —— 断言失败也返回成功（verify.mjs 结尾是
//      无条件 `process.exit(0)`；pg-osshell 在 PG 连不上时 SKIP 也是 `exit(0)`）。
//      ⇒ 接进去只会得到一个「天天绿、一次没真跑」的 step，比天天红更糟。
// 所以两件事必须一起钉：**接线要在** + **退出码要真**。
// ============================================================================
const PG_SUITES = [
  'e2e/oob-real-lab/pg-osshell.e2e.mjs',
  'e2e/oob-real-lab/verify.mjs',
  'e2e/concurrent-isolation/e2e.mjs',
];

/** 纯函数：取文本里**最后一个** `process.exit(...)` 的实参（trim 过）。判据与自证共用。 */
function lastExitArg(text) {
  const hits = [...text.matchAll(/process\.exit\(([^)]*)\)/g)];
  if (!hits.length) return null;
  return hits[hits.length - 1][1].trim();
}

/** 纯函数：是否把 PG 端口/口令写死了（不读 PG_* env ⇒ 换个端口的 PG 永远连不上）。 */
function hasHardcodedPg(text) {
  return /port:\s*5432/.test(text) || /password:\s*['"]postgres['"]/.test(text);
}

test('③ PG 三套必须在 ci.yml 里接线（写了却永不跑第二次 = 隐形能力）', () => {
  const yml = readFileSync(CI_YML, 'utf8');
  const missing = PG_SUITES.filter(
    (f) => !new RegExp('node\\s+' + f.replace(/\//g, '\\/')).test(yml)
  );
  assert.deepEqual(
    missing,
    [],
    `这 ${missing.length} 套依赖真 PG 的靶场没有在 ci.yml 里接线：\n  ${missing.join('\n  ')}\n` +
      '它们本机跑通过，但本机跑通 ≠ CI 看得见 —— 不接线就等于「写完再没人执行第二次」。\n' +
      '修法：在 acceptance job 起一个 PostgreSQL（runner 自带 16.15，`sudo systemctl start postgresql.service`），\n' +
      '再用 `run: node <entry>` + PG_* env 直连。**不要**只加 step 而不修退出码（见下一条）。'
  );
});

test('④ 这三套的退出码必须反映断言结果（否则接进 CI 只是买到恒绿）', () => {
  const problems = [];
  for (const f of PG_SUITES) {
    const text = readFileSync(path.join(REPO, f), 'utf8');
    const last = lastExitArg(text);
    if (last === null) {
      problems.push(`${f} 结尾没有 process.exit(…) ⇒ 退出码全靠异常，判据不可控`);
      continue;
    }
    if (last === '0') {
      problems.push(
        `${f} 最后一个 process.exit 是**字面量 0** ⇒ 断言失败也返回成功。` +
          '接进 CI 后这一步恒绿，跑没跑过、过没过都看不出来 —— 这正是本批接进去之前必须先修的东西。'
      );
    }
    if (hasHardcodedPg(text)) {
      problems.push(
        `${f} 把 PG 端口/口令写死了（不读 PG_* 环境变量）⇒ PG 不在默认 5432/postgres 时永远连不上，` +
          '而连不上会走 SKIP ⇒ 又是恒绿。统一从 e2e/oob-real-lab/lab-app.mjs 的 PG_CONF 取。'
      );
    }
  }
  // 「环境缺项」的跳过必须能被显式要求变成失败：已经专门起了 PG 的门禁里跳过 = 降级。
  // 口径同仓库既有的 RECALL_REQUIRE_MYSQL / MODSEC_REQUIRE_DB。
  //
  // ⚠ 判据必须查**代码形态**（`process.env.PG_REQUIRE` + 真的拿它分支），不能只查
  //   `text.includes('PG_REQUIRE')` —— 缺陷注入实测：删掉那行代码后，注释里还写着
  //   「已设 PG_REQUIRE=1」，includes 照样通过 ⇒ 守卫绿着放行（2026-10-12 实测踩到）。
  //   这是本仓第三次栽在「判据的文本源没排注释」上，凡是查"有没有提到某个开关"的地方
  //   一律要查代码引用而不是字面出现。
  const osshell = readFileSync(path.join(REPO, 'e2e/oob-real-lab/pg-osshell.e2e.mjs'), 'utf8');
  const readsFlag = /process\.env\.PG_REQUIRE/.test(osshell);
  const branchesOnFlag = /if\s*\(\s*PG_REQUIRE\s*\)\s*\{/.test(osshell);
  if (!readsFlag || !branchesOnFlag) {
    problems.push(
      `pg-osshell 的 SKIP 路径没有真正受 PG_REQUIRE 控制（读开关=${readsFlag} / 按开关分支=${branchesOnFlag}）` +
        ' ⇒ 在「已经起了 PG」的门禁里跳过也判绿。默认 SKIP 是对的（本机没 PG 不是代码缺陷），' +
        '但必须有开关能把跳过变成失败，且要在代码里真的读它、真的按它分支（光写在注释里不算）。'
    );
  }
  assert.deepEqual(problems, [], problems.join('\n'));
});

test('自证：③④ 的取词与判据在合成样本上确实会红（不是恒绿的摆设）', () => {
  // 最后一个 exit 是字面量 0 ⇒ 必须被抓
  assert.equal(lastExitArg('process.exit(ok ? 0 : 1);\nprocess.exit(0);'), '0');
  // 最后一个 exit 依赖判定 ⇒ 不算违规
  assert.equal(lastExitArg('process.exit(0);\nprocess.exit(pass ? 0 : 1);'), 'pass ? 0 : 1');
  // 完全没有 exit ⇒ 判据报"不可控"而不是放过
  assert.equal(lastExitArg('console.log("done")'), null);
  // 写死形态 / 正确形态
  assert.equal(hasHardcodedPg("new Client({ host: '127.0.0.1', port: 5432, password: 'postgres' })"), true);
  assert.equal(hasHardcodedPg('const PG_ADMIN = { ...PG_CONF, database: \'postgres\' };'), false);
  assert.equal(hasHardcodedPg("password: process.env.PGPASSWORD ?? 'postgres'"), false, '有 env 兜底的不算写死');
});

// [D22 2026-10-09] 「失败可见化」守卫 —— `tamper-waf-matrix` 的 summary 必须真的连着 outcome。
//
// 背景（TODO 的 K 条「job 红了没人知道」）：该 job 只在 schedule / workflow_dispatch 跑，
// 平时没人盯。复核后确认 2026-09-22 那轮已把**真断言门禁**的 continue-on-error 去掉
// （那个开关本来就不阻塞 PR ⇒ 只买到"失败报成绿"），所以剩下的是**观察面**问题：
// 失败要在 job summary 里一眼可见。
//
// 判据不是"有没有那个 step"，而是**配对**：summary 读的 `steps.<id>.outcome` 必须与真实存在的
// `id:` 对得上。少一个 id ⇒ summary 恒显示"未跑" ⇒ 比没有 summary 更糟（它看起来像在工作）。
// 两个方向都钉：id 必须在、summary 必须读它。
test('★ D22：tamper-waf-matrix 的失败可见化 summary 与其 step id 严格配对', () => {
  const raw = readFileSync(path.join(REPO, '.github/workflows/ci.yml'), 'utf8');
  // 先切出该 job 的片段（下一个顶层 job 定义作为右边界），避免拿别的 job 的 id 蒙混
  const start = raw.indexOf('\n  tamper-waf-matrix:');
  assert.ok(start > 0, '找不到 tamper-waf-matrix job（ci.yml 结构变了？）');
  const rest = raw.slice(start + 1);
  const nextRel = rest.slice(1).search(/\n {2}[a-zA-Z0-9_-]+:\n/);
  const seg = nextRel > 0 ? rest.slice(0, nextRel + 1) : rest;
  // 分母守卫：切错片段（比如切空）会让后面全部"通过"
  assert.ok(seg.length > 3000, `job 段提取异常（${seg.length} 字符）⇒ 片段切分逻辑变了`);

  assert.match(seg, /门禁结果汇总（失败可见化）/, '缺少失败可见化 summary step（K 条的解法）');
  assert.match(seg, /GITHUB_STEP_SUMMARY/, 'summary 必须写进 job summary，否则等于没写');

  for (const id of ['matrix_measure', 'waf_gate']) {
    assert.match(seg, new RegExp(`^\\s+id: ${id}\\s*$`, 'm'), `step id \`${id}\` 缺失`);
    assert.match(
      seg,
      new RegExp(`steps\\.${id}\\.outcome`),
      `summary 必须读 \`steps.${id}.outcome\` —— 漏读会让该步结论恒显示"未跑"（比没有 summary 更误导）`,
    );
  }
});
