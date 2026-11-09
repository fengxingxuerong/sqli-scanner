// ============================================================================
// gateFastPlan.mjs —— gate:fast 的**受影响面推导**（纯函数，D280）
// ============================================================================
// 为什么要有这个模块：一批改动的收口全量 = gate:close ~25 分钟 + 验收 ~25 分钟，
// 批内迭代时「每改一行等一小时」税太重。gate:fast 的取舍标准与 .husky/pre-commit
// 同源（「每次都愿意付的代价」），但比 pre-commit 贵一点、比全量便宜两个数量级：
//   · **恒跑组**：跨文件的全仓静态判据（七道 guard + 预提交三道 + 引用/索引完整性
//     + 孤儿配置键）——它们不执行被测代码、不触网，实测合计 ≤1.5 分钟，且历史上
//     抓的都是「改 A 坏 B」形态（D249 arch、D251 error-contract、D279 孤儿键）。
//   · **受影响组**：按改动文件推导——src 改动映射到 import/命名命中它的测试，
//     scripts 改动映射到它自己的 --selftest，前端改动映射到 vitest + 前端类型，
//     文档/清单改动映射到三道一致性检查。
// 推导必须可单测 ⇒ 全部是**纯函数**：不 spawn、不落盘、不改 git 态；只有
// collectChangedFiles 一处读 git（与 plan 分离，方便用 --files 旁路）。
// 恒跑组**永远非空**（≥10 项）是本模块的不变式——空跑的快门禁等于没有门禁。
// ============================================================================
import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, basename } from 'node:path';

/** 恒跑组条目数下限（自证用：结构性缺失时计划必须显式失败而不是静默空转） */
export const ALWAYS_MIN = 10;

/**
 * 恒跑组：全仓静态判据（不执行被测代码 / 不触网 / 无副作用）。
 * 与 pre-commit 的取舍标准一致，但把「批内最常咬人」的全仓判据也纳入——
 * 七道 guard 在 D279 实测各 1~3s，arch 最大 ~20s，合计仍远低于 2 分钟。
 * @param {string} root 仓库根
 * @returns {Array<{name:string, cmd:string[]}>}
 */
export function alwaysSteps(root) {
  const guards = ['arch', 'nesting', 'complexity', 'duplication', 'deadcode', 'debt', 'typecoverage'];
  const precommit = [
    ['error-contract', 'scripts/error-contract-guard.mjs'],
    ['module-loadable', 'scripts/module-loadable.mjs'],
    ['version-sync', 'scripts/version-sync.mjs'],
  ];
  return [
    ...guards.map((g) => ({ name: g, cmd: ['node', `scripts/${g}-guard.mjs`] })),
    ...precommit.flatMap(([name, script]) => [{ name, cmd: ['node', script] }]),
    { name: 'refs', cmd: ['node', 'scripts/ref-integrity.mjs'] },
    { name: 'greenguard', cmd: ['node', 'scripts/greenguard-check.mjs'] },
    { name: 'changelog-index', cmd: ['node', 'scripts/changelog-index.mjs', '--check'] },
    // 孤儿配置键判据：D279 实测它抓得到「纯重构把解构改成成员读取」的副作用，
    // 且是 node --test 单文件 ~1s——是「跨文件判据放测试里」的最便宜一员。
    { name: 'orphan-keys', cmd: ['node', '--test', join('server', 'tests', 'configOrphanKeys.guard.test.js')] },
  ];
}

/**
 * 从 git 收集改动文件（工作区改动 + 暂存 + 未跟踪）。
 * @param {string} root 仓库根
 * @returns {string[]} posix 相对路径（仅现存文件；纯删除项无法映射，跳过并在调用方提示）
 */
export function collectChangedFiles(root) {
  const out = new Set();
  const run = (args) => spawnSync('git', args, { cwd: root, encoding: 'utf8', shell: process.platform === 'win32' });
  for (const args of [['status', '--porcelain'], ['diff', '--name-only', 'HEAD']]) {
    const r = run(args);
    if (r.status !== 0) continue;
    for (const line of (r.stdout || '').split(/\r?\n/)) {
      const p = line.replace(/^[^\s]+\s+/, '').replace(/^"|"$/g, '').trim();
      if (p && existsSync(join(root, p))) out.add(p.replace(/\\/g, '/'));
    }
  }
  return [...out].sort();
}

/** 一个受影响步骤（name + cmd），cmd 直接可 spawn */
/**
 * 找出引用了某 src 模块的测试文件。两层匹配：
 *   ① 文件名提示：测试文件名含 src 文件主干（csrfKeeper.js → csrfKeeper*.test.js）；
 *   ② 内容命中：测试文件内容含 src 文件主干（import 路径 / 关键导出名）。
 * 只读 server/tests 下 .test.js（~540 个文件、约 4MB），实测 <1s，不值得建索引。
 * @param {string} root 仓库根
 * @param {string} srcRel 形如 server/src/core/csrfKeeper.js 的 posix 相对路径
 * @returns {string[]} 相对仓库根的测试文件路径
 */
function testsForSrcFile(root, srcRel) {
  const stem = basename(srcRel).replace(/\.(js|mjs|cjs|ts|tsx)$/, '');
  if (!stem) return [];
  const dir = join(root, 'server', 'tests');
  const hits = [];
  let names = [];
  try { names = readdirSync(dir); } catch { return []; }
  for (const f of names) {
    if (!f.toLowerCase().endsWith('.test.js')) continue;
    if (f.toLowerCase().includes(stem.toLowerCase())) { hits.push(join('server', 'tests', f)); continue; }
    try {
      const src = readFileSync(join(dir, f), 'utf8');
      if (src.includes(stem)) hits.push(join('server', 'tests', f));
    } catch { /* 读不了的文件不拦路 */ }
  }
  return hits.sort();
}

/** 单个改动文件的分类与即时落步（scripts 类当场产出步骤，其余攒进 state 末尾统一落） */
function consumeFile(f, state, root, add, warnings) {
  if (f.startsWith('server/tests/') && f.endsWith('.test.js')) { state.serverTests.push(f); return; }
  if (f.startsWith('server/src/')) { state.srcStems.push(f); return; }
  if (f.startsWith('scripts/')) { planScriptStep(f, root, add, warnings); return; }
  if (f.startsWith('src/')) { state.frontend = true; return; }
  if (f.startsWith('e2e/')) { state.e2eLike = true; return; }
  if (/^(docs|recipes|skills)\//.test(f) || f.endsWith('.md')) { state.docsLike = true; return; }
  if (f === 'package.json' || f === 'server/package.json' || f.startsWith('server/bin/')) { state.manifestLike = true; return; }
  warnings.push(`改动的 ${f} 无自动映射——确认它属于哪个面（CI/文档/引擎），必要时显式跑对应门禁`);
}

/**
 * 自证入口的**形态**（不是「文件里出现过 --selftest 字样」）。
 * D280 收口实测：ci-local.mjs 把一堆 `--selftest` 当命令字符串存着，字符串包含判定
 * 会把「整套 CI 全跑」当成一步自证塞进快门禁，>240s 不返回，分层预算被打破；
 * 同形态第二例 gateFastPlan.mjs 是库模块，它没有入口，`node <file> --selftest` 顶层
 * 零断言直接 exit 0 ⇒ 恒绿假自证。判据脚本的入口统一在启动参数上判断自证旗标。
 */
const SELFTEST_ENTRY = /(?:argv|args)\b[^\n]{0,40}\.\s*(?:includes|has)\(\s*['"]--selftest['"]\s*\)/;

/** 只认代码行的启动参数判断：注释里的自然语言、清单里的命令字符串都不算入口 */
function hasSelftestEntry(text) {
  return text.split(/\r?\n/).some((line) => {
    const t = line.trim();
    if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) return false;
    return SELFTEST_ENTRY.test(line);
  });
}

/** scripts 改动：只认真正的自证入口；没有入口就不映射（宁可警告，不许假自证/拉全量） */
function planScriptStep(f, root, add, warnings) {
  const abs = join(root, f);
  try {
    if (!existsSync(abs)) { warnings.push(`改动的 ${f} 读不了内容（已删除？）`); return; }
    const text = readFileSync(abs, 'utf8');
    if (hasSelftestEntry(text)) {
      add(`selftest:${basename(f)}`, ['node', f, '--selftest']);
    } else {
      const hint = text.includes('--selftest') ? '（只在命令字符串里出现，不是自证入口）' : '';
      const tail = f.startsWith('scripts/lib/')
        ? '——库模块由消费者自证覆盖，不单独映射'
        : '——不映射自证；若为全量执行器，勿把它塞进快门禁';
      warnings.push(`改动的 ${f} 没有 --selftest 入口${hint}${tail}`);
    }
  } catch { warnings.push(`改动的 ${f} 读不了内容（已删除？）`); }
}

/** 分类攒完后统一落步骤（顺序：直接测试 → src 映射 → 前端 → e2e → 文档 → 清单 → 空集兜底） */
function emitGroupSteps(state, root, files, add) {
  let added = 0;
  const put = (name, cmd) => { added++; add(name, cmd); };
  if (state.serverTests.length) put('tests:direct', ['node', '--test', '--test-concurrency=4', ...state.serverTests]);
  if (state.srcStems.length) {
    const mapped = [...new Set(state.srcStems.flatMap((f) => testsForSrcFile(root, f)))];
    if (mapped.length) put('tests:src-mapped', ['node', '--test', '--test-concurrency=4', ...mapped]);
    put('typecheck:server', ['npm', 'run', '--silent', 'typecheck:server']);
  }
  if (state.frontend) {
    put('typecheck:frontend', ['npm', 'run', '--silent', 'typecheck:frontend']);
    put('tests:frontend', ['npm', 'run', '--silent', 'test']);
  }
  if (state.e2eLike) put('e2e-wiring', ['node', 'scripts/e2e-wiring-check.mjs']);
  if (state.docsLike) {
    put('facts', ['npm', 'run', '--silent', 'facts:check']);
    put('readme', ['node', 'scripts/readme-consistency.mjs']);
  }
  if (state.manifestLike) {
    put('facts', ['npm', 'run', '--silent', 'facts:check']);
    put('pack-check', ['node', 'scripts/pack-check.mjs']);
  }
  // 空改动集 = 全仓快检模式：受影响组不能为空（空跑的门禁会退化成装饰），
  // 补上最便宜的两道一致性检查——README/台账漂移即使没有代码改动也该被看见。
  if (files.length === 0 && added === 0) {
    put('facts', ['npm', 'run', '--silent', 'facts:check']);
    put('readme', ['node', 'scripts/readme-consistency.mjs']);
  }
}

/**
 * 受影响组：按改动文件推导要跑什么。
 * @param {string} root 仓库根
 * @param {string[]} files posix 相对路径（collectChangedFiles 的产物或 --files 旁路）
 * @returns {{affected:Array<{name:string, cmd:string[]}>, warnings:string[]}}
 */
export function affectedSteps(root, files) {
  const affected = [];
  const warnings = [];
  // 同一条命令可由多个面同时触发（docsLike + manifestLike 都会要 facts:check）——
  // 去重，别把同一判据跑两遍还让「步数」看起来比实际多。
  const add = (name, cmd) => {
    const key = JSON.stringify(cmd);
    if (!affected.some((s) => JSON.stringify(s.cmd) === key)) affected.push({ name, cmd });
  };
  const state = { serverTests: [], srcStems: [], frontend: false, docsLike: false, manifestLike: false, e2eLike: false };
  for (const f of files) consumeFile(f, state, root, add, warnings);
  for (const f of state.srcStems) {
    const hits = testsForSrcFile(root, f);
    if (hits.length === 0) warnings.push(`改动的 ${f} 没有映射到任何测试（文件名/内容都不含「${basename(f).replace(/\.js$/, '')}」）——若它确实有行为，请补判据或说明为何不需要`);
  }
  emitGroupSteps(state, root, files, add);
  return { affected, warnings };
}
