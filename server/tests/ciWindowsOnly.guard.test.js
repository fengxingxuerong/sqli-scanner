// ============================================================================
// ciWindowsOnly.guard.test.js —— 「CI 步骤里藏着 Windows-only 依赖」守卫
//
// 为什么必须有（2026-09-27 实测教训，本仓最贵的一类错：**假绿**）：
//   `tamper-waf-matrix` 的 WAF A/B 门禁在 ubuntu runner 上**从未成功过**，
//   却长期以「绿」或「跳过」两种形态存在，直到有人手动 dispatch 才暴露。根因是那一步
//   调 `compare-real.run.py` → `e2e/udf-lab/mysql_sandbox.py`，而后者是 **Windows 专用**：
//     `MYSQLD = MYSQL_HOME/"bin"/"mysqld.exe"`（硬编码 .exe）、`MYSQL_HOME` 默认 `D:\mysql`、
//     进程管理用 `tasklist`/`taskkill`，且全文**零平台分支**。
//   ⇒ 在 ubuntu 上连 `--init` 都跑不起来（路径不存在，FileNotFoundError）。
//
//   它为什么能潜伏这么久 —— 三种掩盖形态，本守卫要防的正是这三种：
//     ① **job 级跳过**：该 job 只在 schedule / workflow_dispatch 触发，push 时整 job skipped；
//     ② **continue-on-error**：该步曾带它（2026-09-22 才去掉），失败被吞成绿 ——
//        run #10 显示 success 就是这形态，它当时同样在失败；
//     ③ **路径没走到**：acceptance 里那条同类沙箱路径只在宿主不放行 secure_file_priv
//        时才走，而它起的 docker MySQL 已放行 ⇒ 沙箱重试从不触发 ⇒「没走到」被读成「能跑」。
//
// 判据（三向，缺一不可 —— 与 ciWiring.guard / ref-integrity 同构）：
//   ① 检出：ci.yml 的 `run:` 里指向**本仓脚本**的，该脚本不得含**未登记**的
//      Windows-only 模式（.exe 硬编码 / 盘符路径 / tasklist|taskkill|wmic）；
//   ② 不空转：扫描器必须真能扫到脚本与命中（否则"零违规"可能是扫描器自己的锅）；
//   ③ 反例自证：用合成片段证明判据会红（断言不敏感 = 假绿，正是本守卫要防的东西）。
//
// 为什么用「显式登记」而不是纯静态判定：
//   多处命中是**合法的**（默认值 + 跨行守卫 / 纯错误提示文案）。判据若只看单行，
//   会把 `env.mjs`（有 `existsSync` 前置 + `[SKIP]`）和 `run-all.mjs:216`
//   （`process.platform` 守卫在**上一行**）全报成违规 —— 噪声淹没信号。
//   故采用本仓既有模式（同 `KNOWN_MISSING_UI_KEYS` / `EXCLUDED_JOBS` / `.arch-baseline.json`）：
//   **把已核实的例外显式登记 + 写清理由**，未登记的新命中立刻红；并加**反向断言**防登记表腐烂。
//
// 为什么只查 ci.yml 的 run: 而不查全仓：
//   本机开发脚本（`e2e/udf-lab/*.py`、`mysql_sandbox.py`）**本来就是 Windows 工具链**，
//   在 Windows 本机跑是正确用法 —— 全仓扫会把它们全报成违规。真正的风险面只有一处：
//   **CI 会在 ubuntu 上执行的那些命令**。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const CI_YML = path.join(REPO, '.github', 'workflows', 'ci.yml');

/** Windows-only 模式 —— 只保留**可能导致运行时失败**的，不含纯文案特征。 */
const WINDOWS_ONLY = [
  { id: 'exe', re: /['"`][^'"`\n]*\.exe['"`]/, desc: '硬编码 .exe 可执行文件路径' },
  { id: 'drive', re: /['"`][A-Za-z]:[\\/]/, desc: '硬编码 Windows 盘符路径' },
  { id: 'wincmd', re: /\b(tasklist|taskkill|wmic)\b/, desc: 'Windows 专用进程/系统命令' },
];

/**
 * 已核实的合法例外。**每条都必须写清"为什么安全"** —— 只写"已检查"等于没写。
 * key = `${相对路径}:${行号}:${模式id}`
 */
const KNOWN_SAFE = new Map([
  ['e2e/redteam-lab/env.mjs:17:exe',
    '默认值，但下方（同函数 try/catch 内）有 `existsSync(MYSQLD)` 前置 + `[SKIP]` + exit 0 —— 见该文件 2026-09-21 的 CI-FIX 注释；CI 上实测输出 `[SKIP] 未找到 mysqld 二进制`，按设计跳过'],
  ['e2e/redteam-lab/env.mjs:17:drive', '同上（同一行的路径默认值）'],
  ['e2e/redteam-lab/env.mjs:18:drive',
    'MYSQL_CWD 默认值，仅与 MYSQLD 配套使用；MYSQLD 不存在时不会走到 spawn'],
  ['e2e/redteam-lab/env.mjs:24:exe',
    'PG_EXE 默认值；同文件对 PostgreSQL 有「已监听则复用」+ 缺失时的 SKIP 路径（CI 日志实测为跳过而非失败）'],
  ['e2e/redteam-lab/env.mjs:24:drive', '同上（同一行的路径默认值）'],
  ['e2e/redteam-lab/env.mjs:25:drive', 'PG_DATA 默认值，仅与 PG_EXE 配套'],
  ['e2e/redteam-lab/env.mjs:50:exe',
    '该行是**注释**（`// 硬等 60 秒才抛错。CI（ubuntu-latest）上 MYSQLD 默认值是 ...`），描述的正是这条 CI-FIX 本身'],
  ['e2e/redteam-lab/env.mjs:50:drive', '同上（同一行注释）'],
  ['e2e/run-all.mjs:177:exe',
    '`py` 变量**只在 useSandbox=true 时使用**（下一行 `const cmd = useSandbox ? py : "node"`）；而 useSandbox 由 `sandboxAvailable()` 决定，CI 上沙箱 datadir 不存在 ⇒ 该分支不进入'],
  ['e2e/run-all.mjs:177:drive', '同上（同一行的 python 默认路径）'],
  ['e2e/run-all.mjs:216:wincmd',
    '该 `taskkill` 在 `if (process.platform === "win32" && p.pid)` 之内（**上一行**）—— 平台守卫是跨行的，行级判据看不到，故此处显式登记'],
  ['e2e/waf-lab/compare-real.e2e.mjs:154:wincmd',
    '该行是**错误提示文案**（端口被占时的排查建议），不参与执行；同段紧邻的下一行已给出 POSIX 方案 `lsof -ti :PORT | xargs kill -9`'],
]);

/** 抽 ci.yml 里「会指向本仓脚本」的命令 token（只认 node/python + 脚本扩展名）。 */
export function extractScriptInvocations(ymlText) {
  const out = [];
  for (const line of ymlText.split(/\r?\n/)) {
    const t = line.trim();
    if (t.startsWith('#')) continue; // 注释不是执行
    for (const m of t.matchAll(/\b(?:node|python3?|bash|sh)\s+([^\s'"`|;&]+\.(?:mjs|js|cjs|py|sh))\b/g)) {
      out.push(m[1]);
    }
  }
  return [...new Set(out)];
}

/**
 * 追踪「ci.yml 直接调用的脚本」→ 它 import 的本仓文件（**一层**）。
 *
 * 为什么必须有这一层：2026-09-27 那次的真实路径是
 *   ci.yml → `compare-real.run.py` → `import mysql_sandbox`（经 sys.path.insert）
 * 而 **Windows-only 的代码在 mysql_sandbox.py 里，不在被直接调用的那个文件里**。
 * 只扫直接调用点会漏掉它 —— 这正是本守卫要防的「判据看不见它声称在管的东西」。
 *
 * 只做一层（不递归）：一层已覆盖实测形态，且避免把整个依赖图拉进来导致噪声。
 */
export function reachableLocalFiles(rel, text) {
  const out = [];
  const dir = path.posix.dirname(rel.split(path.sep).join('/'));
  if (rel.endsWith('.py')) {
    // Python：解析 `import X` / `from X import`，并在①同目录 ②sys.path.insert 注入的目录里找 X.py
    const searchDirs = [dir];
    for (const m of text.matchAll(/sys\.path\.insert\(\s*\d+\s*,\s*str\(\s*[\w.]+\s*\/\s*"([^"]+)"\s*\/\s*"([^"]+)"\s*\)\s*\)/g)) {
      searchDirs.push(`${m[1]}/${m[2]}`);
    }
    const mods = new Set();
    for (const m of text.matchAll(/^\s*import\s+([A-Za-z_][\w.]*)/gm)) mods.add(m[1].split('.')[0]);
    for (const m of text.matchAll(/^\s*from\s+([A-Za-z_][\w.]*)\s+import/gm)) mods.add(m[1].split('.')[0]);
    for (const mod of mods) {
      for (const d of searchDirs) {
        const cand = path.posix.normalize(`${d}/${mod}.py`);
        if (existsSync(path.join(REPO, cand))) { out.push(cand); break; }
      }
    }
  } else {
    // JS/TS：只跟相对路径 import（外部包不在本仓）
    for (const m of text.matchAll(/(?:from|require\()\s*['"](\.[^'"]+)['"]/g)) {
      const base = path.posix.normalize(`${dir}/${m[1]}`);
      for (const ext of ['', '.js', '.mjs', '.cjs', '/index.js']) {
        const cand = base + ext;
        if (existsSync(path.join(REPO, cand))) { out.push(cand); break; }
      }
    }
  }
  return [...new Set(out)];
}

/** 扫描一个脚本文本，返回未登记的命中列表。 */
export function scanText(rel, text, knownSafe = KNOWN_SAFE) {
  const hits = [];
  const lines = text.split(/\r?\n/);
  for (const [i, line] of lines.entries()) {
    for (const pat of WINDOWS_ONLY) {
      if (!pat.re.test(line)) continue;
      const key = `${rel}:${i + 1}:${pat.id}`;
      if (knownSafe.has(key)) continue;
      hits.push({ key, line: i + 1, id: pat.id, desc: pat.desc, text: line.trim().slice(0, 90) });
    }
  }
  return hits;
}

const CI_TEXT = readFileSync(CI_YML, 'utf8');
const INVOCATIONS = extractScriptInvocations(CI_TEXT);

test('自证①：扫描器真能抽到脚本调用（否则"零违规"可能是解析写错）', () => {
  assert.ok(INVOCATIONS.length > 0, '未从 ci.yml 抽到任何本仓脚本调用 —— 解析逻辑需同步 ci.yml 的写法');
  assert.ok(
    INVOCATIONS.some((p) => p.includes('ref-integrity.mjs')),
    `未抽到 ref-integrity.mjs，实际抽到：${INVOCATIONS.join(', ')}`,
  );
  assert.ok(INVOCATIONS.some((p) => p.includes('compare-real.e2e.mjs')), '未抽到 compare-real.e2e.mjs');
});

test('自证④：import 链追踪必须真能到达 mysql_sandbox.py（那次 bug 的间接路径）', () => {
  // 回归守卫：2026-09-27 的真实路径是 compare-real.run.py → import mysql_sandbox（经 sys.path.insert），
  // 而 Windows-only 的代码在 mysql_sandbox.py 里。若这层追踪失效，本守卫就漏掉整个 bug 形态。
  const runner = path.join(REPO, 'e2e', 'waf-lab', 'compare-real.run.py');
  if (!existsSync(runner)) return; // 文件被删时跳过（存在性归 ref-integrity）
  const deps = reachableLocalFiles('e2e/waf-lab/compare-real.run.py', readFileSync(runner, 'utf8'));
  assert.ok(
    deps.includes('e2e/udf-lab/mysql_sandbox.py'),
    `import 链追踪未到达 mysql_sandbox.py，实际到达：${deps.join(', ') || '（空）'}`,
  );
});

test('自证②：判据对合成反例必须敏感（防断言空转 —— 本守卫要防的正是这个）', () => {
  const synthetic = [
    "const MYSQLD = process.env.MYSQLD_PATH || 'D:/mysql/bin/mysqld.exe';",
    "spawn('taskkill', ['/pid', String(p.pid)]);",
  ].join('\n');
  const hits = scanText('SYNTHETIC.js', synthetic, new Map());
  assert.ok(hits.length >= 3, `合成反例应命中至少 3 处（exe/drive/wincmd），实际 ${hits.length}：${JSON.stringify(hits)}`);
  assert.ok(hits.some((h) => h.id === 'exe'), '未命中 .exe 模式');
  assert.ok(hits.some((h) => h.id === 'drive'), '未命中盘符模式');
  assert.ok(hits.some((h) => h.id === 'wincmd'), '未命中 Windows 命令模式');
});

test('自证③：登记表不得虚胖 —— 每个登记项必须仍真实命中（防腐烂）', () => {
  const cache = new Map();
  const stale = [];
  for (const key of KNOWN_SAFE.keys()) {
    const m = /^(.*):(\d+):([a-z]+)$/.exec(key);
    assert.ok(m, `登记项格式非法（应为 path:line:modeId）：${key}`);
    const [, rel, lineStr, modeId] = m;
    const abs = path.join(REPO, rel);
    if (!existsSync(abs)) { stale.push(`${key} —— 文件已不存在`); continue; }
    if (!cache.has(rel)) cache.set(rel, readFileSync(abs, 'utf8').split(/\r?\n/));
    const line = cache.get(rel)[Number(lineStr) - 1];
    if (line === undefined) { stale.push(`${key} —— 行号超出范围（文件变短了？）`); continue; }
    const pat = WINDOWS_ONLY.find((p) => p.id === modeId);
    if (!pat.re.test(line)) stale.push(`${key} —— 该行已不再命中「${pat.desc}」（代码变了，登记项该删）`);
  }
  assert.deepEqual(stale, [], `登记表腐烂了（${stale.length} 项）：\n  ${stale.join('\n  ')}`);
});

test('① 检出：ci.yml 指向的本仓脚本（含一层 import 链）不得含未登记的 Windows-only 依赖', () => {
  const violations = [];
  const scanned = new Set();
  const queue = [...INVOCATIONS];
  for (const rel of queue) {
    const posixRel = rel.split(path.sep).join('/');
    if (scanned.has(posixRel)) continue;
    scanned.add(posixRel);
    const abs = path.join(REPO, rel);
    if (!existsSync(abs)) continue; // 存在性归 ref-integrity 管，此处不重复报
    const text = readFileSync(abs, 'utf8');
    for (const h of scanText(posixRel, text)) {
      violations.push(`${posixRel}:${h.line}  [${h.desc}]  ${h.text}`);
    }
    // 一层 import 链：Windows-only 的代码常常不在被直接调用的那个文件里
    for (const dep of reachableLocalFiles(posixRel, text)) queue.push(dep);
  }
  assert.deepEqual(
    violations,
    [],
    `ci.yml 会在 ubuntu runner 上执行这些脚本，但它们含**未登记**的 Windows-only 依赖：\n  ` +
      violations.join('\n  ') +
      '\n\n本仓 2026-09-27 实测：`mysql_sandbox.py` 正是此形态，导致 tamper-waf-matrix 的 WAF A/B\n' +
      '门禁在 ubuntu 上**从未成功过**，却因 job 级跳过 + continue-on-error 长期不可见。\n\n' +
      '修法三选一：\n' +
      '  ① 加平台守卫（`process.platform === "win32"` / `existsSync` 前置 + `[SKIP]`）；\n' +
      '  ② 若它本就只能在 Windows 用，就别挂在 ubuntu 的 CI 步骤上；\n' +
      '  ③ 若确属合法（如纯错误提示文案），加进 KNOWN_SAFE 并**写清为什么安全**。',
  );
});
