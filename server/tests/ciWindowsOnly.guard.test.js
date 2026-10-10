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
 * key = `${相对路径}:${模式id}:${内容锚点}`（锚点＝那一行去空白后的前 60 字符，见 snippetOf）
 * ⚠ 新增/修改登记项的正确姿势：把那行原文交给 regKey() 生成，**不要手抄**，
 *   也不要再用行号 —— 行号键三个月漂过四次，第四次是加一个靶场就触发。
 */
const KNOWN_SAFE = new Map([
  ['e2e/redteam-lab/env.mjs:exe:const MYSQLD = process.env.MYSQLD_PATH || \'D:/mysql/bin/mysq',
    '默认值，但下方（同函数 try/catch 内）有 `existsSync(MYSQLD)` 前置 + `[SKIP]` + exit 0 —— 见该文件 2026-09-21 的 CI-FIX 注释；CI 上实测输出 `[SKIP] 未找到 mysqld 二进制`，按设计跳过'],
  ['e2e/redteam-lab/env.mjs:drive:const MYSQLD = process.env.MYSQLD_PATH || \'D:/mysql/bin/mysq', '同上（同一行的路径默认值）'],
  ['e2e/redteam-lab/env.mjs:drive:const MYSQL_CWD = process.env.MYSQL_CWD || \'D:/mysql\';',
    'MYSQL_CWD 默认值，仅与 MYSQLD 配套使用；MYSQLD 不存在时不会走到 spawn'],
  ['e2e/redteam-lab/env.mjs:exe:const PG_EXE = process.env.PG_EXE || \'D:/pg-smoke/bin/bin/po',
    'PG_EXE 默认值；同文件对 PostgreSQL 有「已监听则复用」+ 缺失时的 SKIP 路径（CI 日志实测为跳过而非失败）'],
  ['e2e/redteam-lab/env.mjs:drive:const PG_EXE = process.env.PG_EXE || \'D:/pg-smoke/bin/bin/po', '同上（同一行的路径默认值）'],
  ['e2e/redteam-lab/env.mjs:drive:const PG_DATA = process.env.PG_DATA || \'D:/pg-smoke/data\';', 'PG_DATA 默认值，仅与 PG_EXE 配套'],
  ['e2e/redteam-lab/env.mjs:exe:// 硬等 60 秒才抛错。CI（ubuntu-latest）上 MYSQLD 默认值是 `D:/mysql/bin/m',
    '该行是**注释**（描述的正是这条 CI-FIX 本身），不参与执行'],
  ['e2e/redteam-lab/env.mjs:drive:// 硬等 60 秒才抛错。CI（ubuntu-latest）上 MYSQLD 默认值是 `D:/mysql/bin/m', '同上（同一行注释）'],
  // ── 键格式变更（2026-10-10 D34，TODO §8 的正解）───────────────────────────────
  //   旧键 `path:行号:kind` 三个月漂了四次，第四次是**往 run-all 的 LABS 里加一个靶场**触发的
  //   （177→182→186、216→221→254、195→225/263→318、152→159/225→232/318→325）。
  //   新键 `path:kind:内容锚点`（整行去空白后前 60 字符）不随行号移动，且 自证⑤ 两种口径都钉着：
  //   插 10 行注释必须仍绿、删掉命中行必须红；自证⑥ 另钉"一张牌不许盖多行"。
  //   ⚠ 改这些键的正确姿势：把该行原文交给 regKey() 生成，别手抄（手抄一个空格就静默失效）。
  ["e2e/run-all.mjs:exe:const exe = ['postgres.exe', 'postgres'].some((n) => fs.exis",
    '`pgSandboxAvailable()` 同时试 `postgres.exe` 与 POSIX 名 `postgres`，且整体包在 ' +
    '`fs.existsSync(path.join(PG_BIN_DIR, n))` 里 —— ubuntu 上两者都不存在 ⇒ 返回 false ⇒ ' +
    'PG 类靶场按口径如实 SKIP（不把环境问题记成靶场失败）。PG_BIN_DIR 本身可经环境变量 PG_BIN 覆盖'],
  ["e2e/run-all.mjs:exe:'C:\\\\Users\\\\Admin（无密码）\\\\.workbuddy\\\\binaries\\\\python\\\\versio",
    '`PY_CANDIDATES` 里的本机默认路径；解析时**逐个真跑 `-c print(1)`** 才算可用（2026-09-28 实测：该路径已是 0xC0000135 死链，只看 existsSync 挡不住），候选列表随后是 PATH 上的 `python`/`python3` ⇒ ubuntu 落到它们；全不可用则如实 SKIP'],
  ["e2e/run-all.mjs:drive:'C:\\\\Users\\\\Admin（无密码）\\\\.workbuddy\\\\binaries\\\\python\\\\versio", '同上（同一行的 python 默认路径）'],
  ['e2e/run-all.mjs:wincmd:spawn(\'taskkill\', [\'/pid\', String(p.pid), \'/T\', \'/F\'], { std',
    '该 `taskkill` 在 `if (process.platform === "win32" && p.pid)` 之内（**上一行**）—— 平台守卫是跨行的，行级判据看不到，故此处显式登记；else 分支走 `p.kill("SIGKILL")`'],
  ['e2e/waf-lab/compare-real.e2e.mjs:wincmd:` Windows: netstat -ano | findstr :${LAB_PORT} 然后 taskkill /',
    '该行是**错误提示文案**（端口被占时的排查建议），不参与执行；同段紧邻的下一行已给出 POSIX 方案 `lsof -ti :PORT | xargs kill -9`'],
]);

/**
 * 登记键的**内容锚点**（TODO §8 的正解，2026-10-10 D34 落地）。
 *
 * 为什么换：旧键是 `path:行号:kind`，行号随上游插入必然漂 —— 实测三个月漂了四次
 * （177→182→186、216→221→254、195→225/263→318、本批又 152→159/225→232/318→325），
 * 而且**第四次的触发条件是"往 run-all 的 LABS 里加一个靶场"** —— 那是本仓最常见的正常操作。
 * 每次漂移都要人记得去核对行号，这本身就是判据失效的形状（忘了核对 = 免检牌发到不存在的行上，
 * 而那条真正的 Windows-only 依赖变成"未登记"→ 要么假红要么假绿）。
 *
 * 锚点取「整行去空白后前 60 字符」：足够定位到具体那一处，又不会因为缩进/换行风格而变。
 */
export function snippetOf(line) {
  return String(line ?? '').trim().replace(/\s+/g, ' ').slice(0, 60);
}

/** 登记键：`路径:kind:内容锚点` */
export function regKey(rel, modeId, line) {
  return `${rel}:${modeId}:${snippetOf(line)}`;
}

/**
 * 登记表健康检查（纯函数，便于用合成文本反证）：
 * 每个登记项必须**恰好命中一行**。0 行 = 腐烂（免检牌指向已经不存在的代码）；
 * ≥2 行 = 一张牌覆盖了多处（其中可能藏着新加的那处真违规）。
 * @param {string} rel 相对路径（仅用于报错文案）
 * @param {string[]} lines 该文件按行切开的文本
 * @param {Map<string,string>} knownSafe 登记表
 * @returns {string[]} 问题清单（空 = 健康）
 */
export function staleRegistrations(rel, lines, knownSafe = KNOWN_SAFE) {
  const out = [];
  for (const key of knownSafe.keys()) {
    if (!key.startsWith(`${rel}:`)) continue;
    const rest = key.slice(rel.length + 1);
    const sep = rest.indexOf(':');
    const modeId = rest.slice(0, sep);
    const anchor = rest.slice(sep + 1);
    const pat = WINDOWS_ONLY.find((p) => p.id === modeId);
    if (!pat) { out.push(`${key} —— kind "${modeId}" 不在模式表里（登记项格式错）`); continue; }
    const matched = [];
    lines.forEach((l, i) => {
      if (pat.re.test(l) && snippetOf(l) === anchor) matched.push(i + 1);
    });
    if (matched.length === 0) {
      const now = lines.map((l, i) => (pat.re.test(l) ? i + 1 : 0)).filter(Boolean);
      out.push(
        `${key} —— 这条内容锚点在该文件里已不存在（代码变了，登记项该删或重新核对）`
        + `；该 kind 当前命中行：${now.length ? now.join(', ') : '（无）'}`,
      );
    } else if (matched.length > 1) {
      out.push(
        `${key} —— 内容锚点命中 ${matched.length} 行（${matched.join(', ')}）：`
        + '一张免检牌覆盖多处 = 新加的那处真违规也会被静默放过。请把锚点写得更具体（加长片段），'
        + '或为每一行分别登记并各写理由',
      );
    }
  }
  return out;
}

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
      const key = regKey(rel, pat.id, line);
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

test('自证③：登记表不得虚胖 —— 每个登记项必须仍**恰好**命中一行（防腐烂，也不许一张牌盖多处）', () => {
  const rels = [...new Set([...KNOWN_SAFE.keys()].map((k) => k.slice(0, k.indexOf(':'))))];
  assert.ok(rels.length >= 3, `登记表只覆盖 ${rels.length} 个文件 —— 判据可能已经空转`);
  const stale = [];
  for (const rel of rels) {
    const abs = path.join(REPO, rel);
    if (!existsSync(abs)) {
      // 文件没了 ⇒ 它名下每个登记项都算陈旧（"缺失即报错"，同 facts 的口径，不静默通过）
      for (const k of [...KNOWN_SAFE.keys()].filter((x) => x.startsWith(`${rel}:`))) {
        stale.push(`${k} —— 文件已不存在`);
      }
      continue;
    }
    stale.push(...staleRegistrations(rel, readFileSync(abs, 'utf8').split(/\r?\n/)));
  }
  assert.deepEqual(stale, [], `登记表有问题（${stale.length} 项）：\n  ${stale.join('\n  ')}`);
});

test('自证⑤：内容锚点不随**行号漂移**失效（TODO §8 的验证口径，两种都要）', () => {
  const rel = 'SYNTHETIC-drift.mjs';
  const target = "  const exe = ['postgres.exe', 'postgres'].some((n) => existsSync(n));";
  const one = `${target}\n  spawn('taskkill', ['/pid', String(p.pid)]);\n`;
  const reg = new Map([[regKey(rel, 'exe', target), '合成：仅供自证']]);
  // 基线：登记项只豁免它那一处，另一处仍必须报 ⇒ 判据没有整体放水
  assert.deepEqual(scanText(rel, one, reg).map((h) => h.id), ['wincmd'], '基线应只剩 wincmd 未登记');
  assert.deepEqual(staleRegistrations(rel, one.split('\n'), reg), [], '合成登记项本应健康');
  // 口径①：文件顶部插 10 行注释 ⇒ 行号整体下移 ⇒ 锚点必须仍然成立（旧的 path:行号:kind 键在这里必红）
  const shifted = `${'// 插入的注释行\n'.repeat(10)}${one}`;
  assert.deepEqual(
    scanText(rel, shifted, reg).map((h) => h.id),
    ['wincmd'],
    '插 10 行注释后同一处又被报成违规 ⇒ 锚点还在随行号失效',
  );
  assert.deepEqual(staleRegistrations(rel, shifted.split('\n'), reg), [], '插注释不该让登记项变陈旧');
  // 口径②：把那行 Windows-only 代码删掉 ⇒ 登记项必须立刻陈旧（否则免检牌指向不存在的代码）
  const stale = staleRegistrations(rel, "  spawn('taskkill', ['/pid', String(p.pid)]);\n".split('\n'), reg);
  assert.equal(stale.length, 1, '删掉命中行后登记项仍"健康" = 假绿');
  assert.match(stale[0], /已不存在/);
});

test('自证⑥：同一锚点覆盖多行时必须报错（一张免检牌不许盖住新加的违规）', () => {
  const rel = 'SYNTHETIC-dup.mjs';
  const dup = "  const exe = 'mysqld.exe';";
  const reg = new Map([[regKey(rel, 'exe', dup), '合成：故意让两行同形']]);
  const stale = staleRegistrations(rel, `${dup}\n${dup}\n`.split('\n'), reg);
  assert.equal(stale.length, 1, '两处同形命中应报"一张牌盖多处"，实得 0 ⇒ 新加的那处会被静默放过');
  assert.match(stale[0], /命中 2 行/);
  // 反方向自证：若判据本身连这两行都扫不出来，上面那条就是空转
  assert.equal(scanText(rel, `${dup}\n${dup}\n`, new Map()).filter((h) => h.id === 'exe').length, 2);
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
