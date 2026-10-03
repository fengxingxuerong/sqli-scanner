// ============================================================================
// actionYaml.wiring.test.js —— action.yml 的**接线守卫**
// ============================================================================
// 守什么：`action.yml` 是本仓对外的 CI 入口，它把开关名、input 名、step id、
// 输出键、格式名**硬编码成字符串**。这类「字符串契约」没有类型系统兜底：
// 有人把 CLI 的 `--technique` 改名、或把某个 input 从 `scope` 改成 `scopes`，
// YAML 本身完全合法、YAML 解析也不报错，但 action 会在使用者那边**静默失效**
// （参数被 unknownFlags 拒绝或表达式求值为空）——正是本仓反复栽的「判据采集面 ≠ 真实实现面」。
//
// 判据全部落在**行为**上，而不是「文本里有没有这个词」：
//   ① action 塞进 ARGS 的每个开关，都必须被 `parseArgs` 接受（用真实的 `unknownFlagError` 判）。
//   ② 每个 `${{ inputs.x }}` 引用的 input 必须在 `inputs:` 里声明。
//   ③ 每个 `${{ steps.<id>.outputs.<k> }}` 引用的 step id 必须存在，且该 step 的 run 体里
//      确实 `echo "<k>=" >> $GITHUB_OUTPUT`（否则 output 恒为空 —— 声明了但没人写）。
//   ④ `--formats` 的默认值必须 ⊆ `scripts/one-click-scan.mjs` 里真实的 `FORMATS` 数组
//      （从源码字面量解析，且断言解析非空 ⇒ 防「正则没匹上导致的空转绿」）。
//   ⑤ 结构不变量：扫描步骤的 cwd = `github.action_path`（否则在 action checkout 里跑）、
//      `--out` 用 `github.workspace` 绝对路径（否则报告写进 action 目录被丢弃）、
//      SARIF 上传带 `always()` + formats 含 sarif 的门禁、退出码三分（0/1/2）在 enforce 步骤判定。
//
// 反空转（自证）：末尾有一条 selftest，断言「判据真的能把一个不存在的开关判死」。
// 本仓教训：首跑全绿要先怀疑解析空转，而不是先庆祝。
//
// ⚠ 刻意不 import 根 devDependencies（如 `yaml`）：CI 的 test-server job 只跑
//   `cd server && npm ci`，根本 node_modules 不存在 —— 用 `yaml` 会在 CI 直接 ERR_MODULE_NOT_FOUND，
//   本地却全绿（又一个「本地绿、CI 红」的形态）。故此处用**窄结构化解析**，边界由自证钉住。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { parseArgs, unknownFlagError } from '../bin/cli/args.js';

const ACTION_PATH = fileURLToPath(new URL('../../action.yml', import.meta.url));
const ONE_CLICK_PATH = fileURLToPath(new URL('../../scripts/one-click-scan.mjs', import.meta.url));

const ACTION_SRC = readFileSync(ACTION_PATH, 'utf8');
// 去注释行（判据文本源必须排除注释：本仓 10-03 两次因注释被当成判据而假绿）。
const CODE_LINES = ACTION_SRC.split(/\r?\n/).filter((l) => !/^\s*#/.test(l));
const CODE = CODE_LINES.join('\n');

/** 取顶层 `key:` 段（到下一个顶格行为止）。找不到时返回 null（由调用方断言非空）。 */
function topSection(key) {
  const lines = CODE_LINES;
  const start = lines.findIndex((l) => l === `${key}:` || l.startsWith(`${key}:`));
  if (start < 0) return null;
  const out = [];
  for (let i = start + 1; i < lines.length; i++) {
    if (/^\S/.test(lines[i])) break;
    out.push(lines[i]);
  }
  return out.join('\n');
}

/** 取 2 空格缩进段里的某个条目块（条目名到下一个同级条目）。 */
function subEntry(sectionText, name) {
  if (!sectionText) return null;
  const lines = sectionText.split(/\r?\n/);
  const start = lines.findIndex((l) => new RegExp(`^ {2}${name}:`).test(l));
  if (start < 0) return null;
  const out = [lines[start]];
  for (let i = start + 1; i < lines.length; i++) {
    if (/^ {2}\S/.test(lines[i])) break;
    out.push(lines[i]);
  }
  return out.join('\n');
}

const INPUTS_SECTION = topSection('inputs');
const OUTPUTS_SECTION = topSection('outputs');
const RUNS_SECTION = topSection('runs');

/** action 里声明的 input 名集合 */
const declaredInputs = new Set(
  (INPUTS_SECTION || '')
    .split(/\r?\n/)
    .map((l) => l.match(/^ {2}([A-Za-z0-9_-]+):\s*$/)?.[1])
    .filter(Boolean)
);

/** step id 集合 */
const stepIds = new Set(
  [...CODE.matchAll(/^\s+id:\s*([A-Za-z0-9_-]+)\s*$/gm)].map((m) => m[1])
);

/** `${{ inputs.x }}` 全部引用 */
const inputRefs = new Set([...CODE.matchAll(/\binputs\.([A-Za-z0-9_-]+)\b/g)].map((m) => m[1]));

/** `steps.<id>.outputs.<key>` 全部引用 */
const outputRefs = [...CODE.matchAll(/\bsteps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\b/g)]
  .map((m) => ({ step: m[1], key: m[2] }));

/** action 塞进 ARGS 的开关（只认 ARGS 赋值行 —— 避免读到 shell 内建开关如 `read -r -a`） */
const argsFlagLines = CODE_LINES.filter((l) => /^\s*ARGS\+?=\(/.test(l));
const argsFlags = [...new Set(
  argsFlagLines.flatMap((l) => [...l.matchAll(/(^|\s)(-{1,2}[A-Za-z][A-Za-z0-9-]*)/g)].map((m) => m[2]))
)];

/** `scripts/one-click-scan.mjs` 自带、不经过 args.js 解析的开关（先被 splitOwnArgs 摘走） */
const ONE_CLICK_OWN_FLAGS = new Set(['-F', '--formats', '--no-ledger', '--quiet']);

/** 从 one-click 源码解析真实 FORMATS 字面量（用于 ④） */
function oneClickFormats() {
  const src = readFileSync(ONE_CLICK_PATH, 'utf8');
  const m = src.match(/const FORMATS = \[([^\]]*)\]/);
  assert.ok(m, 'on one-click-scan.mjs 里应有 `const FORMATS = [...]`（解析失败 ⇒ 判据 ④ 会空转）');
  return m[1].split(',').map((s) => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
}

// ─────────────────────────────────────────────────────────────────────────────
// 0) 反空转自证：判据必须真的能判死一个不存在的开关
// ─────────────────────────────────────────────────────────────────────────────
test('action wiring: 自证 —— 判据能把不存在的开关判死（防解析空转）', () => {
  assert.notEqual(unknownFlagError(parseArgs(['--definitely-not-a-real-flag'])), null);
  assert.equal(unknownFlagError(parseArgs(['--technique', 'union'])), null);
});

// ─────────────────────────────────────────────────────────────────────────────
// 1) 解析结构非空（否则下面所有断言都在空集合上「全绿」）
// ─────────────────────────────────────────────────────────────────────────────
test('action wiring: YAML 结构解析非空（inputs / outputs / runs / ARGS 开关）', () => {
  assert.ok(INPUTS_SECTION, '应能切出 inputs: 段');
  assert.ok(OUTPUTS_SECTION, '应能切出 outputs: 段');
  assert.ok(RUNS_SECTION, '应能切出 runs: 段');
  assert.ok(declaredInputs.size >= 10, `声明的 input 应 >= 10，实得 ${declaredInputs.size}`);
  assert.ok(argsFlags.length >= 8, `ARGS 里的开关应 >= 8，实得 ${argsFlags.length}: ${argsFlags.join(' ')}`);
  assert.ok(stepIds.has('scan'), '应存在 id: scan 的步骤');
});

// ─────────────────────────────────────────────────────────────────────────────
// 2) 每个 ARGS 开关都必须被真实解析器接受
// ─────────────────────────────────────────────────────────────────────────────
test('action wiring: action 用到的每个 CLI 开关都被 parseArgs 接受', () => {
  const bad = [];
  for (const flag of argsFlags) {
    if (ONE_CLICK_OWN_FLAGS.has(flag)) continue;
    if (unknownFlagError(parseArgs([flag])) !== null) bad.push(flag);
  }
  assert.deepEqual(bad, [], `action 引用了 CLI 不认识的开关（改名/拼错）：${bad.join(' ')}`);
});

test('action wiring: 关键开关确实在 ARGS 里（防止有人整段删掉）', () => {
  for (const f of ['-u', '-F', '-o', '--scope', '--level', '--risk']) {
    assert.ok(argsFlags.includes(f), `ARGS 应包含 ${f}`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3) inputs 引用闭合
// ─────────────────────────────────────────────────────────────────────────────
test('action wiring: 每个 ${{ inputs.x }} 引用都在 inputs: 里声明', () => {
  const missing = [...inputRefs].filter((n) => !declaredInputs.has(n));
  assert.deepEqual(missing, [], `引用了未声明的 input：${missing.join(', ')}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// 4) outputs 引用闭合：step id 存在 + 该 step 真的往 $GITHUB_OUTPUT 写了该键
// ─────────────────────────────────────────────────────────────────────────────
test('action wiring: 每个 steps.<id>.outputs.<key> 都有对应的 step 与 echo 写入', () => {
  assert.ok(outputRefs.length > 0, '应有 outputs 引用（否则本判据空转）');
  for (const { step, key } of outputRefs) {
    assert.ok(stepIds.has(step), `引用了不存在的 step：${step}`);
    // 键必须由该 step 真实写出，否则 output 恒为空字符串（声明了、没人写）
    assert.match(
      CODE,
      new RegExp(`echo "${key}=`),
      `step ${step} 的输出键 "${key}" 没有对应的 echo 写入`
    );
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 5) --formats 默认值 ⊆ one-click 的真实 FORMATS
// ─────────────────────────────────────────────────────────────────────────────
test('action wiring: formats 默认值都在 one-click-scan.mjs 支持的格式内', () => {
  const formatsEntry = subEntry(INPUTS_SECTION, 'formats');
  assert.ok(formatsEntry, 'inputs.formats 条目应存在');
  const def = formatsEntry.match(/default:\s*'([^']*)'/)?.[1] ?? '';
  assert.ok(def.length > 0, 'formats 应有非空默认值');
  const supported = new Set(oneClickFormats());
  assert.ok(supported.size >= 3, `解析到的 FORMATS 应 >= 3，实得 ${[...supported].join(',')}`);
  const bad = def.split(',').map((s) => s.trim()).filter(Boolean).filter((f) => !supported.has(f));
  assert.deepEqual(bad, [], `formats 默认值含不支持项：${bad.join(', ')}`);
});

// ─────────────────────────────────────────────────────────────────────────────
// 6) 结构不变量（每一条都对应一个会「静默失效」的写法）
// ─────────────────────────────────────────────────────────────────────────────
test('action wiring: 扫描步骤用 one-click 入口，cwd = action_path，--out 用 workspace 绝对路径', () => {
  assert.match(CODE, /scripts\/one-click-scan\.mjs/, 'action 应调用 scripts/one-click-scan.mjs');
  assert.match(
    CODE,
    /working-directory:\s*\$\{\{\s*github\.action_path\s*\}\}/,
    '扫描步骤的 working-directory 必须是 github.action_path'
  );
  // --out 必须是绝对路径：本步骤 cwd 是 action 的 checkout，相对路径会把报告写进
  // action 目录、随 runner 一起被丢弃。这里钉两处紧邻事实：① 输出目录由 github.workspace 派生；
  // ② `-o` 用的正是那个变量（只钉①会漏掉「变量换了名字但 -o 还指着旧的」）。
  assert.match(
    CODE,
    /OUT_DIR="\$\{\{\s*github\.workspace\s*\}\}\//,
    '输出目录必须由 github.workspace 派生（相对路径会被写进 action 的 checkout）'
  );
  assert.match(CODE, /-o\s+"\$OUT_DIR"/, '--out 必须传上面那个绝对路径变量');
});

test('action wiring: SARIF 上传带 always() 与 formats 门禁', () => {
  const sarifStep = CODE.split(/\n\s+- name:/).find((s) => /upload-sarif@/.test(s));
  assert.ok(sarifStep, '应有 codeql-action/upload-sarif 步骤');
  assert.match(sarifStep, /always\(\)/, 'SARIF 上传应带 always()（扫描失败也要留证据）');
  assert.match(sarifStep, /contains\(\s*inputs\.formats\s*,\s*'sarif'\s*\)/, 'SARIF 上传应受 formats 含 sarif 门禁');
});

test('action wiring: 退出码三分在 enforce 步骤判定，且 1（没扫成）永远判红', () => {
  const enforce = CODE.split(/\n\s+- name:/).find((s) => /Enforce scanner exit code/.test(s));
  assert.ok(enforce, '应有 Enforce scanner exit code 步骤');
  assert.match(enforce, /SCAN_EXIT/, 'enforce 应读取扫描退出码');
  assert.match(enforce, /FAIL_ON_FINDINGS/, 'enforce 应响应 fail-on-findings');
  // 三态语义：0 绿 / 2 视开关 / 其余（含 1）判红 —— 把「没扫成」当绿是本仓明确禁止的假安全
  assert.match(enforce, /\b0\)/, '应显式处理退出码 0');
  assert.match(enforce, /\b2\)/, '应显式处理退出码 2');
  assert.match(enforce, /\*\)/, '应有兜底分支（1 等执行失败必须判红）');
});
