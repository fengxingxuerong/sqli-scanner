#!/usr/bin/env node
/**
 * mutation-check.mjs —— 断言敏感度门禁（变异测试 / mutation testing）
 *
 * 解决什么：测试全绿 ≠ 断言有效。本脚本把安全关键模块逐个「改坏一个位点」，
 * 若对应测试仍然全绿 —— 该位点没有任何断言守护（存活 = 缺口）。
 *
 * 覆盖范围（诚实记录）：只跑下面 TARGETS 里的模块子集，不是全仓。
 * 选入标准 = 安全关键 + 纯逻辑密集 + 有专属测试 + 离线可跑（挂网络/靶场的测试不入选，
 * 否则门禁变成「网络好就绿」）。全仓会把门禁拉到小时级 = 等于没有门禁。
 *
 * 用法：
 *   node scripts/mutation-check.mjs --list            列出目标与位点
 *   node scripts/mutation-check.mjs                   全量（存活即 exit 1）
 *   node scripts/mutation-check.mjs --limit=6         每目标最多 6 个位点（快档）
 *   node scripts/mutation-check.mjs --file=src/core/scopeGuard.js
 *   node scripts/mutation-check.mjs --report          只报告存活，不因存活退出非零（开发期用）
 *
 * 三档超时（依据见 scripts/../docs 记录，实测后再调）：
 *   基线轮  BASE_MS   —— 回答「这套测试本来是好的吗」，值得等
 *   变异轮  MUTANT_MS —— 回答「改这一处还会红吗」，挂住 == 不通过
 *   内层    --test-timeout —— 防止单个用例撞满 node 自己的默认超时后串行累加
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const SERVER = path.join(ROOT, 'server');

const BASE_MS = 120_000;
const MUTANT_MS = 30_000;
const TEST_TIMEOUT_MS = 5_000;

/** 目标模块 → 所有真正覆盖它的测试文件（挂载不全 = 那部分断言不参与判定 = 假存活） */
const TARGETS = [
  {
    file: 'src/core/waf/channelPolicy.js',
    tests: ['tests/waf.channelPolicy.test.js'],
  },
  {
    file: 'src/core/waf/blockPolicy.js',
    tests: ['tests/waf.blockSignature.test.js'],
  },
  {
    file: 'src/core/waf/blockProfile.js',
    tests: [
      'tests/waf.blockProfile.test.js',
      'tests/waf.bypassSearcher.test.js',
      'tests/waf.bypassWiring.test.js',
      'tests/waf.chainVerify.test.js',
    ],
  },
  {
    file: 'src/core/scopeGuard.js',
    tests: ['tests/scopeGuard.test.js', 'tests/scopeGuard.redirect.test.js'],
  },
  {
    file: 'src/core/scanValidityGuard.js',
    tests: ['tests/scanValidity.test.js', 'tests/scanValidity.selfInflicted.test.js', 'tests/netErrGuard.test.js'],
  },
  {
    file: 'src/engine/secondOrderMethod.js',
    tests: ['tests/guards.production.test.js'],
  },
  {
    file: 'src/core/dbHealthGuard.js',
    tests: ['tests/dbHealthGuard.test.js'],
  },
  {
    file: 'src/engine/echoStrip.js',
    tests: ['tests/echoStrip.escapeVariant.test.js'],
  },
  {
    // 覆盖率曾是最薄弱的核心（lines 52%）且长期无专属测试；
    // 测试为 stub 驱动真实入口（tests/detect.orchestration.test.js）
    file: 'src/engine/scan/detect.js',
    tests: ['tests/detect.orchestration.test.js'],
  },
  {
    // 拖库范围解析（449 行，此前零测试挂载，lines 67.6%）
    file: 'src/engine/extractScope.js',
    tests: ['tests/extractScope.modes.test.js'],
  },
  {
    // 扫描收尾（188 行，此前零测试挂载，branch 48%）—— 交付报告的最后一道
    file: 'src/engine/scan/finalize.js',
    tests: ['tests/finalize.report.test.js'],
  },
];

/**
 * 已知等价变异白名单 —— 变异后语义未变（存活是正常现象），已逐个人工确认。
 * 每项必须附理由；不允许为了达标而放宽「存活即失败」。
 * key = `文件相对路径:位点序号:算子`
 */
const EQUIVALENT = new Map([
  // 例：['src/core/xxx.js:3:&&→||', '该分支两侧条件恒等（人工核对：…）'],
]);

/** 变异算子：成对或单向。位点级替换（不是全局），保证能定位到具体那一行 */
const OPERATORS = [
  { from: ' && ', to: ' || ', name: '&&→||' },
  { from: ' || ', to: ' && ', name: '||→&&' },
  { from: ' === ', to: ' !== ', name: '===→!==' },
  { from: ' !== ', to: ' === ', name: '!==→===' },
  { from: ' >= ', to: ' > ', name: '>=→>' },
  { from: ' <= ', to: ' < ', name: '<=→<' },
  { from: ' > ', to: ' >= ', name: '>→>=' },
  { from: ' < ', to: ' <= ', name: '<→<=' },
  { from: 'return true', to: 'return false', name: 'return true→false' },
  { from: 'return false', to: 'return true', name: 'return false→true' },
  { from: 'continue;', to: 'break;', name: 'continue→break' },
];

// ---------- 变异体安全网：改写前备份，任何路径都恢复 ----------
const pending = new Map();
let restoring = false;
function restoreAll() {
  if (restoring) return;
  restoring = true;
  for (const [file, original] of pending) {
    try {
      fs.writeFileSync(file, original, 'utf8');
    } catch {
      console.error(`!! 无法恢复 ${file} —— 请手动 git checkout -- ${path.relative(ROOT, file)}`);
    }
  }
  pending.clear();
  restoring = false;
}
process.on('exit', restoreAll);
process.on('SIGINT', () => { restoreAll(); process.exit(130); });
process.on('SIGTERM', () => { restoreAll(); process.exit(143); });

// ---------- CLI ----------
const argv = process.argv.slice(2);
const flag = (name) => argv.find((a) => a.startsWith(`--${name}=`))?.slice(name.length + 3);
const has = (name) => argv.includes(`--${name}`);
const onlyFile = flag('file');
const limit = flag('limit') ? Number(flag('limit')) : Infinity;
const reportOnly = has('report');
const verbose = has('verbose');

const targets = onlyFile ? TARGETS.filter((t) => t.file.includes(onlyFile)) : TARGETS;
if (targets.length === 0) {
  console.error(`没有匹配 --file=${onlyFile} 的目标，可用目标见 --list`);
  process.exit(2);
}

// ---------- 位点枚举 ----------
function isCodeLine(src, index) {
  const lineStart = src.lastIndexOf('\n', index) + 1;
  const lineEnd = src.indexOf('\n', index);
  const line = src.slice(lineStart, lineEnd === -1 ? src.length : lineEnd).trim();
  return !(line.startsWith('//') || line.startsWith('*') || line.startsWith('/*'));
}

function collectMutants(target) {
  const abs = path.join(SERVER, target.file);
  const src = fs.readFileSync(abs, 'utf8');
  const out = [];
  for (const op of OPERATORS) {
    let i = 0;
    while ((i = src.indexOf(op.from, i)) !== -1) {
      if (isCodeLine(src, i)) {
        out.push({
          file: target.file,
          abs,
          op: op.name,
          index: i,
          snippet: src.slice(Math.max(0, i - 40), i + op.from.length + 20).replace(/\s+/g, ' '),
          mutate: () => src.slice(0, i) + op.to + src.slice(i + op.from.length),
        });
      }
      i += op.from.length;
    }
  }
  out.sort((a, b) => a.index - b.index);
  return Number.isFinite(limit) ? out.slice(0, limit) : out;
}

// ---------- 跑测试 ----------
function runTests(testFiles, timeoutMs) {
  try {
    execFileSync(
      process.execPath,
      [
        '--env-file=.env.test',
        '--import=./tests/_setup.mjs',
        '--test',
        '--test-reporter=dot',
        `--test-timeout=${TEST_TIMEOUT_MS}`,
        ...testFiles,
      ],
      { cwd: SERVER, stdio: 'pipe', timeout: timeoutMs },
    );
    return { pass: true };
  } catch (err) {
    const out = `${err.stdout || ''}${err.stderr || ''}`;
    // 语法级破坏：模块加载就炸，测的不是行为 —— 单独归类，既不算杀死也不算存活
    const syntax = /SyntaxError|Unexpected token|Cannot use import statement/.test(out);
    return { pass: false, syntax, timedOut: err.killed === true || /timed out/i.test(out) };
  }
}

// ---------- 主流程 ----------
const started = Date.now();
const survivors = [];
const invalids = [];
const timing = [];
let mutantsTotal = 0;
let killed = 0;

if (has('list')) {
  for (const t of targets) {
    const ms = collectMutants(t);
    console.log(`${t.file}  (${t.tests.length} 个测试文件, ${ms.length} 个位点)`);
    for (const [i, m] of ms.entries()) console.log(`   [${i}] ${m.op.padEnd(18)} ${m.snippet}`);
  }
  process.exit(0);
}

for (const target of targets) {
  const mutants = collectMutants(target);
  const abs = path.join(SERVER, target.file);
  const original = fs.readFileSync(abs, 'utf8');

  const t0 = Date.now();
  const base = runTests(target.tests, BASE_MS);
  const baseMs = Date.now() - t0;
  if (!base.pass) {
    console.error(`✗ 基线未通过：${target.file} —— 先修测试再跑变异（否则存活/杀死都不可信）`);
    process.exit(3);
  }
  timing.push({ file: target.file, baseMs, mutants: mutants.length });

  for (const [i, m] of mutants.entries()) {
    mutantsTotal += 1;
    pending.set(abs, original);
    let res;
    try {
      fs.writeFileSync(abs, m.mutate(), 'utf8');
      res = runTests(target.tests, MUTANT_MS);
    } finally {
      try { fs.writeFileSync(abs, original, 'utf8'); } catch { /* 由 restoreAll 兜底 */ }
      pending.delete(abs);
    }

    const key = `${target.file}:${i}:${m.op}`;
    if (res.syntax) {
      invalids.push({ key, snippet: m.snippet });
      if (verbose) console.log(`   无效  ${key}  ${m.snippet}  (语法破坏，不计入判定)`);
      continue;
    }
    if (res.pass) {
      const reason = EQUIVALENT.get(key);
      if (reason) {
        if (verbose) console.log(`   等价  ${key}  ${reason}`);
        continue;
      }
      survivors.push({ key, snippet: m.snippet, timedOut: Boolean(res.timedOut) });
      console.log(`   存活  ${key}  ${m.snippet}`);
    } else {
      killed += 1;
      if (verbose) console.log(`   杀死  ${key}  ${m.snippet}`);
    }
  }
}

// ---------- 报告 ----------
console.log('\n=== 变异结果 ===');
console.log(`目标 ${targets.length} 个模块 · 变异 ${mutantsTotal} 处 · 杀死 ${killed} · 存活 ${survivors.length} · 无效 ${invalids.length}`);
console.log('\n基线耗时（用于调超时档位）：');
for (const t of timing) console.log(`   ${String(t.baseMs).padStart(6)}ms  ${t.file}  (${t.mutants} 位点)`);
if (invalids.length) {
  console.log('\n语法破坏（不参与判定，若过多说明算子该收窄）：');
  for (const v of invalids) console.log(`   ${v.key}  ${v.snippet}`);
}
if (survivors.length) {
  console.log('\n存活清单 = 断言缺口清单（逐条补断言，或确认等价后写进 EQUIVALENT 附理由）：');
  for (const s of survivors) console.log(`   ${s.key}  ${s.snippet}`);
}
console.log(`\n总耗时 ${((Date.now() - started) / 1000).toFixed(1)}s`);

if (survivors.length > 0 && !reportOnly) {
  console.error(`\nFAIL：${survivors.length} 处变异存活 —— 这些行为差异没有任何断言守护`);
  process.exit(1);
}
console.log(reportOnly ? '\n（--report 模式：存活不判失败）' : '\nPASS：无存活变异');
