#!/usr/bin/env node
// ============================================================================
// scripts/facts-sync.mjs —— 测试数字单一来源（Single Source of Truth）
// ============================================================================
// 解决的问题：README / 文档里的测试数、覆盖率数字靠人手维护，每补测一轮就漂一次。
// 实测（2026-09-18）同时存在 5 处漂移，其中 README 徽章写 2144、实际 2172。
//
// 设计要点：
//   1. **数字只有一个来源** —— docs/_facts.json（由 --refresh 实跑生成，勿手改）
//   2. **阈值不重复定义** —— 直接读权威位置：
//        · 前端 vitest.config.ts 的 coverage.thresholds
//        · 服务端 server/package.json 的 --test-coverage-* 参数
//   3. **只管「实时口径」，不碰历史存档** —— 带日期的评估报告/发布说明是过去某一刻的
//      事实记录，改了就毁证据。严格校验范围限定 README.md（对外门面）；其余文档只 WARN。
//
// 用法：
//   node scripts/facts-sync.mjs --refresh              # 实跑采集测试数 → 写 _facts.json
//   node scripts/facts-sync.mjs --refresh --coverage   # 连覆盖率一起采集（更慢）
//   node scripts/facts-sync.mjs                        # --check：校验 README 是否漂移
//   node scripts/facts-sync.mjs --fix                  # 按 _facts.json 修正 README
// ============================================================================
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const FACTS_PATH = resolve(ROOT, 'docs/_facts.json');
const README_PATH = resolve(ROOT, 'README.md');
const SOURCES_PATH = resolve(ROOT, 'docs/_facts.sources.json');

const args = new Set(process.argv.slice(2));
const doRefresh = args.has('--refresh');
const doFix = args.has('--fix');
const withCoverage = args.has('--coverage');

// ── 阈值：从权威位置读，不重复定义 ─────────────────────────────────────────

function readFrontendThresholds() {
  const src = readFileSync(resolve(ROOT, 'vitest.config.ts'), 'utf8');
  const block = src.match(/thresholds:\s*\{([\s\S]*?)\}/);
  if (!block) throw new Error('vitest.config.ts 里找不到 coverage.thresholds');
  const pick = (key) => {
    const m = block[1].match(new RegExp(`${key}:\\s*([\\d.]+)`));
    if (!m) throw new Error(`vitest.config.ts 的 thresholds 缺 ${key}`);
    return Number(m[1]);
  };
  return {
    statements: pick('statements'),
    branches: pick('branches'),
    functions: pick('functions'),
    lines: pick('lines'),
  };
}

function readServerThresholds() {
  const pkg = JSON.parse(readFileSync(resolve(ROOT, 'server/package.json'), 'utf8'));
  const cmd = pkg.scripts['test:coverage'];
  if (!cmd) throw new Error('server/package.json 缺 test:coverage');
  const pick = (key) => {
    const m = cmd.match(new RegExp(`--test-coverage-${key}=([\\d.]+)`));
    if (!m) throw new Error(`server test:coverage 缺 --test-coverage-${key}`);
    return Number(m[1]);
  };
  return { lines: pick('lines'), branches: pick('branches'), functions: pick('functions') };
}

// ── 采集：实跑测试，只认输出里的数字 ────────────────────────────────────────

// 实测坑（2026-09-18）：vitest 即使 stdout 被管道捕获**照样输出 ANSI 颜色码**，
// 形如 `Tests \u001b[22m \u001b[1m\u001b[32m294 passed` —— 数字前带转义序列，
// 任何 `Tests\s+(\d+)` 都匹配不上。必须先剥离再解析（覆盖率表格同理，否则整表解析失败）。
// 覆盖 CSI（含 `?` 参数，如 `\u001b[?25l`）、OSC、以及单字符 ESC 形式。
const ANSI_RE = /\u001b\[[0-9;?]*[ -/]*[@-~]|\u001b\][^\u0007]*(?:\u0007|\u001b\\)|\u001b[@-Z\\-_]/g;
const stripAnsi = (s) => String(s).replace(ANSI_RE, '');

// 为什么用 spawnSync 而不是 execFileSync：
// execFileSync **只返回 stdout**，stderr 拿不到；而 vitest 在 TTY 探测不确定时会换输出流，
// 导致「同一条命令上一次拿得到 Tests 行、这一次拿不到」（实测踩到，非确定性）。
// spawnSync 无论退出码如何都同时给出 stdout + stderr，两个流合并后再解析才稳。
function run(cmd, cwd) {
  const r = spawnSync(cmd, {
    cwd, shell: true, encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) throw r.error;
  // 非零退出（覆盖率低于阈值 / 有用例失败）也照常解析：阈值与用例是否通过由各自原有门禁负责，
  // 本脚本只负责把真实数字取出来。
  return stripAnsi(`${r.stdout || ''}${r.stderr || ''}`);
}

function collectFrontend({ coverage }) {
  const out = run(`npx vitest run${coverage ? ' --coverage' : ''}`, ROOT);
  const files = out.match(/Test Files\s+(\d+)\s+passed/);
  const tests = out.match(/Tests\s+(\d+)\s+passed(?:\s*\|\s*(\d+)\s+failed)?/);
  if (!tests) {
    console.error('── 前端测试输出尾部（未能解析 Tests 行）──');
    console.error(out.split('\n').slice(-40).join('\n'));
    throw new Error('前端测试输出里找不到 Tests 行');
  }
  const res = {
    files: files ? Number(files[1]) : null,
    tests: Number(tests[1]) + (tests[2] ? Number(tests[2]) : 0),
    pass: Number(tests[1]),
    fail: tests[2] ? Number(tests[2]) : 0,
  };
  if (coverage) {
    // v8 text 报表的总计行：All files | 90.01 | 79.01 | 70.64 | 90.01 |
    const row = out.match(/^All files\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)/m);
    if (!row) {
      console.error('── 前端覆盖率报表原文（未能解析 All files 行）──');
      console.error(out.split('\n').filter((l) => l.includes('|') || l.includes('All files')).slice(-40).join('\n'));
      throw new Error('前端覆盖率输出里找不到 All files 行');
    }
    res.coverage = {
      statements: Number(row[1]), branches: Number(row[2]),
      functions: Number(row[3]), lines: Number(row[4]),
    };
  }
  return res;
}

function collectServer({ coverage }) {
  // 覆盖率采集用 :report 变体（不带 --test-coverage-*=阈值）：
  // 阈值是门禁的职责，采集脚本不该因为它退出非零而拿不到数字。
  // [TOOL-FIX 2026-09-18] 显式钉 `--test-reporter=tap`。本脚本只认 `# tests N` 这种 TAP 汇总行，
  // 而 node:test 的 reporter 选型取决于 stdout 的 TTY 探测：在 Windows + Git Bash 下 `npm run test`
  // 走管道时输出的是 spec 格式（`ℹ tests 1885`）→ 本地跑 --refresh 必失败（数字采集器在自己
  // 机器上取不到数，等于没有）。同一台机器上「上一次能解析、下一次不能」的不确定性也一并消除。
  const script = coverage ? 'test:coverage:report' : 'test';
  const out = run(`npm run ${script} -- --test-reporter=tap`, resolve(ROOT, 'server'));
  const pick = (key) => {
    const m = out.match(new RegExp(`^# ${key} (\\d+)$`, 'm'));
    if (!m) throw new Error(`服务端测试输出里找不到 "# ${key}"`);
    return Number(m[1]);
  };
  const res = {
    tests: pick('tests'), pass: pick('pass'), fail: pick('fail'), skip: pick('skipped'),
  };
  if (coverage) {
    // node:test 覆盖率报表总计行：# all files | 88.42 | 72.67 | 75.75 |
    const row = out.match(/^#?\s*all files\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)/m);
    if (!row) {
      console.error('── 服务端覆盖率报表原文（未能解析 all files 行）──');
      console.error(out.split('\n').filter((l) => l.includes('|')).slice(-40).join('\n'));
      throw new Error('服务端覆盖率输出里找不到 all files 行');
    }
    res.coverage = { lines: Number(row[1]), branches: Number(row[2]), functions: Number(row[3]) };
  }
  return res;
}

// ── 采集源指纹：README 与 _facts.json 一致 ≠ 数字是新的 ─────────────────────────
// [2026-09-20 新增] 起因是一次**假绿**：后又提交了两批测试（+17 条用例）却没回填，
// `_facts.json` 停在 1985，而 README 也写 1985 —— 于是 --check 报「一致」。
// **校验的基准自己过期时，一致性检查反而给出假绿。** 这与 CI 里 `continue-on-error`
// 的空转 job 同源（`scripts/ref-integrity.mjs` 也是为此而生）：都是「静默地没在做事」，
// 而静默失败是本项目最贵的一类错。
//
// 判据：把「决定跑哪些测试、总共多少条」的文件集合做**内容指纹**，随 --refresh 一起落盘；
// --check 时重算比对，不一致即报「采集源已改动，_facts.json 可能过期」。
// 用内容哈希而非 mtime：mtime 在 git checkout / 拷贝文件 / CI 上不可复现，
// 会把判据变成噪声源（CI 里所有文件同一时刻，mtime 判据必然全量误报）。
//
// 边界（写清免得被当万能）：只覆盖**测试文件 + 驱动采集的配置**。
// 依赖版本、`.env.test`、被测源码改动**不在此判据内** —— 改被测源码不改用例数，
// 那是覆盖率门禁的职责。判据宁可窄而准，也不宽而吵。

const SOURCE_SPECS = [
  ['src/tests', /\.(test|spec)\.(ts|tsx)$/], // 前端：vitest.config.ts 的 include
  ['server/tests', /\.test\.js$/],           // 服务端：node --test 默认发现
];
// 驱动采集的配置：前者决定「哪些文件算测试」，后者决定「怎么跑、覆盖率阈值多少」
// （`server/tests/_setup.mjs` 是 `--import=` 的入口，改了会影响整轮运行）
const SOURCE_SINGLES = ['vitest.config.ts', 'server/package.json', 'server/tests/_setup.mjs'];

function listSources() {
  const out = SOURCE_SINGLES.filter((f) => existsSync(resolve(ROOT, f)));
  for (const [dir, re] of SOURCE_SPECS) {
    const abs = resolve(ROOT, dir);
    if (!existsSync(abs)) continue;
    for (const e of readdirSync(abs, { recursive: true, withFileTypes: true })) {
      if (!e.isFile() || !re.test(e.name)) continue;
      // Dirent.parentPath 在 Node 20.12+ 才有（更早是 .path），两种都兜住
      const parent = e.parentPath ?? e.path;
      out.push(relative(ROOT, resolve(parent, e.name)).replace(/\\/g, '/'));
    }
  }
  return [...new Set(out)].sort();
}

const hashFile = (abs) => {
  const buf = readFileSync(abs);
  // [CI-FIX 2026-09-20] 指纹必须对 EOL 规范化（\r\n → \n）：本机 core.autocrlf=true 时
  // 工作区是 CRLF、CI checkout 是 LF，按原始字节算则同一个 blob 两边指纹不同 ——
  // 首次 CI 实跑即 69 个文件全报「修改」（假红）。与当年 `git archive + diff -rq`
  // 的 EOL 假阳性同族：**跨平台判据里任何字节级比较都必须先做 EOL 归一**。
  // 含 \0 的二进制文件不规范化（按原字节）。
  const norm = buf.includes(0) ? buf : Buffer.from(buf.toString('utf8').replace(/\r\n/g, '\n'), 'utf8');
  return createHash('sha256').update(norm).digest('hex').slice(0, 12);
};

function collectSourceDigest() {
  const files = {};
  for (const rel of listSources()) files[rel] = hashFile(resolve(ROOT, rel));
  // 总指纹：对「路径:短哈希」有序列表再哈希 —— 任一文件增/删/改都会改变它。
  // per-file 表一并留档，是为了报错时能指名道姓，而不是只说「有东西变了」。
  const sha256 = createHash('sha256')
    .update(Object.entries(files).map(([k, v]) => `${k}:${v}`).join('\n'))
    .digest('hex').slice(0, 16);
  return {
    at: new Date().toISOString().replace(/\.\d+Z$/, '+00:00'),
    count: Object.keys(files).length,
    sha256,
    files,
  };
}

function writeSourceDigest() {
  const d = collectSourceDigest();
  mkdirSync(dirname(SOURCES_PATH), { recursive: true });
  writeFileSync(SOURCES_PATH, JSON.stringify({
    _comment: '采集源指纹：决定「跑哪些测试、多少条」的文件集合。由 scripts/facts-sync.mjs --refresh 生成，勿手改。',
    _why: 'README 与 _facts.json 互相一致不等于数字是新的 —— 两边可能双双停在旧值上。本文件是「数字采集于哪一版测试代码」的凭证，--check 时重算比对。',
    _scope: '测试文件 + 驱动采集的配置（含覆盖率阈值来源）。不含依赖版本 / .env.test / 被测源码。',
    ...d,
  }, null, 2) + '\n', 'utf8');
  return d;
}

function checkSourceStaleness() {
  if (!existsSync(SOURCES_PATH)) {
    return { ok: false, reason: 'missing' };
  }
  const saved = JSON.parse(readFileSync(SOURCES_PATH, 'utf8'));
  const now = collectSourceDigest();
  if (saved.sha256 === now.sha256) return { ok: true };
  const old = saved.files || {};
  const added = Object.keys(now.files).filter((k) => !(k in old));
  const changed = Object.keys(now.files).filter((k) => k in old && old[k] !== now.files[k]);
  const removed = Object.keys(old).filter((k) => !(k in now.files));
  return {
    ok: false, reason: 'stale', savedAt: saved.at,
    savedCount: saved.count, nowCount: now.count, added, changed, removed,
  };
}

// ── README 实时口径的定位规则（声明式，不靠行号） ───────────────────────────

// repl 收到的是完整匹配数组 m（m[0]=整段，m[1..]=捕获组）。
// 注意：不要写 `(...a) => rw.repl(...a, facts)` —— String.replace 回调会把
// offset/string 追加在捕获组之后，facts 会被顶到最后一位，导致 m[1] 其实是 p1 而 facts 拿不到。
const README_RULES = [
  {
    id: 'badge.tests',
    desc: '徽章：测试通过总数',
    lineRe: /shields\.io\/badge\/tests-/,
    rewrites: [{
      re: /(badge\/tests-)\d+(%20passing)/,
      repl: (m, f) => m[1] + f.badge.testsPassing + m[2],
    }],
  },
  {
    id: 'block.frontend',
    desc: '「测试」代码块：前端用例数注释',
    lineRe: /^# 前端测试（/,
    rewrites: [{
      re: /^(# 前端测试（)\d+( 个用例）)$/,
      repl: (m, f) => m[1] + f.frontend.tests + m[2],
    }],
  },
  {
    id: 'block.server',
    desc: '「测试」代码块：服务端用例数注释',
    lineRe: /^# 服务端测试（/,
    rewrites: [{
      re: /^(# 服务端测试（)\d+( 个用例）)$/,
      repl: (m, f) => m[1] + f.server.tests + m[2],
    }],
  },
  {
    id: 'status.frontend',
    desc: '「项目状态」：前端用例 + 覆盖率 + 阈值',
    lineRe: /^- 前端测试: /,
    rewrites: [
      {
        re: /^(- 前端测试: )\d+(\/)\d+( 通过)/,
        repl: (m, f) => m[1] + f.frontend.pass + m[2] + f.frontend.tests + m[3],
      },
      {
        re: /(覆盖率门禁 stmts )[\d.]+( \/ branch )[\d.]+( \/ func )[\d.]+/,
        tolerant: true,
        repl: (m, f) =>
          m[1] + f.frontend.coverage.statements.toFixed(2) +
          m[2] + f.frontend.coverage.branches.toFixed(2) +
          m[3] + f.frontend.coverage.functions.toFixed(2),
      },
      {
        re: /(，阈值 )[\d.]+(\/)[\d.]+(\/)[\d.]+/,
        repl: (m, f) =>
          m[1] + f.frontend.thresholds.statements +
          m[2] + f.frontend.thresholds.branches +
          m[3] + f.frontend.thresholds.functions,
      },
    ],
  },
  {
    id: 'status.server',
    desc: '「项目状态」：服务端用例 + 覆盖率 + 阈值 + 复测日期',
    lineRe: /^- 服务端测试: /,
    rewrites: [
      {
        re: /^(- 服务端测试: )\d+( 用例（)\d+( pass \/ )\d+( fail \/ )\d+( skip)/,
        repl: (m, f) =>
          m[1] + f.server.tests + m[2] + f.server.pass +
          m[3] + f.server.fail + m[4] + f.server.skip + m[5],
      },
      {
        re: /(并发口径 )\d{4}-\d{2}-\d{2}( 复测)/,
        repl: (m, f) => m[1] + f.generatedAt.slice(0, 10) + m[2],
      },
      {
        re: /(；)\d+( skip 为环境依赖显式跳过)/,
        repl: (m, f) => m[1] + f.server.skip + m[2],
      },
      {
        re: /(覆盖率 lines )[\d.]+( \/ branch )[\d.]+( \/ func )[\d.]+/,
        tolerant: true,
        repl: (m, f) =>
          m[1] + f.server.coverage.lines.toFixed(2) +
          m[2] + f.server.coverage.branches.toFixed(2) +
          m[3] + f.server.coverage.functions.toFixed(2),
      },
      {
        re: /(，阈值 )[\d.]+(\/)[\d.]+(\/)[\d.]+/,
        repl: (m, f) =>
          m[1] + f.server.thresholds.lines +
          m[2] + f.server.thresholds.branches +
          m[3] + f.server.thresholds.functions,
      },
    ],
  },
];

// 逐行套用规则。每条 rewrite 必须命中 —— 未命中说明 README 结构变了、规则已失效，
// 这本身是缺陷（静默跳过会让校验变成「假绿」），必须报出来。
function rewriteLines(lines, facts) {
  const drifts = [];
  const out = [];
  for (const line of lines) {
    let cur = line;
    const hits = [];
    for (const rule of README_RULES) {
      if (!rule.lineRe.test(cur)) continue;
      hits.push(rule);
      for (const rw of rule.rewrites) {
        const m = cur.match(rw.re);
        if (!m) {
          // 规则匹配式失效（README 结构变了）——必须报，静默跳过等于假绿
          drifts.push({ rule, line: cur, reason: `匹配式未命中：${rw.re}` });
          continue;
        }
        const expected = rw.repl(m, facts);
        if (expected === m[0]) continue;
        let delta = null;
        if (rw.tolerant) {
          delta = maxNumericDelta(m[0], expected);
          // 覆盖率抖动在容差内 → 视为一致，不改写、不报漂移
          if (delta !== null && delta <= COVERAGE_TOLERANCE) continue;
        }
        cur = cur.replace(rw.re, () => expected);
        drifts.push({ rule, line, from: m[0], to: expected, delta });
      }
    }
    out.push(cur);
  }
  return { drifts, out };
}

// 逐位提取数字后取最大差值；结构不一致（数字个数变了）返回 null
function maxNumericDelta(a, b) {
  const na = a.match(/[\d.]+/g) || [];
  const nb = b.match(/\d+(?:\.\d+)?/g) || [];
  if (na.length !== nb.length) return null;
  let max = 0;
  for (let i = 0; i < na.length; i++) {
    max = Math.max(max, Math.abs(Number(na[i]) - Number(nb[i])));
  }
  return max;
}

// 覆盖率是浮点，且实测有抖动：同一台机器连跑 3 次，branch 得 79.03 / 79.01 / 79.01
// （最大 0.02pt；其余字段稳定）。逐位精确比对会把门禁变成 flake 源——正是本项目最反感的
// 「假红」。故对覆盖率字段给 0.2pt 容差（实测抖动的 10×），既能吸收抖动，又能抓住任何
// 真实回退（真回退远大于 0.2pt）。测试用例数/通过数/阈值是整数且确定，仍走精确比对。
// 注意：这里放宽的是「文档与实测是否一致」，覆盖率本身的回退由 vitest.config.ts /
// server package.json 的阈值门禁负责，职责不重叠。
const COVERAGE_TOLERANCE = 0.2;

// 报「采集源过期」时最多列几个文件名：本地排障够用，CI 日志不被刷屏
const STALE_LIST_MAX = 8;
const fmtList = (arr) => {
  const head = arr.slice(0, STALE_LIST_MAX).map((f) => `            · ${f}`).join('\n');
  return arr.length > STALE_LIST_MAX
    ? `${head}\n            …另有 ${arr.length - STALE_LIST_MAX} 个`
    : head;
};

function reportStale(s, doFix) {
  if (s.reason === 'missing') {
    console.error(`[facts] 缺少 ${SOURCES_PATH}：无法确认 _facts.json 是当前测试代码采出来的。`);
    console.error('[facts] 这不是「没问题」，是「没有依据」—— 本判据不静默通过。');
    console.error('[facts] 修法：node scripts/facts-sync.mjs --refresh --coverage');
    return;
  }
  console.error('[facts] ⚠ 采集源已改动 —— _facts.json 可能过期（README 与它「一致」不代表数字是新的）');
  console.error(`[facts]   指纹采集于 ${s.savedAt}（${s.savedCount} 个文件）→ 现在 ${s.nowCount} 个`);
  if (s.added.length) console.error(`[facts]   新增（${s.added.length}）：\n${fmtList(s.added)}`);
  if (s.changed.length) console.error(`[facts]   修改（${s.changed.length}）：\n${fmtList(s.changed)}`);
  if (s.removed.length) console.error(`[facts]   删除（${s.removed.length}）：\n${fmtList(s.removed)}`);
  if (doFix) {
    console.error('[facts] 已**拒绝**本次 --fix：基准（_facts.json）自己过期时，按它改 README 等于把旧数字再抄一遍。');
  }
  console.error('[facts] 修法：node scripts/facts-sync.mjs --refresh --coverage && node scripts/facts-sync.mjs --fix');
}

// ── 主流程 ──────────────────────────────────────────────────────────────────

function buildFacts() {
  const frontendThresholds = readFrontendThresholds();
  const serverThresholds = readServerThresholds();
  console.log(`[facts] 前端阈值 ${JSON.stringify(frontendThresholds)}（源：vitest.config.ts）`);
  console.log(`[facts] 服务端阈值 ${JSON.stringify(serverThresholds)}（源：server/package.json）`);

  console.log(`[facts] 采集前端测试${withCoverage ? ' + 覆盖率' : ''}…`);
  const fe = collectFrontend({ coverage: withCoverage });
  console.log(`[facts]   前端 ${fe.tests} 用例 / ${fe.files} 文件`);
  console.log(`[facts] 采集服务端测试${withCoverage ? ' + 覆盖率' : ''}…`);
  const sv = collectServer({ coverage: withCoverage });
  console.log(`[facts]   服务端 ${sv.tests} 用例（${sv.pass} pass / ${sv.fail} fail / ${sv.skip} skip）`);

  const prev = existsSync(FACTS_PATH) ? JSON.parse(readFileSync(FACTS_PATH, 'utf8')) : null;
  const cov = (fresh, old) => fresh || old || null;

  return {
    _comment: '实时口径唯一来源。由 scripts/facts-sync.mjs --refresh 生成，勿手改。',
    _definitions: {
      'badge.testsPassing': '前端 pass + 服务端 pass（徽章文案为 tests passing，据此取真实通过数）',
      'frontend.tests': 'vitest 用例总数（含失败）',
      'server.tests': 'node:test 用例总数（含 skip/fail）',
    },
    generatedAt: new Date().toISOString().replace(/\.\d+Z$/, '+00:00'),
    coverageCollected: withCoverage || Boolean(prev?.coverageCollected),
    frontend: {
      ...fe,
      coverage: cov(fe.coverage, prev?.frontend?.coverage),
      thresholds: frontendThresholds,
    },
    server: {
      ...sv,
      coverage: cov(sv.coverage, prev?.server?.coverage),
      thresholds: serverThresholds,
    },
    badge: { testsPassing: fe.pass + sv.pass },
  };
}

function main() {
  if (doRefresh) {
    const facts = buildFacts();
    if (!facts.frontend.coverage || !facts.server.coverage) {
      console.error('[facts] 覆盖率数字缺失：请加 --coverage 重新采集（否则 README 覆盖率一栏无法校验）');
      return 1;
    }
    mkdirSync(dirname(FACTS_PATH), { recursive: true });
    writeFileSync(FACTS_PATH, JSON.stringify(facts, null, 2) + '\n', 'utf8');
    console.log(`[facts] 已写入 ${FACTS_PATH}`);
    console.log(`[facts] 徽章测试数 = ${facts.badge.testsPassing}（${facts.frontend.pass} + ${facts.server.pass}）`);
    // 采集源指纹与数字**同批**落盘。分开写会制造「数字已新、指纹还旧」的中间态，
    // 那比「两个都旧」更坏：判据会报 stale，而数字其实是对的。
    const digest = writeSourceDigest();
    console.log(`[facts] 已写入 ${SOURCES_PATH}（测试源 ${digest.count} 个文件，总指纹 ${digest.sha256}）`);
    return 0;
  }

  if (!existsSync(FACTS_PATH)) {
    console.error(`[facts] 缺少 ${FACTS_PATH}，先跑 --refresh`);
    return 2;
  }
  const facts = JSON.parse(readFileSync(FACTS_PATH, 'utf8'));
  const readme = readFileSync(README_PATH, 'utf8');
  // 必须原样保留换行符：本仓库 README 是纯 CRLF（实测 575/575，且仓库无 .gitattributes）。
  // 若按 '\n' 切分，每行尾部会残留 '\r'，而 JS 正则的 `$` **不匹配**尾部 '\r' 之前的位置
  // ——带 `$` 锚点的规则会全部静默失效（实测踩到）。这里按检测到的 EOL 切分并原样写回。
  const eol = readme.includes('\r\n') ? '\r\n' : '\n';
  const { drifts, out } = rewriteLines(readme.split(eol), facts);

  // 先算采集源是否过期 —— 它决定 --fix 能不能落地（基准脏时一律拒绝改文件）
  const stale = checkSourceStaleness();
  let failed = false;

  if (drifts.length === 0) {
    console.log('[facts] README 实时口径与 _facts.json 一致。');
  } else {
    console.log(`[facts] 检出 ${drifts.length} 处漂移：\n`);
    for (const d of drifts) {
      console.log(`  · ${d.rule ? d.rule.desc : '（规则失效，需人工处理）'}`);
      if (d.reason) {
        console.log(`      原因: ${d.reason}（README 结构可能已改）\n`);
        continue;
      }
      console.log(`      README 现状: ${d.from.trim()}`);
      console.log(`      _facts.json: ${d.to.trim()}`);
      if (d.delta !== null && d.delta !== undefined) {
        console.log(`      偏差: ${d.delta.toFixed(2)}pt（容差 ${COVERAGE_TOLERANCE}）`);
      }
      console.log();
    }

    if (doFix && stale.ok) {
      writeFileSync(README_PATH, out.join(eol), 'utf8');
      console.log(`[facts] 已按 _facts.json 修正 README（${drifts.length} 处，保持原有 ${eol === '\r\n' ? 'CRLF' : 'LF'} 换行）。`);
    } else if (!doFix) {
      console.log('[facts] 数字漂移：README 声称的测试/覆盖率与实测不符。');
      console.log('[facts] 修法：node scripts/facts-sync.mjs --fix（或先 --refresh 重新采集）');
      failed = true;
    }
    // doFix && !stale.ok 的分支：不写盘，由下面的 reportStale 说明为什么
  }

  if (stale.ok) {
    console.log('[facts] 采集源未改动（指纹与 _facts.json 同批）。');
  } else {
    console.error('');
    reportStale(stale, doFix);
    failed = true;
  }

  return failed ? 1 : 0;
}

process.exit(main());
