#!/usr/bin/env node
// ============================================================================
// arch-guard.mjs —— 架构门禁（防止工程重新腐化）
//
// 三条规则：
//  ① 体积上限：单个文件超过 MAX_LINES 行 → 失败。已有超标文件记在基线里，
//     基线内允许存在（技术债显式化），但**不允许再变长**——瘦身后需下调基线。
//  ② 循环依赖：server/src 与 src 的 ESM import 图里出现环 → 失败。
//  ③ console 回归：生产代码（排除 tests/scripts/e2e）不得出现 console.*。
//
// 设计原则：**不留半开的闸门**。规则一旦启用就必须为 0 违规；
// 历史债靠基线显式列出（可见、可追、可逐步清），而不是靠警告蒙混。
//
// 用法：
//   node scripts/arch-guard.mjs            # 检查（违规则退出码 1）
//   node scripts/arch-guard.mjs --update   # 重新生成基线（仅在瘦身后使用）
//   node scripts/arch-guard.mjs --selftest # 自证判据不空转（D249）
// ============================================================================
import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();
const MAX_LINES = 1200;
const HARD_MAX_LINES = 2000; // 任何情况下都不得越过（含基线内文件）
// 容差：小幅功能增长不该让门禁变红——否则每次 feature 提交都红灯，红灯一多就没人看了。
// 实测教训：本门禁首次上线后就误伤过两次合理提交（httpClient +12 是 ratePerSec 语义修复、
// cli.js +19 是 CSRF 会话层与 --skip 新功能）。超过容差才视为"膨胀"需先瘦身或显式更新基线。
const GRACE_LINES = 30;
// [2026-09-23] 补第二判据：**字节数**。
// 行数会系统性漏掉「数据密集型」文件 —— `payloadRegistry.js` 只有 983 行（低于 1200 上限），
// 却有 167.2 KB（平均 174 字节/行，567 行超 200 字符，是第二名 httpClient.js 的 2.7 倍）。
// 纯按行数管，它永远绿灯；而 SEA/sidecar 打包体积、AST 解析开销、diff 可读性都只跟**字节**有关。
// 「门禁看不见它声称在管的东西」是比「没有门禁」更隐蔽的形态，故此处两侧都量。
const MAX_BYTES = 100 * 1024; // 100 KB：超过即视为技术债（须进基线或拆分）
const HARD_MAX_BYTES = 256 * 1024; // 256 KB：任何情况下都不得越过（含基线内）
const GRACE_BYTES = 16 * 1024; // 16 KB 容差：小幅数据增长不该让门禁变红
const BASELINE_PATH = path.join('scripts', '.arch-baseline.json');

const SCAN_DIRS = [
  // [E5-2 2026-09-23] server/src 补 `.json`：数据从 JS 搬到 JSON 后，体积债**不该因为换了容器而隐身**。
  // 实测：payloadRegistry.js 167.2 KB（已登记）→ 变成 15.9 KB + payloads/registry.json 150.1 KB；
  // 若继续只扫代码扩展名，后者会凭空消失，门禁报告看不出任何变化 —— 那正是「判据被绕过」的形态。
  { dir: path.join('server', 'src'), exts: ['.js', '.mjs', '.json'] },
  { dir: path.join('server', 'bin'), exts: ['.js'] },
  { dir: 'src', exts: ['.ts', '.tsx', '.js'] },
];

// 只有**代码**文件才做「导入图解析」与「console 扫描」：JSON 里出现 `import` / `console.log`
// 字样既可能是数据，也可能是误伤源（本仓 payload 模板里就有大量 SQL 关键字与函数名）。
const CODE_EXTS = ['.js', '.mjs', '.ts', '.tsx'];
const isCodeFile = (f) => CODE_EXTS.some((e) => f.endsWith(e));

const EXCLUDE_RE = /(^|[\\/])(node_modules|dist|dist-engine|tests|e2e|scripts|archived|__mocks__)([\\/]|$)/;

function walk(dir, exts, out = []) {
  const abs = path.join(ROOT, dir);
  if (!fs.existsSync(abs)) return out;
  for (const ent of fs.readdirSync(abs, { withFileTypes: true })) {
    const rel = path.posix.join(dir.split(path.sep).join('/'), ent.name);
    if (EXCLUDE_RE.test(rel)) continue;
    if (ent.isDirectory()) walk(rel, exts, out);
    else if (exts.some((e) => ent.name.endsWith(e))) out.push(rel);
  }
  return out;
}

function lineCount(rel) {
  const t = fs.readFileSync(path.join(ROOT, rel), 'utf8');
  return t.split('\n').length;
}

function byteCount(rel) {
  return fs.statSync(path.join(ROOT, rel)).size;
}

// ---------- ① 体积 ----------
// 两个维度并行：行数管「代码复杂度」，字节管「数据/打包成本」。两者不是同一件事，
// 只量其中一个都会留盲区（见 MAX_BYTES 处的注释）。
function checkSize(files, baselineLines, baselineBytes = {}) {
  const violations = [];
  const oversize = new Map(); // file → [{ kind, value, base }]

  const dimension = (f, kind, value, fmt, max, hardMax, grace, base) => {
    const pretty = fmt(value);
    if (value > hardMax) {
      violations.push(`${f}：${pretty}，越过硬上限 ${fmt(hardMax)}（必须拆分）`);
      return;
    }
    if (value <= max) return;
    if (base === undefined) {
      violations.push(`${f}：${pretty}，超过 ${fmt(max)} 且不在基线内（新债，必须拆分或说明）`);
    } else if (value > base + grace) {
      violations.push(`${f}：${pretty} > 基线 ${fmt(base)} + 容差 ${fmt(grace)}（膨胀，请先瘦身或显式更新基线）`);
    } else {
      if (!oversize.has(f)) oversize.set(f, []);
      oversize.get(f).push({ kind, value, fmt, base });
    }
  };

  for (const f of files) {
    dimension(f, '行数', lineCount(f), (v) => `${v} 行`, MAX_LINES, HARD_MAX_LINES, GRACE_LINES, baselineLines[f]);
    dimension(f, '体积', byteCount(f), (v) => `${(v / 1024).toFixed(1)} KB`, MAX_BYTES, HARD_MAX_BYTES, GRACE_BYTES, baselineBytes[f]);
  }

  return { violations, oversize };
}

// ---------- ② 循环依赖 ----------
function parseImports(rel) {
  let t = fs.readFileSync(path.join(ROOT, rel), 'utf8');
  // 必须先剥掉块注释：JSDoc 里常有 `@param {import('./X.js').T}` 这类**纯类型引用**，
  // 它不是运行时依赖。不剥离会产生大量假阳性（首次跑就误报了 ScanManager 环）。
  t = t.replace(/\/\*[\s\S]*?\*\//g, '');
  // 行注释同样剥掉（避免示例代码里的 import 被计入）
  t = t.replace(/(^|[^:])\/\/[^\n]*/g, '$1');
  const specs = [];
  const re = /(?:^|\n)\s*(?:import|export)[\s\S]*?from\s*['"]([^'"]+)['"]|(?:^|\n)\s*import\s*['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)/g;
  let m;
  while ((m = re.exec(t))) {
    const s = m[1] || m[2] || m[3];
    if (s) specs.push(s);
  }
  return specs;
}

function resolveSpec(fromRel, spec) {
  if (!spec.startsWith('.')) return null; // 外部包/内置模块
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(fromRel), spec));
  for (const cand of [base, base + '.js', base + '.mjs', base + '.ts', base + '.tsx',
                      path.posix.join(base, 'index.js'), path.posix.join(base, 'index.ts')]) {
    if (fs.existsSync(path.join(ROOT, cand))) return cand;
  }
  return null;
}

function buildGraph(files) {
  const graph = new Map();
  for (const f of files.filter(isCodeFile)) {
    const deps = new Set();
    for (const s of parseImports(f)) {
      const r = resolveSpec(f, s);
      if (r && r !== f) deps.add(r);
    }
    graph.set(f, [...deps]);
  }
  return graph;
}

function findCycles(graph) {
  const cycles = [];
  const state = new Map(); // 0=未访问 1=在栈 2=完成
  const stack = [];
  const seen = new Set();

  function dfs(node) {
    state.set(node, 1);
    stack.push(node);
    for (const dep of graph.get(node) || []) {
      if (state.get(dep) === 1) {
        const idx = stack.indexOf(dep);
        const cycle = stack.slice(idx).concat(dep);
        const key = [...cycle].slice(0, -1).sort().join('→');
        if (!seen.has(key)) {
          seen.add(key);
          cycles.push(cycle);
        }
      } else if (!state.get(dep)) {
        dfs(dep);
      }
    }
    stack.pop();
    state.set(node, 2);
  }

  for (const n of graph.keys()) if (!state.get(n)) dfs(n);
  return cycles;
}

// ---------- ③ console 回归 ----------
// 规则边界：只禁「调试输出」——console.log / debug / info。
// console.error / warn 属**错误上报**，是合法用途：
//   · 前端无 logger 可用，React 错误边界的 componentDidCatch 官方就建议在此记录；
//   · 失败路径已给用户可见提示（setExportError），console.error 是附带的服务端不可见日志。
// 把它们一起禁掉，只会逼人删掉合理的错误处理来凑绿 —— 那是规则不准，不是代码不净。
function checkConsole(files) {
  const hits = [];
  for (const f of files) {
    if (!isCodeFile(f)) continue;
    if (!(f.startsWith('server/src') || f.startsWith('src/'))) continue;
    const t = fs.readFileSync(path.join(ROOT, f), 'utf8');
    const lines = t.split('\n');
    lines.forEach((l, i) => {
      if (/(^|[^.\w])console\.(log|debug|info)\s*\(/.test(l) && !l.trim().startsWith('//')) {
        hits.push(`${f}:${i + 1}`);
      }
    });
  }
  return hits;
}

// ---------- selftest ----------
// [D249 2026-11-04] 判据自证：注入一次性 fixture 直接调用内部函数，断言「该红的红、
// 该绿的绿」。fixture 写进 server/src 是因为 console 规则只对生产目录（server/src /
// src 前缀）生效；finally 里整目录清除并自证无残留 —— 若被中断残留，下一次真跑
// arch:guard 会红（可见方向的安全失败）。依赖 cwd = 仓库根（ROOT = process.cwd()）。
function selftestMain() {
  const dir = path.join(ROOT, 'server', 'src', '__arch_selftest__');
  const rel = (f) => `server/src/__arch_selftest__/${f}`;
  const results = [];
  const ok = (cond, name) => results.push([!!cond, name]);

  const writeFixture = (name, content) => {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, name), content, 'utf8');
  };

  try {
    // 体积 fixture：行数维度（软上限 / 硬上限）+ 字节维度（数据密集型，行数会漏）
    writeFixture('lines_1201.js', '// pad\n'.repeat(1201));
    writeFixture('lines_2001.js', '// pad\n'.repeat(2001));
    writeFixture('bytes_101k.js', 'x'.repeat(101 * 1024));
    // 循环依赖 fixture：两文件互导
    writeFixture('cycA.js', "import { b } from './cycB.js';\nexport const a = 1;\n");
    writeFixture('cycB.js', "import { a } from './cycA.js';\nexport const b = 2;\n");
    // console fixture：log（禁）/ error（错误上报，合法）/ 行注释 / 块注释
    writeFixture('consoleFix.js', [
      'const t = 1;',
      'console.log(t);',
      'console.error(t);',
      '// console.log(inLineComment);',
      '/* console.log(inBlockComment); */',
    ].join('\n'));

    const l1201 = rel('lines_1201.js');
    const l2001 = rel('lines_2001.js');
    const b101k = rel('bytes_101k.js');

    // —— 体积：行数维度 ——
    ok(checkSize([l1201], {}).violations.length === 1, '① 1201 行、基线外 → 违规');
    ok(checkSize([l2001], { [l2001]: 2001 }).violations.length === 1, '② 2001 行越硬上限：基线登记也 → 违规（硬上限不认基线）');
    ok(checkSize([l1201], { [l1201]: 1100 }).violations.length === 1, '③ 基线 1100 → 1201（+101 > 容差 30）→ 违规（膨胀）');
    const within = checkSize([l1201], { [l1201]: 1190 });
    ok(within.violations.length === 0 && within.oversize.has(l1201), '④ 基线 1190（+11 ≤ 容差）→ 不违规且入台账');
    ok(checkSize([l1201], { [l1201]: 1300 }).violations.length === 0, '⑤ 已瘦身（1201 < 基线 1300）→ 不违规');
    // —— 体积：字节维度独立生效（payloadRegistry 教训：983 行 / 167KB 纯行数永远绿灯）——
    ok(checkSize([b101k], {}).violations.length === 1, '⑥ 1 行 101KB → 字节维度违规');

    // —— 循环依赖：检出 + cycleKey 规范化契约（与方向/重复无关，基线才可比）——
    const cyc = findCycles(buildGraph([rel('cycA.js'), rel('cycB.js')]));
    ok(cyc.length === 1, '⑦ A⇄B 互导 → 恰检出 1 条环');
    ok(cycleKey(cyc[0]) === [rel('cycA.js'), rel('cycB.js')].sort().join('|'), '⑧ cycleKey = 排序去重文件集（基线可比）');

    // —— console：钉住现行规则的真实语义（不为绿而改判定）——
    const hits = checkConsole([rel('consoleFix.js')]);
    ok(JSON.stringify(hits) === JSON.stringify([`${rel('consoleFix.js')}:2`, `${rel('consoleFix.js')}:5`]),
      '⑨ console 判定：log 命中第 2 行；console.error（错误上报）/行注释不命中');
    ok(hits.some((h) => h.endsWith(':5')), '⑩ 已知盲区（显式钉住）：单行块注释 /* console.log */ 仍命中 —— 现行规则只剔除行注释（!startsWith("//")），块注释内被注释掉的调试代码靠基线吸收；未来若修此规则，此处会红提醒同步契约');
    ok(checkConsole(['scripts/arch-guard.mjs']).length === 0, '⑪ 非生产目录（scripts/）不命中');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  ok(!fs.existsSync(dir), '⑫ fixture 已清除，无残留');

  const failed = results.filter(([p]) => !p);
  for (const [p, name] of results) console.log(`  ${p ? '✅' : '❌'} ${name}`);
  if (failed.length) {
    console.error(`[arch-guard] ✗ selftest ${failed.length}/${results.length} 条失败`);
    process.exit(1);
  }
  console.log(`[arch-guard] ✓ selftest 全绿（${results.length} 条判据）`);
}

if (process.argv.includes('--selftest')) {
  selftestMain();
  process.exit(0);
}

// ---------- main ----------
const files = [];
for (const s of SCAN_DIRS) files.push(...walk(s.dir, s.exts));

// 基线统一结构：
//   { "__size__": { 文件: 行数 }, "__cycles__": ["环的规范化 key"], "__console__": { 文件: 命中数 } }
// 历史债**显式登记**（可见、可追、可逐步清），但一律「只减不增」——
// 这是本门禁与「警告式检查」的关键差别：不新增一行债，也不靠警告蒙混。
function cycleKey(cycle) {
  return [...new Set(cycle)].sort().join('|');
}

function loadBaseline() {
  const empty = { __size__: {}, __size_bytes__: {}, __cycles__: [], __console__: {} };
  if (!fs.existsSync(path.join(ROOT, BASELINE_PATH))) return empty;
  const raw = JSON.parse(fs.readFileSync(path.join(ROOT, BASELINE_PATH), 'utf8'));
  // 兼容旧版（只有行数体积基线）
  if (raw.__size__ || raw.__cycles__ || raw.__console__) return { ...empty, ...raw, __size_bytes__: raw.__size_bytes__ || {} };
  return { ...empty, __size__: raw };
}

if (process.argv.includes('--update')) {
  const nextSize = {};
  const nextBytes = {};
  for (const f of files) {
    const n = lineCount(f);
    if (n > MAX_LINES) nextSize[f] = n;
    const b = byteCount(f);
    if (b > MAX_BYTES) nextBytes[f] = b;
  }
  const nextCycles = findCycles(buildGraph(files)).map(cycleKey);
  const nextConsole = {};
  for (const hit of checkConsole(files)) {
    const file = hit.split(':')[0];
    nextConsole[file] = (nextConsole[file] || 0) + 1;
  }
  const next = { __size__: nextSize, __size_bytes__: nextBytes, __cycles__: nextCycles, __console__: nextConsole };
  fs.mkdirSync(path.join(ROOT, 'scripts'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, BASELINE_PATH), JSON.stringify(next, null, 2) + '\n');
  console.log(`基线已更新 → ${BASELINE_PATH}`);
  console.log(`  行数超标 ${Object.keys(nextSize).length} 个 · 体积超标 ${Object.keys(nextBytes).length} 个 · 循环依赖 ${nextCycles.length} 条 · console ${Object.values(nextConsole).reduce((a, b) => a + b, 0)} 处`);
  for (const [f, n] of Object.entries(nextSize)) console.log(`    [行数] ${n} 行  ${f}`);
  for (const [f, b] of Object.entries(nextBytes)) console.log(`    [体积] ${(b / 1024).toFixed(1)} KB  ${f}`);
  for (const f of nextCycles) console.log(`    [循环] ${f}`);
  for (const [f, n] of Object.entries(nextConsole)) console.log(`    [console] ${n} 处  ${f}`);
  process.exit(0);
}

const baseline = loadBaseline();

const size = checkSize(files, baseline.__size__, baseline.__size_bytes__);
const cycles = findCycles(buildGraph(files));
const consoleHits = checkConsole(files);

const problems = [];
if (size.violations.length) problems.push(['文件体积', size.violations]);

// 循环依赖：基线外的环（新增债）才算失败
const baseCycles = new Set(baseline.__cycles__ || []);
const newCycles = cycles.filter((c) => !baseCycles.has(cycleKey(c)));
if (newCycles.length) problems.push(['循环依赖（新增，基线外）', newCycles.map((c) => c.join(' → '))]);

// console：同一文件的命中数超过基线（新增）才算失败
const consoleByFile = {};
for (const hit of consoleHits) {
  const f = hit.split(':')[0];
  consoleByFile[f] = (consoleByFile[f] || 0) + 1;
}
const newConsole = Object.entries(consoleByFile)
  .filter(([f, n]) => n > (baseline.__console__?.[f] ?? 0))
  .map(([f, n]) => `${f}：${n} 处 > 基线 ${baseline.__console__?.[f] ?? 0} 处`);
if (newConsole.length) problems.push(['生产代码 console.*（新增）', newConsole]);

const knownCycles = cycles.length - newCycles.length;

console.log(`扫描 ${files.length} 个文件（server/src + server/bin + src）`);
console.log(`阈值：单文件 ${MAX_LINES} 行（硬上限 ${HARD_MAX_LINES}）且 ${MAX_BYTES / 1024} KB（硬上限 ${HARD_MAX_BYTES / 1024} KB）`);
console.log('');

if (size.oversize.size) {
  console.log(`基线内的技术债 ${size.oversize.size} 个文件（只减不增）：`);
  for (const [file, notes] of size.oversize) {
    const summary = notes
      .map((n) => {
        const delta = n.value - n.base;
        const tag = delta < 0 ? `（已瘦 ${n.fmt(-delta)}，可下调基线）` : delta > 0 ? `（容差内 +${n.fmt(delta)}）` : '';
        return `${n.kind} ${n.fmt(n.value)}（基线 ${n.fmt(n.base)}）${tag}`;
      })
      .join(' · ');
    console.log(`  ${file}  ${summary}`);
  }
  console.log('');
}

if (knownCycles > 0) {
  console.log(`基线内的循环依赖 ${knownCycles} 条（只减不增，建议排期清）：`);
  for (const c of cycles.filter((x) => baseCycles.has(cycleKey(x)))) console.log('  ' + c.join(' → '));
  console.log('');
}
if (Object.keys(consoleByFile).length) {
  const total = Object.values(consoleByFile).reduce((a, b) => a + b, 0);
  console.log(`基线内的 console.* ${total} 处（只减不增）：`);
  for (const [f, n] of Object.entries(consoleByFile)) console.log(`  ${n} 处  ${f}`);
  console.log('');
}

if (problems.length === 0) {
  console.log('架构门禁通过：无新增体积违规 / 无新增循环依赖 / 无新增 console');
  process.exit(0);
}

console.error('架构门禁未通过：');
for (const [name, list] of problems) {
  console.error(`\n[${name}] ${list.length} 项`);
  for (const x of list) console.error('  - ' + x);
}
process.exit(1);
