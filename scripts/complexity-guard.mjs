#!/usr/bin/env node
// ============================================================================
// scripts/complexity-guard.mjs —— 函数级复杂度门禁（基线制）
//
// ── 为什么要有这道门 ─────────────────────────────────────────────────────────
// arch-guard 管**文件**体积、nesting-guard 管**嵌套深度**，但没有门禁管**函数**。
// 真实事故形态：文件不到 1200 行、嵌套不到 7 层，但某个函数体几百行、圈复杂度
// 几十 —— 改它时"这个分支属于哪段逻辑"要靠滚动条确认，漏改一支的概率极高。
// 本仓实测：blindExtractor.js 的 extractBoolean 单函数约 271 行；scanHelpers.js
// 仅 181 行却含上百个分支点。文件级门禁对这类"单函数巨兽"完全无感。
//
// ── 判据（保守，宁少报不误伤）───────────────────────────────────────────────
// · 函数边界由 scripts/lib/jsLexer.mjs 的 findFunctions 识别；不确定者不判定
//   （计入 unparsed），避免把嵌套内函数误当外层长度。
// · **有效行数**为主判据（剔除纯空白/纯注释行）——纯注释行不代表职责复杂度。
// · 圈复杂度基数 1，计数 if/for/while/case/catch/&&/||/??/?. /三目 ?（可核，无主观权重）。
// · 软上限（新代码不得从软上限起步）与硬上限（任何情况不得越过）分离，与
//   nesting-guard 同一取向；存量超软上限者登记入基线，只许持平或下降。
//
// ── 基线「只减不增」────────────────────────────────────────────────────────
// docs/_complexity-baseline.json 记录存量超软上限函数。检查时：
//   现测 > 基线值 + 容差（默认 0）→ 失败（存量不许变差）；
//   现测 < 基线值 → 提示「可下调基线」；
//   --fix-baseline **先判定后写盘**：超硬上限未入基线 / 基线腰斩（条目减半）⇒ 拒绝且零副作用；
//   允许时才原子写（临时文件 + rename）。[D180] 此前是「先写后退」，拒绝也把基线写坏了。
//
// 用法：
//   node scripts/complexity-guard.mjs               # 检查（违规则 exit 1）
//   node scripts/complexity-guard.mjs --selftest    # 自证判据不空转
//   node scripts/complexity-guard.mjs --fix-baseline# 瘦身后重生成基线（判定不过则拒绝，exit 2）
//   node scripts/complexity-guard.mjs --json        # 机器可读输出
// ============================================================================
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { lex, findFunctions, countBranches, effectiveBodyLines } from './lib/jsLexer.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE_FILE = path.join(ROOT, 'docs', '_complexity-baseline.json');

const SCAN_DIRS = ['server/src', 'server/bin', 'src', 'scripts'];
const EXT = ['.js', '.ts', '.tsx', '.mjs'];

// 软上限：新代码超过即失败（必须拆分）
const SOFT_FN_LINES = 100;
const SOFT_COMPLEXITY = 15;
// 硬上限：任何情况不得越过（存量超者进基线，须持平或下降）
const HARD_FN_LINES = 200;
const HARD_COMPLEXITY = 25;
// 容差：基线允许比基线再涨 0（刻意设 0）
const GRACE = 0;

function collect(rel, exts, out) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) return out;
  for (const ent of fs.readdirSync(abs, { withFileTypes: true })) {
    if (ent.name.startsWith('.')) continue;
    const sub = path.posix.join(rel.replace(/\\/g, '/'), ent.name);
    if (ent.isDirectory()) {
      if (['node_modules', 'dist', 'build', 'target', '.git', 'coverage'].includes(ent.name)) continue;
      collect(sub, exts, out);
    } else if (exts.some((e) => ent.name.endsWith(e))) out.push(sub);
  }
  return out;
}

/**
 * 度量给定文件列表中的每个函数。
 * @param {string[]} files 相对仓库根或绝对路径的源文件列表
 * @returns {Record<string, {lines:number, complexity:number}>} 键为 `文件::函数名`
 */
export function measureFunctions(files) {
  const out = {};
  for (const f of files) {
    const abs = path.isAbsolute(f) ? f : path.join(ROOT, f);
    let src;
    try { src = fs.readFileSync(abs, 'utf8'); } catch { continue; }
    const { tokens } = lex(src);
    const { functions } = findFunctions(src);
    const relKey = path.isAbsolute(f) ? f : f.replace(/\\/g, '/');
    for (const fn of functions) {
      const bodyTokens = tokens.filter((t) => t.line >= fn.startLine && t.line <= fn.endLine);
      const complexity = 1 + countBranches(bodyTokens);
      const lines = effectiveBodyLines(src, fn.startLine, fn.endLine);
      out[`${relKey}::${fn.name}`] = { lines, complexity };
    }
  }
  return out;
}

function loadBaseline() {
  try {
    return JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf8'));
  } catch {
    return { _comment: '函数级复杂度基线：只减不增。', functions: {} };
  }
}

/**
 * 把基线里 `<arrow@行号>` 形式的键重映射到当前实测的行号。
 *
 * 为什么需要：匿名函数的键带行号（jsLexer 用 `<arrow@${t.line}>` 命名），**在其前面插入
 * 任何注释/空行都会让行号漂移**，于是旧基线条目匹配不上、被当成「新代码超硬上限」误报
 * （D216 实测：加 JSDoc 后 3 个 handler 全部误报，数值 34/30/26 一字未变）。
 *
 * 匹配口径：按 **(有效行数, 圈复杂度) 在同文件的匿名函数里找唯一匹配**。
 *   · 不能按「第 K 个匿名函数」对齐 —— 基线只收超软上限的少数条目（本文件实测 19 个匿名
 *     函数里只有 3 个进基线），序号根本对不上；
 *   · 特征相同才映射 ⇒ 存量**变差**（行数/复杂度上升）时匹配不上，仍按「新函数」判定并报错，
 *     不会因为「反正都是同一个箭头」而放行；
 *   · 同文件有两个特征完全相同的匿名函数 ⇒ 歧义 ⇒ 不映射（宁可误报，不静默错配）。
 * @param {Record<string,{lines:number,complexity:number}>} measured 当前度量
 * @param {Record<string,object>} base 基线条目
 * @returns {Record<string,string>} 实测键 → 基线键 的映射（仅匿名函数、仅唯一特征匹配）
 */
function remapArrowKeys(measured, base) {
  const ARROW = /^(.*)::<arrow@\d+>$/;
  const byFile = new Map();
  for (const [key, m] of Object.entries(measured)) {
    const hit = ARROW.exec(key);
    if (!hit) continue;
    if (!byFile.has(hit[1])) byFile.set(hit[1], []);
    byFile.get(hit[1]).push({ key, lines: m.lines, complexity: m.complexity });
  }
  const map = {};
  for (const [key, b] of Object.entries(base)) {
    const hit = ARROW.exec(key);
    if (!hit) continue;
    const cands = (byFile.get(hit[1]) || []).filter(
      (c) => c.lines === (b.lines ?? -1) && c.complexity === (b.complexity ?? -1)
    );
    if (cands.length === 1) map[cands[0].key] = key;
  }
  return map;
}

/**
 * 取某实测键对应的基线条目：先按精确键，再按匿名函数序号映射。
 * 抽成函数是为了让 judge 保持「单行取值、零新增分支」（judge 本身已在基线边缘）。
 * @param {{functions?:Record<string,object>}} baseline 基线文档
 * @param {Record<string,string>} remap 实测键 → 基线键
 * @param {string} key 实测键
 * @returns {object|undefined}
 */
function lookupBaseline(baseline, remap, key) {
  const base = baseline.functions || {};
  if (base[key] !== undefined) return base[key];
  const alt = remap[key];
  return alt !== undefined ? base[alt] : undefined;
}

/**
 * 按基线裁定实测结果。
 * @param {Record<string,{lines:number,complexity:number}>} measured
 * @param {{functions?:Record<string,object>}} baseline
 * @param {{softFnLines?:number,hardFnLines?:number,softComplexity?:number,hardComplexity?:number,grace?:number}} [opts]
 * @returns {{errors:string[], notes:string[]}}
 */
export function judge(measured, baseline, opts = {}) {
  const softLines = opts.softFnLines ?? SOFT_FN_LINES;
  const hardLines = opts.hardFnLines ?? HARD_FN_LINES;
  const softCx = opts.softComplexity ?? SOFT_COMPLEXITY;
  const hardCx = opts.hardComplexity ?? HARD_COMPLEXITY;
  const grace = opts.grace ?? GRACE;
  const errors = [];
  const notes = [];
  // [D217] 匿名函数键含行号：先按「同文件序号」对齐，再判定（具名函数不受影响）
  const remap = remapArrowKeys(measured, baseline.functions || {});
  for (const [key, m] of Object.entries(measured)) {
    const b = lookupBaseline(baseline, remap, key);
    if (b === undefined) {
      // 新函数（不在基线）：软/硬上限都强制，不得从超限起步
      if (m.lines > hardLines) {
        errors.push(`${key}：函数体有效 ${m.lines} 行，越过硬上限 ${hardLines}（新代码必须先拆分）`);
        continue;
      }
      if (m.complexity > hardCx) {
        errors.push(`${key}：圈复杂度 ${m.complexity}，越过硬上限 ${hardCx}（新代码必须先拆分）`);
        continue;
      }
      if (m.lines > softLines) errors.push(`${key}：函数体有效 ${m.lines} 行，超过软上限 ${softLines}（新代码请拆分）`);
      else if (m.complexity > softCx) errors.push(`${key}：圈复杂度 ${m.complexity}，超过软上限 ${softCx}（新代码请拆分）`);
      continue;
    }
    // 基线内的存量函数：由基线锁定，只许持平或下降（豁免软/硬上限，否则要求一次性重构全仓）。
    const bl = b.lines ?? 0;
    const bc = b.complexity ?? 0;
    if (m.lines > bl + grace) errors.push(`${key}：函数体有效 ${m.lines} 行 > 基线 ${bl} + 容差 ${grace}（存量只许持平或变浅）`);
    if (m.complexity > bc + grace) errors.push(`${key}：圈复杂度 ${m.complexity} > 基线 ${bc} + 容差 ${grace}（存量只许持平或变浅）`);
    if (m.lines < bl) notes.push(`${key}：函数体已降 ${bl - m.lines} 行（${bl}→${m.lines}），可下调基线`);
    if (m.complexity < bc) notes.push(`${key}：圈复杂度已降 ${bc - m.complexity}（${bc}→${m.complexity}），可下调基线`);
  }
  return { errors, notes };
}

function gatherFiles() {
  return SCAN_DIRS.flatMap((d) => collect(d, EXT, []));
}

/** 是否超软上限（进基线候选） */
function isOverSoft(m) {
  return m.lines > SOFT_FN_LINES || m.complexity > SOFT_COMPLEXITY;
}

/** 是否超硬上限（必须拆分；force 才收录） */
function isOverHard(m) {
  return m.lines > HARD_FN_LINES || m.complexity > HARD_COMPLEXITY;
}

/** 相对旧基线是否变得更省（用于报告「可下调」） */
function isLowered(o, m) {
  if (!o) return false;
  return m.lines < (o.lines ?? m.lines) || m.complexity < (o.complexity ?? m.complexity);
}

/** 只减不增：基线值取 min(实测, 旧值) */
function baselineEntry(o, m) {
  return {
    lines: o ? Math.min(m.lines, o.lines ?? m.lines) : m.lines,
    complexity: o ? Math.min(m.complexity, o.complexity ?? m.complexity) : m.complexity,
    limitLines: SOFT_FN_LINES,
    limitComplexity: SOFT_COMPLEXITY,
  };
}

/**
 * 产出新的基线条目集合（不碰磁盘）。
 * @param {Record<string,{lines:number,complexity:number}>} measured 当前度量
 * @param {Record<string,{lines:number,complexity:number}>} old 旧基线
 * @param {boolean} force 是否收录超硬上限函数
 * @returns {{next: object, added: string[], lowered: string[], overHard: string[]}}
 */
function buildNextEntries(measured, old, force) {
  const next = {};
  const added = [], lowered = [], overHard = [];
  for (const [key, m] of Object.entries(measured)) {
    if (!isOverSoft(m)) continue;
    if (isOverHard(m)) {
      overHard.push(key);
      if (!force) continue; // 超硬上限者不得进基线（须先拆分）
    }
    if (!old[key]) added.push(key);
    if (isLowered(old[key], m)) lowered.push(key);
    next[key] = baselineEntry(old[key], m);
  }
  return { next, added, lowered, overHard };
}

/**
 * 决定「这次写入是否安全」。
 * @param {{old: object, next: object, overHard: string[], force: boolean}} p 规划参数
 * @returns {null|{reason:string, detail:string}} null 表示可以写
 */
function decideRefusal({ old, next, overHard, force }) {
  if (force) return null;
  // 腰斩保护：真正的「瘦身」不该一次删掉一半以上条目（本仓踩过：242 → 5 条，657 行被吞）
  const oldCount = Object.keys(old).length;
  const newCount = Object.keys(next).length;
  if (oldCount >= 20 && newCount * 2 < oldCount) {
    return { reason: 'collapse', detail: `基线将从 ${oldCount} 条写成 ${newCount} 条（腰斩）` };
  }
  if (overHard.length) return { reason: 'over-hard', detail: `${overHard.length} 个函数超硬上限未入基线` };
  return null;
}

/**
 * 规划基线重生成（纯函数，不碰磁盘）。抽出它的原因见 fixBaseline 的注释：
 * 判断必须发生在**写盘之前**，否则「拒绝」也会把基线写坏。
 * @param {Record<string,{lines:number,complexity:number}>} measured 当前度量
 * @param {Record<string,{lines:number,complexity:number}>} old 旧基线
 * @param {{force?: boolean}} [opts] force 才允许收录超硬上限函数 / 腰斩基线
 * @returns {{next: object, added: string[], removed: string[], lowered: string[], overHard: string[], refuse: null|{reason:string, detail:string}}}
 */
function planBaseline(measured, old, opts = {}) {
  const force = opts.force === true;
  const { next, added, lowered, overHard } = buildNextEntries(measured, old, force);
  const removed = Object.keys(old).filter((k) => !next[k]);
  const refuse = decideRefusal({ old, next, overHard, force });
  return { next, added, removed, lowered, overHard, refuse };
}

function fixBaseline(measured, force) {
  const old = loadBaseline().functions || {};
  // ⚠ [D180] 判据必须在**写盘之前**：旧实现先把文件写成「只含合规函数」的版本，
  // 再返回 exit 2 —— 「拒绝执行」却已经把 657 条基线吞掉了（2026-10-26 实测 242 → 5）。
  // 现在：先 planBaseline 判定；拒绝则**零副作用退出**；允许才原子写（临时文件 + rename）。
  const plan = planBaseline(measured, old, { force });
  if (plan.refuse) {
    console.error(`[complexity] ✗ 拒绝写入基线：${plan.refuse.detail}`);
    if (plan.refuse.reason === 'over-hard') {
      console.error('    超硬上限的函数必须**先拆分**；确属存量请显式 --force 收录（会把它们记进基线，属技术债）。');
      console.error(`    名单：${plan.overHard.slice(0, 10).join(', ')}${plan.overHard.length > 10 ? ' …' : ''}`);
    } else {
      console.error('    基线腰斩通常意味着度量面坏了（扫描目录/语言过滤失效）。确认无误请显式 --force。');
    }
    console.error('    （本次**未改动任何文件**：拒绝 = 零副作用）');
    return 2;
  }
  const doc = {
    _comment: '函数级复杂度基线：只减不增。value 不得被提高；新超限函数不得进入基线。',
    _generatedBy: 'node scripts/complexity-guard.mjs --fix-baseline',
    functions: Object.fromEntries(Object.entries(plan.next).sort()),
  };
  const tmp = `${BASELINE_FILE}.tmp-${process.pid}`;
  fs.writeFileSync(tmp, JSON.stringify(doc, null, 2) + '\n', 'utf8');
  fs.renameSync(tmp, BASELINE_FILE);
  console.log(`[complexity] 已写入基线 ${path.relative(ROOT, BASELINE_FILE)}（${Object.keys(plan.next).length} 个函数）`);
  console.log(`  新增 ${plan.added.length} / 删除 ${plan.removed.length} / 下调 ${plan.lowered.length}`);
  if (plan.added.length) console.log(`  ＋ 新增：${plan.added.slice(0, 10).join(', ')}${plan.added.length > 10 ? ' …' : ''}`);
  if (plan.removed.length) console.log(`  － 删除：${plan.removed.slice(0, 10).join(', ')}${plan.removed.length > 10 ? ' …' : ''}`);
  if (plan.lowered.length) console.log(`  ↓ 下调：${plan.lowered.slice(0, 10).join(', ')}${plan.lowered.length > 10 ? ' …' : ''}`);
  return 0;
}

// ---------- CLI ----------
function main() {
  const args = process.argv.slice(2);
  if (args.includes('--selftest')) return selftestMain();
  const fix = args.includes('--fix-baseline');
  const jsonOut = args.includes('--json');
  const force = args.includes('--force');

  const files = gatherFiles();
  const measured = measureFunctions(files);
  const baseline = loadBaseline();

  if (fix) return fixBaseline(measured, force);

  const { errors, notes } = judge(measured, baseline);
  if (jsonOut) {
    console.log(JSON.stringify({ measured, errors, notes }, null, 2));
    return errors.length ? 1 : 0;
  }
  for (const n of notes) console.log(`  ⚠ ${n}`);
  if (errors.length) {
    console.error(`❌ 函数级复杂度门禁：${errors.length} 处违规`);
    for (const e of errors) console.error(`   · ${e}`);
    console.error('\n如何修：按职责把长函数/高分支函数拆成若干子函数；不要为降指标机械搬移代码。');
    console.error('若确认某函数无法在本次改动内拆分，请先拆，不要把它写进基线放宽。');
    return 1;
  }
  const inBaseline = Object.keys(baseline.functions || {}).length;
  console.log(`✅ 函数级复杂度门禁通过（扫描 ${files.length} 个文件；基线内技术债 ${inBaseline} 个函数）`);
  return 0;
}

/**
 * [D217] 匿名函数行号漂移的判据自证。
 * 从 selftestMain 拆出：加上这两条后主体超过 100 行软上限（门禁对自己的要求一样适用）。
 * @param {(name: string, fn: () => void) => void} t 用例执行器
 * @param {(v: unknown, m: string) => void} ok 断言
 * @returns {void}
 */
function selftestArrowRemap(t, ok) {
  t('⑨ 匿名函数仅行号漂移（同文件数量不变）不误报', () => {
    const measured = { 'x.js::<arrow@20>': { lines: 120, complexity: 18 } };
    const base = { 'x.js::<arrow@10>': { lines: 120, complexity: 18 } };
    const r = judge(measured, { functions: base });
    ok(r.errors.length === 0, `仅行号漂移不应报错，实际：${r.errors.join('|')}`);
  });
  t('⑩ 匿名函数数量变化仍报错（不掩盖新增）', () => {
    const measured = {
      'x.js::<arrow@20>': { lines: 120, complexity: 18 },
      'x.js::<arrow@40>': { lines: 300, complexity: 30 },
    };
    const base = { 'x.js::<arrow@10>': { lines: 120, complexity: 18 } };
    const r = judge(measured, { functions: base });
    ok(r.errors.length > 0, '新增的匿名超硬上限函数必须仍被报出');
    ok(r.errors.some((e) => e.includes('arrow@40')), `应点名新增的那个，实际：${r.errors.join('|')}`);
  });
  t('⑪ 存量匿名函数变差仍报错（特征不匹配不回退放行）', () => {
    const measured = { 'x.js::<arrow@20>': { lines: 140, complexity: 40 } };
    const base = { 'x.js::<arrow@10>': { lines: 120, complexity: 18 } };
    const r = judge(measured, { functions: base });
    ok(r.errors.length > 0, '变差后必须报错（不能因「同一个箭头」而放行）');
    ok(/硬上限/.test(r.errors[0]), `应按新函数超硬上限报出，实际：${r.errors[0]}`);
  });
}

function selftestMain() {
  let failed = 0;
  const t = (name, fn) => {
    try { fn(); console.log(`  ✔ ${name}`); }
    catch (e) { failed++; console.log(`  ✖ ${name}\n    ${e.message}`); }
  };
  const ok = (v, m) => { if (!v) throw new Error(m); };

  console.log('自证（判据不得空转）：');

  // 夹具写 os.tmpdir()，退出用 process.exitCode（继承 greenguard-check 事故教训）
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'complexity-selftest-'));
  const write = (name, content) => {
    const p = path.join(dir, name);
    fs.writeFileSync(p, content, 'utf8');
    return p;
  };
  try {
    // ① 250 行单函数 → 被报出且定位到该函数
    const longSrc = 'function longFn() {\n'
      + Array.from({ length: 250 }, (_, i) => `  const v${i} = ${i};`).join('\n')
      + '\n}\n';
    const longFile = write('long.js', longSrc);
    const mLong = measureFunctions([longFile]);
    const longKey = Object.keys(mLong).find((k) => k.includes('longFn'));
    t('① 250 行单函数被度量并报出', () => {
      ok(longKey, `未识别出 longFn，实测键：${Object.keys(mLong).join(',')}`);
      ok(mLong[longKey].lines > HARD_FN_LINES, `有效行数应超硬上限 200，实际 ${mLong[longKey].lines}`);
      const r = judge(mLong, { functions: {} });
      ok(r.errors.some((e) => e.includes('longFn')), `应报出 longFn，实际：${r.errors.join('|')}`);
    });

    // ② 分支密集 → 复杂度超限被报出
    const branchySrc = 'function branchy(a) {\n'
      + Array.from({ length: 30 }, (_, i) => `  if (a === ${i}) return ${i};`).join('\n')
      + '\n  return -1;\n}\n';
    const branchyFile = write('branchy.js', branchySrc);
    const mBranchy = measureFunctions([branchyFile]);
    const branchyKey = Object.keys(mBranchy).find((k) => k.includes('branchy'));
    t('② 分支密集函数复杂度超限被报出', () => {
      ok(branchyKey, `未识别出 branchy，实测键：${Object.keys(mBranchy).join(',')}`);
      ok(mBranchy[branchyKey].complexity > HARD_COMPLEXITY, `圈复杂度应超硬上限 25，实际 ${mBranchy[branchyKey].complexity}`);
      const r = judge(mBranchy, { functions: {} });
      ok(r.errors.some((e) => e.includes('branchy') && /复杂度/.test(e)), `应报复杂度超限，实际：${r.errors.join('|')}`);
    });

    // ③ 假基线「基线 6 → 现测 7」判「变差」
    t('③ 存量函数度量变差被判失败', () => {
      const r = judge(
        { 'x.js::f': { lines: 7, complexity: 2 } },
        { functions: { 'x.js::f': { lines: 6, complexity: 2 } } },
      );
      ok(r.errors.length >= 1, '基线 6 变 7 应报错');
      ok(/只许持平或变浅/.test(r.errors[0]), `错误信息应说明只许持平或变浅：${r.errors[0]}`);
    });

    // ④ 合规函数不报（防误伤）
    t('④ 合规函数不报（防误伤）', () => {
      const r = judge({ 'x.js::f': { lines: 50, complexity: 5 } }, { functions: {} });
      ok(r.errors.length === 0, `合规函数不应报错，实际：${r.errors.join('|')}`);
    });

    // ⑤ 词法反证：模板串/注释内的大括号与 if 不计入体积与复杂度
    const trickySrc = 'function tricky() {\n'
      + '  const t = `if if { ${x} }`;\n'
      + '  // if { { {\n'
      + '  /* if if { */\n'
      + '  return 1;\n'
      + '}\n';
    const trickyFile = write('tricky.js', trickySrc);
    const mTricky = measureFunctions([trickyFile]);
    const trickyKey = Object.keys(mTricky).find((k) => k.includes('tricky'));
    t('⑤ 模板串/注释内的 { 与 if 不计入', () => {
      ok(trickyKey, `未识别出 tricky，实测键：${Object.keys(mTricky).join(',')}`);
      ok(mTricky[trickyKey].complexity === 1, `纯函数复杂度应为 1，实际 ${mTricky[trickyKey].complexity}`);
      ok(mTricky[trickyKey].lines <= 4, `注释行应被剔除，实际有效行 ${mTricky[trickyKey].lines}`);
    });

    // ⑥⑦⑧ [D180] --fix-baseline 的写盘安全性（本仓 2026-10-26 实测过：拒绝执行却把基线
    // 从 242 条写成 5 条）。判据必须是纯函数、且在写盘之前。
    t('⑥ 超硬上限存在时 fix-baseline 拒绝（且拒绝理由是 over-hard）', () => {
      const measured = { 'x.js::giant': { lines: 260, complexity: 30 } };
      const plan = planBaseline(measured, {}, {});
      ok(plan.refuse && plan.refuse.reason === 'over-hard', `应拒绝且原因为 over-hard，实际 ${JSON.stringify(plan.refuse)}`);
      ok(plan.overHard.includes('x.js::giant'), '应点名超硬上限函数');
    });
    t('⑦ 基线腰斩（242 → 少量）被拒绝，防「度量面坏掉」把基线写没', () => {
      const old = Object.fromEntries(Array.from({ length: 240 }, (_, i) => [`f${i}.js::fn`, { lines: 150, complexity: 20 }]));
      const measured = { 'f0.js::fn': { lines: 150, complexity: 20 } };
      const plan = planBaseline(measured, old, {});
      ok(plan.refuse && plan.refuse.reason === 'collapse', `应拒绝且原因为 collapse，实际 ${JSON.stringify(plan.refuse)}`);
      // --force 才放行（显式确认）
      ok(planBaseline(measured, old, { force: true }).refuse === null, '--force 应放行');
    });
    t('⑧ 正常瘦身：只降不升，且不会把旧条目无故丢掉', () => {
      const old = { 'a.js::f': { lines: 160, complexity: 20 }, 'b.js::g': { lines: 140, complexity: 18 } };
      const measured = { 'a.js::f': { lines: 120, complexity: 20 }, 'b.js::g': { lines: 140, complexity: 18 } };
      const plan = planBaseline(measured, old, {});
      ok(plan.refuse === null, `不应拒绝，实际 ${JSON.stringify(plan.refuse)}`);
      ok(plan.next['a.js::f'].lines === 120, `应下调到实测值 120，实际 ${plan.next['a.js::f'].lines}`);
      ok(plan.next['b.js::g'].lines === 140, '未变条目应保持');
      ok(plan.removed.length === 0, `不应删除条目，实际 ${plan.removed.join(',')}`);
      const raised = planBaseline({ 'a.js::f': { lines: 300, complexity: 30 } }, old, { force: true });
      ok(raised.next['a.js::f'].lines === 160, '只减不增：基线不得被提高');
    });

    // ⑨⑩ [D217] 匿名函数行号漂移判据（拆到独立函数，守住 selftestMain 的 100 行软上限）
    selftestArrowRemap(t, ok);

    console.log(failed ? `\n❌ selftest ${failed} 条失败` : '\n✅ selftest 全绿');
    process.exitCode = failed ? 1 : 0;
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* 夹具在 tmpdir，漏清也伤不到门禁 */ }
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  // selftestMain 通过 process.exitCode 报告结果（让 finally 能清理 tmpdir 夹具）；
  // 故这里仅在 main 返回了明确退出码时才覆盖，否则保留 exitCode。
  const code = main();
  if (code !== undefined) process.exit(code);
}