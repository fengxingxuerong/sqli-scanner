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
//   --fix-baseline 写入前校验新条目不得超过硬上限（超者须先拆分，除非 --force）。
//
// 用法：
//   node scripts/complexity-guard.mjs               # 检查（违规则 exit 1）
//   node scripts/complexity-guard.mjs --selftest    # 自证判据不空转
//   node scripts/complexity-guard.mjs --fix-baseline# 瘦身后重生成基线
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
  const base = baseline.functions || {};
  for (const [key, m] of Object.entries(measured)) {
    const b = base[key];
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

function fixBaseline(measured, force) {
  const old = loadBaseline().functions || {};
  const next = {};
  const added = [], removed = [], lowered = [], overHard = [];
  for (const [key, m] of Object.entries(measured)) {
    const overSoft = m.lines > SOFT_FN_LINES || m.complexity > SOFT_COMPLEXITY;
    if (!overSoft) continue;
    if (m.lines > HARD_FN_LINES || m.complexity > HARD_COMPLEXITY) {
      overHard.push(key);
      if (!force) continue; // 超硬上限者不得进基线（须先拆分）
    }
    const o = old[key];
    if (!o) added.push(key);
    // 只减不增：基线值不得被提高
    const lines = o ? Math.min(m.lines, o.lines ?? m.lines) : m.lines;
    const complexity = o ? Math.min(m.complexity, o.complexity ?? m.complexity) : m.complexity;
    if (o && (lines < (o.lines ?? lines) || complexity < (o.complexity ?? complexity))) lowered.push(key);
    next[key] = { lines, complexity, limitLines: SOFT_FN_LINES, limitComplexity: SOFT_COMPLEXITY };
  }
  for (const key of Object.keys(old)) if (!next[key]) removed.push(key);
  const doc = {
    _comment: '函数级复杂度基线：只减不增。value 不得被提高；新超限函数不得进入基线。',
    _generatedBy: 'node scripts/complexity-guard.mjs --fix-baseline',
    functions: Object.fromEntries(Object.entries(next).sort()),
  };
  fs.writeFileSync(BASELINE_FILE, JSON.stringify(doc, null, 2) + '\n', 'utf8');
  console.log(`[complexity] 已写入基线 ${path.relative(ROOT, BASELINE_FILE)}（${Object.keys(next).length} 个函数）`);
  console.log(`  新增 ${added.length} / 删除 ${removed.length} / 下调 ${lowered.length}`);
  if (added.length) console.log(`  ＋ 新增：${added.slice(0, 10).join(', ')}${added.length > 10 ? ' …' : ''}`);
  if (removed.length) console.log(`  － 删除：${removed.slice(0, 10).join(', ')}${removed.length > 10 ? ' …' : ''}`);
  if (lowered.length) console.log(`  ↓ 下调：${lowered.slice(0, 10).join(', ')}${lowered.length > 10 ? ' …' : ''}`);
  if (overHard.length && !force) console.warn(`  ⚠ ${overHard.length} 个函数超硬上限未入基线（须先拆分；确属存量可 --force 收录）`);
  return overHard.length && !force ? 2 : 0;
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