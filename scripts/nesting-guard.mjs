#!/usr/bin/env node
// ============================================================================
// scripts/nesting-guard.mjs —— 代码嵌套深度门禁（基线制）
//
// ── 为什么要有这道门 ─────────────────────────────────────────────────────────
// arch-guard 管体积（行数 + 字节），但**没有任何门禁管嵌套深度**。
// 深度与体积是两个独立维度，真实事故也长这样：
//   · 一个 200 行的文件可以套 8 层 if/for/try，每加一层就多一层缩进与一份控制流状态；
//   · 「改一个分支时忘了另一分支」这类 bug，在深嵌套里发生率显著更高 ——
//     因为"这个 if 属于哪个循环"需要向上数缩进才能确认。
// 而检测编排类代码（switch → case → for → try → if）天然容易堆到 8~10 层。
//
// ── 为什么用基线制（存量豁免 + 收紧容差），而不是一刀切 ───────────────────────
// 存量 94 个文件深度 ≥5，直接判红等于要求一次性重构全仓——那是拿"质量"的名义
// 制造一次巨大的、无测试覆盖的破坏性改动，风险远大于收益。
// 与 arch-guard 的体积门禁同一取向：
//   · 超**硬上限**的，任何情况下不得继续加深（必须先拆）；
//   · 存量文件只允许**持平或变浅**，变深即失败（防技术债滚雪球）；
//   · 深度超**软上限**的新文件 → 直接失败（新人/新代码不得从 7 层起步）。
//
// ── 度量方法（为什么不能直接数 '{'）────────────────────────────────────────
// 朴素做法是数大括号，但会把这些全部误算进深度：
//   · 字符串/模板串里的 '{'（如 `${db}.${t}`、payload 模板里的 '{'）—— 而本仓
//     **恰好**大量使用模板串与 SQL 模板，这类误算极其常见；
//   · 注释里的 '{'（本仓注释密度很高，且常引用代码形态）；
//   · 正则字面量里的 '{'。
// 因此这里做逐字符词法扫描：跳过字符串/模板串、行注释、块注释后再计深度。
// 实测：不跳过的粗测把 extractScope.js 报成 11，词法精确测得是 10 —— 差值即误算量。
//
// ── 误报与口径 ─────────────────────────────────────────────────────────────
// · 对象字面量 `{ a: 1 }` 会计入深度。这是**保守**方向（可能略微高估），
//   对"只许变浅"的门禁来说可以接受：高估只会让基线留得宽一点，不会造成假绿。
// · 基线由 --selftest / --fix-baseline 生成，不手写。
// ============================================================================
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { lex } from './lib/jsLexer.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE_FILE = path.join(ROOT, 'docs', '_nesting-baseline.json');

const SCAN_DIRS = ['server/src', 'src', 'scripts', 'e2e'];
const EXT = ['.js', '.ts', '.tsx', '.mjs'];

// 软上限：超过即视为「新债」，新文件直接失败
const SOFT_MAX = 7;
// 硬上限：任何文件任何情况下不得越过（存量已超的进基线，须持平或变浅）
const HARD_MAX = 10;
// 容差：基线文件允许比基线再深 0 层（刻意设 0）
const GRACE = 0;

/**
 * 词法精确的嵌套深度分析：跳过字符串/模板串/行注释/块注释，只数真实代码块。
 * @param {string} src
 * @returns {{max:number, maxLine:number, hotlines:number[]}}
 */
export function analyzeNesting(src) {
  // [D53 2026-10-13] 词法内核抽取到 scripts/lib/jsLexer.mjs，本函数改为复用。
  // 输出契约（max/maxLine/hotlines）逐字节不变 —— 判据细节（跳字符串/模板串/
  // 注释、对象字面量 vs 代码块）搬到 jsLexer.lex，那里是唯一真源，避免四类新门禁
  // 各写一份扫描器重蹈误算。
  const { maxDepth, maxDepthLine, tokens } = lex(src);
  const hotlines = [];
  let depth = 0;
  for (const t of tokens) {
    if (t.type !== 'brace') continue;
    if (t.value === '{') {
      if (t.block) { depth++; if (depth >= SOFT_MAX) hotlines.push(t.line); }
    } else if (t.block) {
      depth--;
    }
  }
  return { max: maxDepth, maxLine: maxDepthLine, hotlines };
}

function collect(rel, exts, out) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) return out;
  for (const ent of fs.readdirSync(abs, { withFileTypes: true })) {
    const sub = path.posix.join(rel.replace(/\\/g, '/'), ent.name);
    if (ent.isDirectory()) {
      if (['node_modules', 'dist', 'build', 'target', '.git', 'coverage'].includes(ent.name)) continue;
      collect(sub, exts, out);
    } else if (exts.some((e) => ent.name.endsWith(e))) out.push(sub);
  }
  return out;
}

/** @returns {Record<string, number>} rel → max depth */
export function measureAll() {
  const files = SCAN_DIRS.flatMap((d) => collect(d, EXT, []));
  const out = {};
  for (const f of files) {
    const { max } = analyzeNesting(fs.readFileSync(path.join(ROOT, f), 'utf8'));
    if (max > 0) out[f] = max;
  }
  return out;
}

function loadBaseline() {
  try {
    return JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf8'));
  } catch {
    return { _comment: '嵌套深度基线：存量文件的最深层级。只许持平或变浅，不许加深。', files: {} };
  }
}

export function judge(measured, baseline, opts = {}) {
  const soft = opts.softMax ?? SOFT_MAX;
  const hard = opts.hardMax ?? HARD_MAX;
  const grace = opts.grace ?? GRACE;
  const errors = [];
  const notes = [];
  for (const [f, depth] of Object.entries(measured)) {
    const base = baseline.files?.[f];
    if (depth > hard) {
      errors.push(`${f}：嵌套 ${depth} 层，越过硬上限 ${hard}（必须先拆分）`);
      continue;
    }
    if (base === undefined) {
      if (depth > soft) errors.push(`${f}：嵌套 ${depth} 层，超过软上限 ${soft}（新文件请用卫语句/早返回压平）`);
      else if (depth >= soft) notes.push(`${f}：嵌套 ${depth} 层，已达软上限`);
      continue;
    }
    if (depth > base + grace) {
      errors.push(`${f}：嵌套 ${depth} 层 > 基线 ${base} + 容差 ${grace}（存量只许持平或变浅）`);
    }
  }
  return { errors, notes };
}

// ---------- CLI ----------
function main() {
  const args = process.argv.slice(2);
  const selftest = args.includes('--selftest');
  const fixBaseline = args.includes('--fix-baseline');

  if (selftest) {
    return selftestMain();
  }

  const measured = measureAll();
  const baseline = loadBaseline();

  if (fixBaseline) {
    const next = {
      _comment: '嵌套深度基线：存量文件的最深层级。只许持平或变浅，不许加深。',
      _generatedBy: 'node scripts/nesting-guard.mjs --fix-baseline',
      files: Object.fromEntries(Object.entries(measured).filter(([, d]) => d >= SOFT_MAX).sort()),
    };
    fs.writeFileSync(BASELINE_FILE, JSON.stringify(next, null, 2) + '\n', 'utf8');
    console.log(`[nesting] 已写入基线 ${path.relative(ROOT, BASELINE_FILE)}（${Object.keys(next.files).length} 个文件）`);
    return 0;
  }

  const { errors, notes } = judge(measured, baseline);
  for (const n of notes) console.log(`  ⚠ ${n}`);
  if (errors.length) {
    console.error(`❌ 嵌套深度门禁：${errors.length} 处违规`);
    for (const e of errors) console.error(`   · ${e}`);
    console.error('\n如何修：用卫语句/早返回把 if-else 链拍平；复杂分支抽成独立函数。');
    console.error('若确认某文件无法在本次改动内压平，请先拆函数，不要调高上限。');
    return 1;
  }
  const deep = Object.entries(measured).filter(([, d]) => d >= SOFT_MAX);
  const maxD = Math.max(0, ...Object.values(measured));
  console.log(`✅ 嵌套深度门禁通过（最深 ${maxD} 层，≥${SOFT_MAX} 层的 ${deep.length} 个文件已在基线内）`);
  return 0;
}

function selftestMain() {
  let failed = 0;
  const t = (name, fn) => {
    try { fn(); console.log(`  ✔ ${name}`); }
    catch (e) { failed++; console.log(`  ✖ ${name}\n    ${e.message}`); }
  };
  const eq = (a, b, m) => { if (a !== b) throw new Error(`${m}：期望 ${b}，实际 ${a}`); };
  const ok = (v, m) => { if (!v) throw new Error(m); };

  console.log('自证（判据不得空转）：');

  /** 造一个恰好 d 层真实嵌套的源码 */
  const deepSrc = (d) => {
    let s = '';
    for (let i = 0; i < d; i++) s += `if(a${i}){\n`;
    s += 'x();\n';
    for (let i = 0; i < d; i++) s += '}\n';
    return s;
  };
  const DEPTH = analyzeNesting(deepSrc(8)).max;
  eq(DEPTH, 8, 'deepSrc 自检：生成的源码应确为 8 层');

  t('词法：模板串里的 { 不计深度', () => {
    // 真实深度 1（if），但模板串里有大括号与花括号文本
    const src = 'if (a) {\n  const x = `${a}.${b}`;\n  const y = "{}{}";\n}\n';
    eq(analyzeNesting(src).max, 1, '模板串/字符串里的 { 不该计深度');
  });

  t('词法：注释里的 { 不计深度', () => {
    const src = 'if (a) {\n  // 这里写了 { { { 不要被数进去\n  /* 块注释 { { */\n}\n';
    eq(analyzeNesting(src).max, 1, '注释里的 { 不该计深度');
  });

  t('词法：真实嵌套逐层递增', () => {
    // function{} → if{} → for{} → try{} = 4 层
    const src = 'function f(){\n if(a){\n  for(;;){\n   try{\n    x();\n   }catch(e){ }\n  }\n }\n}\n';
    eq(analyzeNesting(src).max, 4, '应为 4 层');
    // 再加一层 if 变 5 层 —— 证明判据确实随嵌套递增，而非固定值
    const src2 = 'function f(){\n if(a){\n  if(b){\n   for(;;){\n    try{\n     x();\n    }catch(e){ }\n   }\n  }\n }\n}\n';
    eq(analyzeNesting(src2).max, 5, '应为 5 层');
  });

  t('词法：对象字面量不计深度（否则基线虚高 = 门禁被放宽）', () => {
    // `Array.from({ length: n }, ...)` 这类实参对象曾被记成一层 ⇒ injection.js
    // 测得 7 层而真实控制流只有 5 层，基线因此虚高，后续任何加深都豁免。
    const withObj = 'function f(){\n  if (a) {\n    const x = Array.from({ length: n }, () => 1);\n    return x;\n  }\n}\n';
    eq(analyzeNesting(withObj).max, 2, '实参对象字面量不应计入深度');
    // 去掉对象字面量，深度必须不变 —— 证明判据不是碰巧相等
    const without = withObj.replace('Array.from({ length: n }, () => 1)', 'list');
    eq(analyzeNesting(without).max, 2, '去掉对象字面量后深度应仍为 2');
  });

  t('词法：赋值/返回/数组内的对象字面量都不计深度', () => {
    eq(analyzeNesting('const a = {\n  b: 1,\n};\n').max, 0, '赋值对象');
    eq(analyzeNesting('function f(){\n  return {\n    b: 1,\n  };\n}\n').max, 1, 'return 对象（函数块仍计）');
    eq(analyzeNesting('const a = [{\n  b: 1,\n}];\n').max, 0, '数组内对象');
  });

  t('词法：对象字面量的 } 不得误减后续深度（配对栈）', () => {
    // 若对象字面量的 '}' 被当成代码块收尾，后面真正的 if 深度会被算浅 1 层
    const src = 'function f(){\n  const o = { a: 1 };\n  if (x) {\n    if (y) {\n      z();\n    }\n  }\n}\n';
    eq(analyzeNesting(src).max, 3, 'function+if+if = 3 层，对象字面量不得影响');
  });

  t('判据：新文件超软上限 ⇒ 报错（不得假绿）', () => {
    // judge 的入参是**层数**（measureAll 的产物形态），不是源码文本 —— 先测出来再传
    const d8 = analyzeNesting(deepSrc(8)).max;
    const r = judge({ 'a.js': d8 }, { files: {} }, { softMax: 7, hardMax: 10, grace: 0 });
    ok(r.errors.length === 1, `期望 1 条错误，实际 ${r.errors.length} —— 判据可能空转`);
    ok(/软上限/.test(r.errors[0]), `错误信息应指明软上限，实际：${r.errors[0]}`);
  });

  t('判据：基线文件加深 ⇒ 报错（防债滚雪球）', () => {
    const r = judge({ 'a.js': 7 }, { files: { 'a.js': 6 } }, { softMax: 7, hardMax: 10, grace: 0 });
    ok(r.errors.length === 1, '基线 6 变 7 应报错');
    ok(/只许持平或变浅/.test(r.errors[0]), `错误信息应说明只许持平或变浅：${r.errors[0]}`);
  });

  t('判据：基线文件持平 ⇒ 通过（不误伤）', () => {
    const r = judge({ 'a.js': 6 }, { files: { 'a.js': 6 } }, { softMax: 7, hardMax: 10, grace: 0 });
    eq(r.errors.length, 0, '持平不应报错');
  });

  t('判据：越过硬上限 ⇒ 报错且消息含"必须先拆分"', () => {
    const r = judge({ 'a.js': 11 }, { files: { 'a.js': 11 } }, { softMax: 7, hardMax: 10, grace: 0 });
    ok(r.errors.length === 1, '越过硬上限应报错');
    ok(/必须先拆分/.test(r.errors[0]), `消息应含"必须先拆分"：${r.errors[0]}`);
  });

  t('判据：真实仓库现状不判红（基线已收录）', () => {
    const measured = measureAll();
    const baseline = loadBaseline();
    const r = judge(measured, baseline);
    eq(r.errors.length, 0, `当前仓库应通过，但报出：${r.errors.slice(0, 3).join(' | ')}`);
  });

  console.log(failed ? `\n❌ selftest ${failed} 条失败` : '\n✅ selftest 全绿');
  return failed ? 1 : 0;
}

// 仅在被直接执行时跑 CLI（`node scripts/nesting-guard.mjs`）。
// 不写成无条件 process.exit(main())：那样一来，本模块的 analyzeNesting / judge
// 就**无法被测试 import** —— import 会在求值时执行 main() 并直接结束测试进程。
// （实测踩过：想给 analyzeNesting 写单测，结果 import 把 runner 杀了，测试静默"通过"。）
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) process.exit(main());