#!/usr/bin/env node
// ============================================================================
// scripts/typecoverage-guard.mjs —— JSDoc 类型覆盖门禁（基线制）
//
// ── 为什么要有这道门 ─────────────────────────────────────────────────────────
// server/tsconfig.json 自述 noImplicitAny 有 3045 处未启用；eslint 显式关闭
// no-explicit-any。编译器开关一时半会打不开，但「类型标注覆盖率」可以**独立于
// 编译器开关**度量推进度：JSDoc @param/@returns 标注了多少参数和返回值。
// 本门禁按目录批次度量覆盖率，基线锁定只升不降，首批选 1 个目录归零。
//
// ── 判据 ─────────────────────────────────────────────────────────────────────
// · 参数类型来源：JSDoc `@param {type} name` 或行内 JSDoc
// · 返回值来源：JSDoc `@returns {type}` 或 `@return {type}`
// · coverage = (已标注参数 + 已标注返回值) / (参数总数 + 函数总数)
// · 批次以目录为单位：server/src/core、server/src/engine、server/src/api、server/src/services
//
// ── 基线「只升不降」────────────────────────────────────────────────────────
// docs/_typecoverage-baseline.json 记录各批次覆盖率与未标注热点。
// 检查时：coverage 不得低于基线、untypedHotspots 范围不得扩大、批次集合不得缩小。
//
// 用法：
//   node scripts/typecoverage-guard.mjs               # 检查
//   node scripts/typecoverage-guard.mjs --selftest    # 自证判据不空转
//   node scripts/typecoverage-guard.mjs --fix-baseline# 重生成基线
//   node scripts/typecoverage-guard.mjs --json        # 机器可读输出
// ============================================================================
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { findFunctions } from './lib/jsLexer.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE_FILE = path.join(ROOT, 'docs', '_typecoverage-baseline.json');

const BATCHES = ['server/src/core', 'server/src/engine', 'server/src/api', 'server/src/services'];
const EXT = ['.js', '.ts', '.tsx', '.mjs'];

function collect(rel, exts, out) {
  const abs = path.isAbsolute(rel) ? rel : path.join(ROOT, rel);
  if (!fs.existsSync(abs)) return out;
  for (const ent of fs.readdirSync(abs, { withFileTypes: true })) {
    if (ent.name.startsWith('.')) continue;
    const sub = path.isAbsolute(rel)
      ? path.join(rel, ent.name).replace(/\\/g, '/')
      : path.posix.join(rel.replace(/\\/g, '/'), ent.name);
    if (ent.isDirectory()) {
      if (['node_modules', 'dist', 'build', 'target', '.git', 'coverage'].includes(ent.name)) continue;
      collect(sub, exts, out);
    } else if (exts.some((e) => ent.name.endsWith(e))) out.push(sub);
  }
  return out;
}

// 从源码中提取 JSDoc 注释块（/** ... */）并关联到紧随其后的函数
function extractJsdocBlocks(src) {
  const blocks = [];
  const lines = src.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trimStart();
    if (trimmed.startsWith('/**')) {
      let end = i;
      for (let j = i + 1; j < lines.length; j++) {
        if (lines[j].includes('*/')) { end = j; break; }
      }
      blocks.push({ startLine: i + 1, endLine: end + 1, text: lines.slice(i, end + 1).join('\n') });
      i = end;
    }
  }
  return blocks;
}

// 解析 JSDoc 块中的 @param 和 @returns 标注
function parseJsdocTypes(jsdocText) {
  const paramNames = new Set();
  const hasReturn = /@returns?\s+\{[^}]+\}/.test(jsdocText) || /@returns?\s+\S/.test(jsdocText);
  const paramRe = /@param\s+\{[^}]+\}\s+(\[?\w+\]?)/g;
  let m;
  while ((m = paramRe.exec(jsdocText)) !== null) {
    const name = m[1].replace(/[[\]]/g, '');
    paramNames.add(name);
  }
  return { paramNames, hasReturn };
}

/**
 * 度量给定批次列表的 JSDoc 类型覆盖率。
 * @param {string[]} batches 相对仓库根的目录路径
 * @returns {Record<string, {paramsTotal:number, paramsTyped:number, returnsTotal:number, returnsTyped:number, coverage:number, untypedHotspots:string[]}>}
 */
export function measureCoverage(batches) {
  const out = {};
  for (const batch of batches) {
    const files = collect(batch, EXT, []);
    let paramsTotal = 0, paramsTyped = 0, returnsTotal = 0, returnsTyped = 0;
    const untypedHotspots = [];
    for (const file of files) {
      const abs = path.isAbsolute(file) ? file : path.join(ROOT, file);
      let src;
      try { src = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const { functions } = findFunctions(src);
      const jsdocBlocks = extractJsdocBlocks(src);
      for (const fn of functions) {
        // 找紧邻函数定义前的 JSDoc 块
        const jsdoc = jsdocBlocks.find((b) => b.endLine + 1 >= fn.startLine && b.endLine < fn.startLine + 2);
        const { paramNames, hasReturn } = jsdoc ? parseJsdocTypes(jsdoc.text) : { paramNames: new Set(), hasReturn: false };
        returnsTotal++;
        if (hasReturn) returnsTyped++;
        const fnParams = fn.params || [];
        for (const p of fnParams) {
          paramsTotal++;
          if (paramNames.has(p)) paramsTyped++;
          else if (!jsdoc) {
            untypedHotspots.push(`${file}:${fn.startLine} ${fn.name}(@${p})`);
          }
        }
        if (!hasReturn && !jsdoc) {
          untypedHotspots.push(`${file}:${fn.startLine} ${fn.name}()→?`);
        }
      }
    }
    const denom = paramsTotal + returnsTotal;
    const coverage = denom > 0 ? (paramsTyped + returnsTyped) / denom : 1;
    out[batch] = {
      paramsTotal, paramsTyped, returnsTotal, returnsTyped,
      coverage: Math.round(coverage * 1000) / 10,
      untypedHotspots: untypedHotspots.slice(0, 50),
    };
  }
  return out;
}

function loadBaseline() {
  try {
    return JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf8'));
  } catch {
    return { _comment: 'JSDoc 类型覆盖基线：只升不降。', batches: {} };
  }
}

/**
 * 按基线裁定实测结果。
 * @param {Record<string,object>} measured
 * @param {{batches?:Record<string,object>}} baseline
 * @returns {{errors:string[], notes:string[]}}
 */
export function judge(measured, baseline) {
  const errors = [];
  const notes = [];
  const base = baseline.batches || {};
  const measuredBatches = Object.keys(measured);
  const baselineBatches = Object.keys(base);
  // 批次集合不得缩小
  for (const b of baselineBatches) {
    if (!measuredBatches.includes(b)) errors.push(`批次 ${b} 在基线中但当前未度量 —— 批次集合不得缩小`);
  }
  for (const [batch, m] of Object.entries(measured)) {
    const b = base[batch];
    if (!b) {
      notes.push(`${batch}：新批次，覆盖率 ${m.coverage}%`);
      continue;
    }
    if (m.coverage < b.coverage) {
      errors.push(`${batch}：覆盖率 ${m.coverage}% < 基线 ${b.coverage}%（只升不降）`);
    }
    if (m.coverage > b.coverage) {
      notes.push(`${batch}：覆盖率 ${m.coverage}% > 基线 ${b.coverage}%（可上调基线）`);
    }
    const baseHotspots = b.untypedHotspots || [];
    if (m.untypedHotspots.length > baseHotspots.length) {
      errors.push(`${batch}：未标注热点 ${m.untypedHotspots.length} > 基线 ${baseHotspots.length}（范围不得扩大）`);
    }
  }
  return { errors, notes };
}

function fixBaseline(measured) {
  const old = loadBaseline().batches || {};
  const next = {};
  const added = [], improved = [], degraded = [];
  for (const [batch, m] of Object.entries(measured)) {
    const o = old[batch];
    if (!o) added.push(batch);
    const coverage = o ? Math.max(m.coverage, o.coverage ?? 0) : m.coverage;
    if (o && m.coverage > (o.coverage ?? 0)) improved.push(batch);
    if (o && m.coverage < (o.coverage ?? 0)) degraded.push(batch);
    next[batch] = {
      coverage,
      paramsTotal: m.paramsTotal,
      paramsTyped: m.paramsTyped,
      returnsTotal: m.returnsTotal,
      returnsTyped: m.returnsTyped,
      untypedHotspots: m.untypedHotspots,
    };
  }
  const doc = {
    _comment: 'JSDoc 类型覆盖基线：只升不降。coverage 不得被降低；untypedHotspots 范围不得扩大。',
    _generatedBy: 'node scripts/typecoverage-guard.mjs --fix-baseline',
    batches: Object.fromEntries(Object.entries(next).sort()),
  };
  fs.writeFileSync(BASELINE_FILE, JSON.stringify(doc, null, 2) + '\n', 'utf8');
  console.log(`[typecoverage] 已写入基线 ${path.relative(ROOT, BASELINE_FILE)}（${Object.keys(next).length} 个批次）`);
  for (const [batch, m] of Object.entries(next)) {
    console.log(`  ${batch}: ${m.coverage}% (${m.paramsTyped}/${m.paramsTotal} 参数 + ${m.returnsTyped}/${m.returnsTotal} 返回)`);
  }
  if (added.length) console.log(`  ＋ 新增：${added.join(', ')}`);
  if (improved.length) console.log(`  ↑ 改善：${improved.join(', ')}`);
  if (degraded.length) console.warn(`  ⚠ 下降：${degraded.join(', ')}（基线保持旧值，只升不降）`);
  return 0;
}

// ---------- CLI ----------
function main() {
  const args = process.argv.slice(2);
  if (args.includes('--selftest')) return selftestMain();
  const fix = args.includes('--fix-baseline');
  const jsonOut = args.includes('--json');

  const measured = measureCoverage(BATCHES);
  const baseline = loadBaseline();

  if (fix) return fixBaseline(measured);

  const { errors, notes } = judge(measured, baseline);
  if (jsonOut) {
    console.log(JSON.stringify({ measured, errors, notes }, null, 2));
    return errors.length ? 1 : 0;
  }
  for (const [batch, m] of Object.entries(measured)) {
    console.log(`  ${batch}: ${m.coverage}% (${m.paramsTyped}/${m.paramsTotal} 参数 + ${m.returnsTyped}/${m.returnsTotal} 返回)`);
  }
  for (const n of notes) console.log(`  ⚠ ${n}`);
  if (errors.length) {
    console.error(`❌ JSDoc 类型覆盖门禁：${errors.length} 处违规`);
    for (const e of errors) console.error(`   · ${e}`);
    return 1;
  }
  console.log('✅ JSDoc 类型覆盖门禁通过');
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

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'typecov-selftest-'));
  const write = (name, content) => {
    const p = path.join(dir, name);
    fs.writeFileSync(p, content, 'utf8');
    return p;
  };
  try {
    // ① 全标注函数 → 覆盖率 100%
    const fullSrc = '/**\n * @param {string} a\n * @param {number} b\n * @returns {boolean}\n */\nfunction full(a, b) { return a.length > b; }\n';
    write('full.js', fullSrc);
    t('① 全标注函数 → 覆盖率 100%', () => {
      const m = measureCoverage([dir]);
      const batch = m[dir];
      ok(batch, `未度量批次 ${dir}`);
      ok(batch.coverage === 100, `全标注应 100%，实际 ${batch.coverage}%`);
      ok(batch.untypedHotspots.length === 0, `不应有未标注热点，实际 ${batch.untypedHotspots.length}`);
    });

    // ② 无标注函数 → 覆盖率下降且热点列出
    const bareSrc = 'function bare(a, b) { return a + b; }\n';
    fs.writeFileSync(path.join(dir, 'bare.js'), bareSrc);
    t('② 无标注函数 → 覆盖率下降且热点列出', () => {
      const m = measureCoverage([dir]);
      const batch = m[dir];
      ok(batch.coverage < 100, `有未标注应 <100%，实际 ${batch.coverage}%`);
      ok(batch.untypedHotspots.length > 0, `应列出未标注热点，实际 ${batch.untypedHotspots.length}`);
    });

    // ③ 新增无标注参数 → 门禁按基线裁定失败
    t('③ 新增无标注参数 → 门禁裁定失败', () => {
      const r = judge(
        { 'x': { coverage: 50, paramsTotal: 4, paramsTyped: 2, returnsTotal: 1, returnsTyped: 1, untypedHotspots: ['a', 'b'] } },
        { batches: { 'x': { coverage: 60, untypedHotspots: ['a'] } } },
      );
      ok(r.errors.length >= 1, '覆盖率下降应报错');
      ok(/只升不降/.test(r.errors[0]), `错误信息应说明只升不降：${r.errors[0]}`);
    });

    // ④ 合规不报（防误伤）
    t('④ 合规不报（防误伤）', () => {
      const r = judge(
        { 'x': { coverage: 80, paramsTotal: 5, paramsTyped: 4, returnsTotal: 1, returnsTyped: 1, untypedHotspots: ['a'] } },
        { batches: { 'x': { coverage: 70, untypedHotspots: ['a', 'b'] } } },
      );
      ok(r.errors.length === 0, `覆盖率上升且热点缩小不应报错，实际：${r.errors.join('|')}`);
    });

    // ⑤ 批次集合不得缩小
    t('⑤ 批次集合不得缩小', () => {
      const r = judge(
        { 'x': { coverage: 100, paramsTotal: 0, paramsTyped: 0, returnsTotal: 0, returnsTyped: 0, untypedHotspots: [] } },
        { batches: { 'x': { coverage: 50, untypedHotspots: [] }, 'y': { coverage: 50, untypedHotspots: [] } } },
      );
      ok(r.errors.some((e) => e.includes('y') && e.includes('缩小')), `批次 y 缺失应报错，实际：${r.errors.join('|')}`);
    });

    console.log(failed ? `\n❌ selftest ${failed} 条失败` : '\n✅ selftest 全绿');
    process.exitCode = failed ? 1 : 0;
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* noop */ }
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const code = main();
  if (code !== undefined) process.exit(code);
}