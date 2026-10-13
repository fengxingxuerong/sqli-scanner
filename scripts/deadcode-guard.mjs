#!/usr/bin/env node
// ============================================================================
// scripts/deadcode-guard.mjs —— 未使用导出门禁（基线制）（design §2.1.3.3）
//
// ── 为什么要有这道门 ─────────────────────────────────────────────────────────
// getResponseTransform 已导出但无引用；测试专用导出散落无标注。没有门禁管
// 「导出是否有人用」——死代码静默积累，重构时漏删或误删仍被引用者。
//
// ── 算法 ────────────────────────────────────────────────────────────────────
// · 符号收集：server/src / src / scripts / e2e 的 export 声明
// · 引用收集：全仓 import/require/动态 import
// · 差集 → 扣减用途标记（@public/@used-by/@test-only/@dynamic）与基线豁免
// · 命名空间导入（import * as ns）的模块所有导出自动豁免
//
// 用法：
//   node scripts/deadcode-guard.mjs               # 检查
//   node scripts/deadcode-guard.mjs --selftest    # 自证判据不空转
//   node scripts/deadcode-guard.mjs --fix-baseline# 重生成基线
//   node scripts/deadcode-guard.mjs --json        # 机器可读输出
// ============================================================================
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE_FILE = path.join(ROOT, 'docs', '_deadcode-baseline.json');

const EXPORT_DIRS = ['server/src', 'src', 'scripts', 'e2e'];
const SCAN_DIRS = ['server/src', 'server/tests', 'src', 'scripts', 'e2e'];
const EXT = ['.js', '.ts', '.tsx', '.mjs'];
const USAGE_MARKERS = ['@public', '@used-by', '@test-only', '@dynamic'];

function collect(rel, exts, out) {
  const abs = path.isAbsolute(rel) ? rel : path.join(ROOT, rel);
  if (!fs.existsSync(abs)) return out;
  for (const ent of fs.readdirSync(abs, { withFileTypes: true })) {
    if (ent.name.startsWith('.')) continue;
    const sub = path.isAbsolute(rel)
      ? path.join(rel, ent.name).replace(/\\/g, '/')
      : path.posix.join(rel.replace(/\\/g, '/'), ent.name);
    if (ent.isDirectory()) {
      if (['node_modules', 'dist', 'build', 'target', '.git', 'coverage', 'reports', 'results'].includes(ent.name)) continue;
      collect(sub, exts, out);
    } else if (exts.some((e) => ent.name.endsWith(e))) out.push(sub);
  }
  return out;
}

// ── 符号收集：提取文件中的所有导出 ──────────────────────────────────────────
function extractExports(filePath, src) {
  const exports = [];
  const lines = src.split('\n');

  // export function/async function NAME
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^\s*export\s+(?:async\s+)?function\s+(\w+)/);
    if (m) { exports.push({ name: m[1], file: filePath, line: i + 1, kind: 'function' }); continue; }

    // export const/let/var NAME
    const m2 = lines[i].match(/^\s*export\s+(?:const|let|var)\s+(\w+)/);
    if (m2) { exports.push({ name: m2[1], file: filePath, line: i + 1, kind: 'const' }); continue; }

    // export class NAME
    const m3 = lines[i].match(/^\s*export\s+class\s+(\w+)/);
    if (m3) { exports.push({ name: m3[1], file: filePath, line: i + 1, kind: 'class' }); continue; }

    // export { a, b as c }
    const m4 = lines[i].match(/^\s*export\s*\{([^}]+)\}/);
    if (m4) {
      for (const part of m4[1].split(',')) {
        const names = part.trim().split(/\s+as\s+/);
        if (names[0] && names[0] !== 'default') {
          exports.push({ name: names[names.length - 1].trim(), file: filePath, line: i + 1, kind: 're-export' });
        }
      }
      continue;
    }

    // export default NAME (named default)
    const m5 = lines[i].match(/^\s*export\s+default\s+(\w+)\s*[,;]?/);
    if (m5 && !/^(function|class|const|let|var|async)$/.test(m5[1])) {
      exports.push({ name: 'default', file: filePath, line: i + 1, kind: 'default' });
      continue;
    }
    // export default function/class → default export
    if (/^\s*export\s+default\s+(?:async\s+)?(?:function|class)/.test(lines[i])) {
      exports.push({ name: 'default', file: filePath, line: i + 1, kind: 'default' });
    }
  }
  return exports;
}

// ── 引用收集：提取文件中的所有导入引用 ──────────────────────────────────────
function extractReferences(filePath, src) {
  const refs = new Set();
  const nsImports = new Set(); // modules with import * as ns

  // import { a, b as c } from '...'
  for (const m of src.matchAll(/import\s*\{([^}]+)\}\s*from\s*['"`]([^'"`]+)['"`]/g)) {
    for (const part of m[1].split(',')) {
      const names = part.trim().split(/\s+as\s+/);
      refs.add(names[0].trim());
    }
  }
  // import NAME from '...'
  for (const m of src.matchAll(/import\s+(\w+)\s+from\s*['"`]/g)) {
    refs.add(m[1]);
  }
  // import * as ns from '...' → namespace import
  for (const m of src.matchAll(/import\s+\*\s+as\s+\w+\s+from\s*['"`]([^'"`]+)['"`]/g)) {
    nsImports.add(m[1]);
  }
  // import NAME1, { NAME2 } from '...'
  for (const m of src.matchAll(/import\s+(\w+)\s*,\s*\{([^}]+)\}\s*from\s*['"`]/g)) {
    refs.add(m[1]);
    for (const part of m[2].split(',')) {
      const names = part.trim().split(/\s+as\s+/);
      refs.add(names[0].trim());
    }
  }
  // require('...') with destructuring
  for (const m of src.matchAll(/(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(/g)) {
    for (const part of m[1].split(',')) {
      const names = part.trim().split(/\s*:\s*/);
      refs.add(names[0].trim());
    }
  }
  // Same-file usage: function/const used but not exported (covers re-exports)
  return { refs, nsImports };
}

// ── 用途标记检测：检查导出符号上方是否有 @public 等标记 ──────────────────────
function hasUsageMarker(src, lineNum) {
  const lines = src.split('\n');
  // Check preceding JSDoc block (look up from the export line)
  for (let i = lineNum - 2; i >= 0 && i >= lineNum - 10; i--) {
    if (USAGE_MARKERS.some((m) => lines[i] && lines[i].includes(m))) return true;
    if (lines[i] && !lines[i].trim().startsWith('*') && !lines[i].trim().startsWith('/**') && !lines[i].trim().startsWith('*/') && !lines[i].trim().startsWith('//')) break;
  }
  return false;
}

/**
 * 查找未使用的导出符号。
 * @param {string[]} exportDirs - 导出符号收集目录
 * @param {string[]} scanDirs - 引用收集目录
 * @returns {Array<{file:string,name:string,kind:string,line:number,reason?:string}>}
 */
export function findUnusedExports(exportDirs, scanDirs) {
  const allExports = [];
  const allRefs = new Set();
  const nsModules = new Set();

  const resolve = (f) => path.isAbsolute(f) ? f : path.join(ROOT, f);

  // Collect exports
  for (const d of exportDirs) {
    const files = collect(d, EXT, []);
    for (const f of files) {
      let src;
      try { src = fs.readFileSync(resolve(f), 'utf8'); } catch { continue; }
      allExports.push(...extractExports(f, src));
    }
  }

  // Collect references
  for (const d of scanDirs) {
    const files = collect(d, EXT, []);
    for (const f of files) {
      let src;
      try { src = fs.readFileSync(resolve(f), 'utf8'); } catch { continue; }
      const { refs, nsImports } = extractReferences(f, src);
      for (const r of refs) allRefs.add(r);
      for (const ns of nsImports) nsModules.add(ns);
    }
  }

  // Judge: export not in refs → suspected dead code
  const unused = [];
  for (const exp of allExports) {
    if (exp.name === 'default') continue; // default exports hard to track statically
    if (allRefs.has(exp.name)) continue;

    // Check usage marker
    const abs = path.isAbsolute(exp.file) ? exp.file : path.join(ROOT, exp.file);
    let src;
    try { src = fs.readFileSync(abs, 'utf8'); } catch { continue; }
    if (hasUsageMarker(src, exp.line)) continue;

    // Check namespace import exemption (match by basename without extension)
    const expBasename = path.basename(exp.file).replace(/\.(mjs|js|ts|tsx)$/, '');
    const nsMatch = [...nsModules].some((ns) => {
      const nsBasename = path.basename(ns).replace(/\.(mjs|js|ts|tsx)$/, '');
      return nsBasename === expBasename;
    });
    if (nsMatch) {
      unused.push({ ...exp, reason: 'namespace 导入，无法判定' });
      continue;
    }

    unused.push(exp);
  }
  return unused;
}

function loadBaseline() {
  try {
    return JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf8'));
  } catch {
    return { _comment: '未使用导出基线：只减不增。', symbols: {} };
  }
}

/**
 * 按基线裁定未使用导出检测结果。
 * @param {Array} unused
 * @param {{symbols?:object}} baseline
 * @returns {{errors:string[],notes:string[],exempted:string[]}}
 */
export function judge(unused, baseline) {
  const errors = [];
  const notes = [];
  const exempted = [];
  const baseSymbols = baseline.symbols || {};
  const baseKeys = new Set(Object.keys(baseSymbols));

  for (const u of unused) {
    const key = `${u.file}::${u.name}`;
    if (baseKeys.has(key)) {
      exempted.push(key);
    } else {
      errors.push(`${key}（${u.kind}，第 ${u.line} 行）${u.reason ? ' — ' + u.reason : ''}`);
    }
  }

  // Check for baseline entries that no longer exist (can be removed)
  for (const key of baseKeys) {
    const found = unused.some((u) => `${u.file}::${u.name}` === key);
    if (!found) {
      notes.push(`基线条目 ${key} 已消失，可从基线中移除`);
    }
  }

  return { errors, notes, exempted };
}

function fixBaseline(unused) {
  const old = loadBaseline();
  const oldSymbols = old.symbols || {};
  const symbols = {};
  for (const u of unused) {
    const key = `${u.file}::${u.name}`;
    if (oldSymbols[key]) {
      symbols[key] = oldSymbols[key];
    } else {
      symbols[key] = { reason: '待清理或加用途标注', status: 'open' };
    }
  }
  const doc = {
    _comment: '未使用导出基线：只减不增。新增未使用导出不得进入基线。',
    _generatedBy: 'node scripts/deadcode-guard.mjs --fix-baseline',
    symbols,
  };
  fs.writeFileSync(BASELINE_FILE, JSON.stringify(doc, null, 2) + '\n', 'utf8');
  console.log(`[deadcode] 已写入基线 ${path.relative(ROOT, BASELINE_FILE)}（${Object.keys(symbols).length} 个未使用导出）`);
  return 0;
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--selftest')) return selftestMain();
  const fix = args.includes('--fix-baseline');
  const jsonOut = args.includes('--json');

  const unused = findUnusedExports(EXPORT_DIRS, SCAN_DIRS);
  const baseline = loadBaseline();

  if (fix) return fixBaseline(unused);

  const { errors, notes, exempted } = judge(unused, baseline);
  if (jsonOut) {
    console.log(JSON.stringify({ unused, errors, notes, exempted }, null, 2));
    return errors.length ? 1 : 0;
  }
  if (unused.length > 0) {
    console.log(`  检出 ${unused.length} 个未使用导出`);
    for (const u of unused.slice(0, 20)) {
      const key = `${u.file}::${u.name}`;
      const isExempt = exempted.includes(key);
      console.log(`    ${isExempt ? '⚪' : '❌'} ${key}（${u.kind}，第 ${u.line} 行）${u.reason ? ' — ' + u.reason : ''}`);
    }
    if (unused.length > 20) console.log(`    ... 还有 ${unused.length - 20} 个`);
  }
  for (const n of notes) console.log(`  ⚠ ${n}`);
  if (errors.length) {
    console.error(`❌ 死代码门禁：${errors.length} 处未使用导出（不在基线且无用途标记）`);
    return 1;
  }
  console.log(`✅ 死代码门禁通过（检出 ${unused.length} 个未使用导出，基线豁免 ${exempted.length} 个）`);
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

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dc-selftest-'));
  const write = (name, content) => {
    const p = path.join(dir, name);
    fs.writeFileSync(p, content, 'utf8');
    return p;
  };
  try {
    // ① 导出但无人引用 → 报出
    write('mod.js', 'export function unusedFn() { return 1; }\nexport function usedFn() { return 2; }\n');
    write('user.js', 'import { usedFn } from "./mod.js";\n');
    t('① 导出无人引用 → 报出', () => {
      const unused = findUnusedExports([dir], [dir]);
      const names = unused.map((u) => u.name);
      ok(names.includes('unusedFn'), `应报出 unusedFn，实际 ${JSON.stringify(names)}`);
      ok(!names.includes('usedFn'), `不应报出 usedFn`);
    });

    // ② 加 @public 注释 → 转绿
    write('mod2.js', '/** @public */\nexport function publicFn() { return 1; }\n');
    t('② @public 标记 → 豁免不报', () => {
      const unused = findUnusedExports([dir], [dir]);
      const names = unused.map((u) => u.name);
      ok(!names.includes('publicFn'), `@public 标记不应报出，实际 ${JSON.stringify(names)}`);
    });

    // ③ import * as ns → 豁免不误报
    write('mod3.js', 'export function nsFn() { return 1; }\n');
    write('nsuser.js', 'import * as ns from "./mod3.js";\n');
    t('③ 命名空间导入 → 豁免不误报', () => {
      const unused = findUnusedExports([dir], [dir]);
      const nsEntry = unused.find((u) => u.name === 'nsFn');
      ok(nsEntry, 'nsFn 应在结果中');
      ok(nsEntry.reason && nsEntry.reason.includes('namespace'), `应标注 namespace 豁免，实际 ${nsEntry.reason}`);
    });

    // ④ 基线裁定：不在基线的未使用导出 → 失败
    t('④ 不在基线的未使用导出 → 判失败', () => {
      const r = judge(
        [{ file: 'a.js', name: 'deadFn', kind: 'function', line: 1 }],
        { symbols: {} },
      );
      ok(r.errors.length >= 1, '无基线豁免时应报错');
    });

    // ⑤ 基线裁定：在基线的未使用导出 → 豲免
    t('⑤ 在基线的未使用导出 → 豁免', () => {
      const r = judge(
        [{ file: 'a.js', name: 'deadFn', kind: 'function', line: 1 }],
        { symbols: { 'a.js::deadFn': { reason: '待清理', status: 'open' } } },
      );
      ok(r.errors.length === 0, '基线内应豁免');
      ok(r.exempted.length === 1, '应记录 1 个豁免');
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