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
// [D245] 引用收集面必须含 `server`（递归），否则 server/index.js 这类根入口的 import 看不见。
// 实测：`server/index.js` 里 `import { reportAiRoutes }` 漏扫 ⇒ 判成死代码 ⇒ 删 export 后
// 服务起不来（`does not provide an export named`）。collect 已跳过 node_modules 等目录。
const SCAN_DIRS = ['server', 'src', 'scripts', 'e2e'];
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

// ── 动态 import 目标收集（[D245] 静态分析的最大盲区）────────────────────────
//
// 为什么必须做：本仓 e2e 大量用
//   `const { createOobLabApp } = await import(pathToFileURL(resolve(ROOT, 'e2e/x/lab-app.mjs')).href)`
// 这类**运行时拼装路径**的动态导入。静态正则只认 `import ... from '...'`，于是这些符号
// 全被判成「未使用导出」，164 条基线里混着 25 个这样的**活代码**（2026-11-02 实测：
// 按旧判据删 export 会直接打断 e2e 运行）。
//
// 判据取向：**宁少报不误伤**。路径片段能提取出来 ⇒ 该文件整份豁免（无法知道解构了谁）；
// 提取不出 ⇒ 不豁免（会以「未使用」报出，属已知漏报，不在本门禁兜底）。
//
// @param {string} callerFile 调用点所在文件（项目相对路径）
// @param {string} src 文件源码
// @returns {Set<string>} 被动态 import 的目标文件（项目相对路径）
/**
 * 把 import/export 说明符归一化为项目相对路径（posix 分隔）。
 * @param {string} callerFile 调用点文件（项目相对路径）
 * @param {string} spec 说明符（'./x.js' / '../a/b.js' / 'pkg/sub/x.js' / 绝对路径）
 * @returns {string|null} 项目内相对路径；解析不到或越出项目根则 null
 */
function toProjectRelative(callerFile, spec) {
  if (!/\.(mjs|js|ts|tsx)$/.test(spec)) return null;
  let abs;
  if (spec.startsWith('./') || spec.startsWith('../')) {
    abs = path.resolve(path.dirname(path.join(ROOT, callerFile)), spec);
  } else if (path.isAbsolute(spec)) {
    abs = spec;
  } else {
    abs = path.join(ROOT, spec);
  }
  const rel = path.relative(ROOT, abs).split(path.sep).join('/');
  return rel.startsWith('..') ? null : rel;
}

/**
 * 收集文件内的字符串常量（用于折叠动态 import 里的 `${VAR}`）。
 *
 * 为什么需要：本仓有
 *   `const VERDICT_REL = 'e2e/waf-real/pwnVerdict.mjs'; ... await import(new URL(`../../${VERDICT_REL}`, import.meta.url))`
 * 这种「模板串 + 同文件常量」的形态。不做折叠就提取不到路径，被导入的文件不豁免 ⇒
 * `EXFIL_MARK` 之类被属性访问的符号被判死（2026-11-02 实测：modsecLive.wiring ⑮ 报
 * `Cannot read properties of undefined`）。
 * @param {string} src 文件源码
 * @returns {Map<string,string>} 常量名 → 值
 */
function localStringConstants(src) {
  const out = new Map();
  for (const m of src.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*['"`]([^'"`\n]+)['"`]/g)) {
    out.set(m[1], m[2]);
  }
  return out;
}

/**
 * 收集动态 import 的目标文件。
 * @param {string} callerFile 调用点文件（项目相对路径）
 * @param {string} src 文件源码
 * @returns {Set<string>} 目标文件（项目相对路径）
 */
function collectDynamicImportFiles(callerFile, src) {
  const out = new Set();
  const consts = localStringConstants(src);
  // 不匹配闭合括号：参数里常有 `resolve(ROOT, 'x.js')` 嵌套括号
  for (const m of src.matchAll(/\bimport\s*\(/g)) {
    const window = src
      .slice(m.index + m[0].length, m.index + m[0].length + 400)
      .replace(/\$\{([A-Za-z_$][\w$]*)\}/g, (whole, name) => consts.get(name) ?? whole);
    const lit = window.match(/['"`]([^'"`]*?\.(?:mjs|js|ts|tsx))['"`]/);
    if (!lit) continue;
    const rel = toProjectRelative(callerFile, lit[1]);
    if (rel) out.add(rel);
  }
  return out;
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
  // [D245] 再导出 `export { A, B } from './x.js'` 同样是「消费」。
  // 旧判据只认 import，于是 bar 文件把 foo 的符号转发出去时，foo 里的实现被判成死代码；
  // 一旦按误判删掉 foo 的 export，转发处立即 `does not provide an export named` 断链
  // （2026-11-02 实测：298 个服务端测试文件同时红）。
  for (const m of src.matchAll(/export\s*\{([^}]+)\}\s*from\s*['"`]([^'"`]+)['"`]/g)) {
    for (const part of m[1].split(',')) {
      const n = part.trim().split(/\s+as\s+/)[0].trim();
      if (n) refs.add(n);
    }
  }
  // `export * from './x.js'`：转发的是谁静态不可知 ⇒ 目标文件整份豁免
  const dynamicFiles = collectDynamicImportFiles(filePath, src);
  for (const m of src.matchAll(/export\s*\*\s*from\s*['"`]([^'"`]+)['"`]/g)) {
    const rel = toProjectRelative(filePath, m[1]);
    if (rel) dynamicFiles.add(rel);
  }
  // Same-file usage: function/const used but not exported (covers re-exports)
  return { refs, nsImports, dynFiles: dynamicFiles };
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
 * 收集所有导出声明。
 * @param {string[]} exportDirs 导出符号收集目录
 * @returns {Array<{file:string,name:string,kind:string,line:number}>}
 */
function collectAllExports(exportDirs) {
  const resolve = (f) => (path.isAbsolute(f) ? f : path.join(ROOT, f));
  const all = [];
  for (const d of exportDirs) {
    for (const f of collect(d, EXT, [])) {
      let src;
      try { src = fs.readFileSync(resolve(f), 'utf8'); } catch { continue; }
      all.push(...extractExports(f, src));
    }
  }
  return all;
}

/**
 * 收集所有引用（具名 / 命名空间 / 动态 import 目标）。
 *
 * [D245] `dynTargets` 是被动态 `import()` 的文件集合：那些文件的导出整份豁免。
 * 抽成独立函数的另一个原因：加完这层逻辑后 findUnusedExports 超出复杂度基线，
 * 按本仓纪律「优先抽方法，不上调基线」。
 * @param {string[]} scanDirs 引用收集目录
 * @returns {{allRefs:Set<string>,nsModules:Set<string>,dynTargets:Set<string>}}
 */
function collectAllReferences(scanDirs) {
  const resolve = (f) => (path.isAbsolute(f) ? f : path.join(ROOT, f));
  const allRefs = new Set();
  const nsModules = new Set();
  const dynTargets = new Set();
  for (const d of scanDirs) {
    for (const f of collect(d, EXT, [])) {
      let src;
      try { src = fs.readFileSync(resolve(f), 'utf8'); } catch { continue; }
      const { refs, nsImports, dynFiles } = extractReferences(f, src);
      for (const r of refs) allRefs.add(r);
      for (const ns of nsImports) nsModules.add(ns);
      for (const t of dynFiles) dynTargets.add(t);
    }
  }
  return { allRefs, nsModules, dynTargets };
}

/**
 * 查找未使用的导出符号。
 * @param {string[]} exportDirs - 导出符号收集目录
 * @param {string[]} scanDirs - 引用收集目录
 * @returns {Array<{file:string,name:string,kind:string,line:number,reason?:string}>}
 */
function findUnusedExports(exportDirs, scanDirs) {
  const allExports = collectAllExports(exportDirs);
  const { allRefs, nsModules, dynTargets } = collectAllReferences(scanDirs);
  // Judge: export not in refs → suspected dead code
  const unused = [];
  for (const exp of allExports) {
    if (exp.name === 'default') continue; // default exports hard to track statically
    if (allRefs.has(exp.name)) continue;
    // [D245] 动态 import 的目标文件无法静态知道解构了谁 ⇒ 整份豁免（宁少报不误伤）
    if (dynTargets.has(exp.file)) continue;

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
function judge(unused, baseline) {
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

    // ⑥⑦ [D245] 动态 import 目标整份豁免（旧判据把它当死代码，实测会打断 e2e）
    write('dynTarget.mjs', 'export function dynFn() { return 1; }\n');
    write('dynCaller.mjs', 'const { dynFn } = await import("./dynTarget.mjs");\nvoid dynFn;\n');
    write('dynTarget2.mjs', 'export function dynFn2() { return 1; }\n');
    write('dynCaller2.mjs', 'const m2 = await import(new URL("./dynTarget2.mjs", import.meta.url).href);\nvoid m2;\n');
    t('⑥ 相对路径动态 import 的目标不误报', () => {
      const names = findUnusedExports([dir], [dir]).map((u) => u.name);
      ok(!names.includes('dynFn'), `dynFn 被 await import 消费，不应报出；实际 ${JSON.stringify(names)}`);
    });
    t('⑦ new URL(...) 拼装的动态 import 目标不误报', () => {
      const names = findUnusedExports([dir], [dir]).map((u) => u.name);
      ok(!names.includes('dynFn2'), `dynFn2 被动态 import 消费，不应报出；实际 ${JSON.stringify(names)}`);
    });

    // ⑧ [D245] 再导出 `export { X } from './mod.js'` 视为消费（否则删 X 的 export 即断链）
    write('reSrc.js', 'export function reExportedFn() { return 1; }\n');
    write('reBar.js', 'export { reExportedFn } from "./reSrc.js";\n');
    t('⑧ 再导出视为消费，不断链', () => {
      const names = findUnusedExports([dir], [dir]).map((u) => u.name);
      ok(!names.includes('reExportedFn'), `被再导出的符号不应报死代码；实际 ${JSON.stringify(names)}`);
    });

    // ⑨ [D245] 模板串 + 同文件常量的动态 import（`new URL(`./${REL}`, ...)`）
    write('dynRel.mjs', 'export const DYN_KEY = 1;\n');
    write('dynCaller3.mjs', 'const REL = "dynRel.mjs";\nconst m3 = await import(new URL(`./${REL}`, import.meta.url));\nvoid m3;\n');
    t('⑨ 模板串 + 同文件常量的动态 import 目标不误报', () => {
      const names = findUnusedExports([dir], [dir]).map((u) => u.name);
      ok(!names.includes('DYN_KEY'), `DYN_KEY 被动态 import 消费，不应报出；实际 ${JSON.stringify(names)}`);
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