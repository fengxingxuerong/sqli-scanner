#!/usr/bin/env node
// ============================================================================
// scripts/module-loadable.mjs —— 模块引用完整性门禁（静态，**不执行**被检代码）
//
// 为什么需要它（2026-09-29 实测事故，本仓最容易复发的形态）
// ----------------------------------------------------------------------------
// merge commit `684e4a3`（parents = cc5fd55 00ce269）把
// `server/src/services/scanLedger.js` 回退成了 `00ce269` 的旧版本：
//   · d44ff82（真功能提交，407 行）新增的 5 个函数定义整段丢失
//     （positiveInt / retentionPolicy / entryTs / pruneLedger / highestRisk）
//   · 但同文件里的**调用点与导出清单还在**：`:96 highestRisk(...)`、`:110 pruneLedger(...)`、
//     `:234 export default { ... pruneLedger, retentionPolicy, highestRisk }`
// 后果链：模块 import 期抛 ReferenceError → `scanRoutes.js:33` 具名 import 失败
//   （`SyntaxError: does not provide an export named 'highestRisk'`）→ `server/index.js`
//   起不来、`bin/cli.js` 全崩、186 条台账单测 fail。
//
// 2600+ 条测试**没有一条拦住它**：台账测试自己在模块顶层就崩（崩在 import，跑不到断言），
// 而 `scanRoutes` 从未被任何测试直接 import 过（它靠 `import { defaultScanManager }` 构成
// 环状依赖，顺手也避开了被发现）。
//
// 本门禁的关键设计：**只静态解析、绝不 import**。因此它在"代码已经坏到 import 就崩"
// 的状态下依然能跑完并指名道姓报错 —— 这正是它能在 merge 当时拦住这次事故的原因
// （若它也靠 import，就会和台账测试一样崩在同一个地方，等于没有）。
//
// 判据（两类，本质都是"引用了一个不存在的东西"）
// ----------------------------------------------------------------------------
//   ① 跨文件：`import { X } from './y.js'` 的 X 必须存在于 y.js 的导出集；
//      目标含 `export * from` 时无法静态判定 ⇒ 跳过（宁可漏报不误报）
//   ② 文件内：`export default { ... }` / `export { ... }` 里引用的标识符必须是本模块的
//      **绑定**（import 进来的、或本文件声明的）。本次事故的 3 个符号正是栽在这一条。
//
// 用法：
//   node scripts/module-loadable.mjs           # 检查（有违规 ⇒ 退出码 1）
//   node scripts/module-loadable.mjs --json    # 机器可读
//   node scripts/module-loadable.mjs --selftest # 自证判据不空转（喂合成样本，必须有反应）
// ============================================================================
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'acorn';

const ROOT = process.cwd();
const JSON_OUT = process.argv.includes('--json');
const SELFTEST = process.argv.includes('--selftest');
const SERVER = path.join(ROOT, 'server');

// 扫 server/ 下的 .js（Node 引擎本体）。前端是 .ts/.tsx，由 tsc 与 vitest 覆盖，
// 且前端没有"装配期整体崩掉"这一形态，故不入本门禁。
const SKIP_DIRS = new Set([
  'node_modules', 'data', 'logs', 'dist-engine', 'tests', '__fixtures__', 'tmpdiag', 'dist',
]);

function walkJs(dir, out = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const ent of entries) {
    const p = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (SKIP_DIRS.has(ent.name) || ent.name.startsWith('.')) continue;
      walkJs(p, out);
    } else if (ent.isFile() && ent.name.endsWith('.js')) {
      out.push(p);
    }
  }
  return out;
}

/** 解构模式 → 被绑定的标识符名列表（`const {a, b: c} = x` ⇒ [a, c]） */
function collectPattern(node, out) {
  if (!node) return;
  switch (node.type) {
    case 'Identifier': out.push(node.name); break;
    case 'ObjectPattern':
      for (const p of node.properties) {
        if (!p) continue;
        if (p.type === 'RestElement') collectPattern(p.argument, out);
        else collectPattern(p.value, out);
      }
      break;
    case 'ArrayPattern':
      for (const el of node.elements) collectPattern(el, out);
      break;
    case 'AssignmentPattern': collectPattern(node.left, out); break;
    case 'RestElement': collectPattern(node.argument, out); break;
    /* c8 ignore next */
    default: break;
  }
}

function declaredNames(decl) {
  if (!decl) return [];
  if (decl.type === 'FunctionDeclaration' || decl.type === 'ClassDeclaration') {
    return decl.id ? [decl.id.name] : [];
  }
  if (decl.type === 'VariableDeclaration') {
    const out = [];
    for (const d of decl.declarations) collectPattern(d.id, out);
    return out;
  }
  return [];
}

const specName = (n) => (n && (n.name ?? n.value)) || null;

/**
 * 解析单个模块，产出「导出集 / 导入清单 / 模块级绑定 / 导出处引用」。
 * 只处理 Program 顶层语句 —— 这正是 ESM 的语义（import/export 只能在顶层）。
 */
function analyzeSource(src, absPath) {
  const ast = parse(src, { ecmaVersion: 'latest', sourceType: 'module', allowHashBang: true });
  const exports = new Set();
  const starExport = [];
  const imports = [];
  const bindings = new Set();
  const exportRefs = [];
  const lineOf = (n) => (n && n.loc ? n.loc.start.line : 0);

  for (const node of ast.body) {
    switch (node.type) {
      case 'ImportDeclaration': {
        const names = [];
        for (const s of node.specifiers) {
          if (s.type === 'ImportSpecifier') {
            names.push({ imported: specName(s.imported), local: specName(s.local) });
            if (s.local) bindings.add(s.local.name); // 具名 import 同样是本模块的绑定
          } else if (s.local) {
            bindings.add(s.local.name); // default / namespace import：整体绑定
          }
        }
        imports.push({ source: node.source.value, names, line: lineOf(node) });
        break;
      }
      case 'ExportNamedDeclaration': {
        if (node.declaration) {
          for (const n of declaredNames(node.declaration)) {
            exports.add(n);
            bindings.add(n);
          }
        }
        for (const s of node.specifiers || []) {
          exports.add(specName(s.exported));
          // ⚠️ `export { x } from './y.js'` 是**再导出**：`s.local`（=x）指的是 y.js 里的名字，
          // 不是本模块的绑定 ⇒ 不能拿去和 bindings 比（否则每个再导出模块都误报）。
          // 只有无 source 的 `export { x }` 才引用本模块标识符。引用侧交给下面 source 分支的跨文件判据。
          if (s.local && !node.source) exportRefs.push({ name: specName(s.local), line: lineOf(s) });
        }
        if (node.source) {
          // `export { x } from './y.js'`：等价于 import + re-export，引用侧交给跨文件判据
          const names = (node.specifiers || []).map((s) => ({
            imported: specName(s.local) ?? specName(s.exported),
            local: specName(s.exported),
          }));
          imports.push({ source: node.source.value, names, line: lineOf(node) });
        }
        break;
      }
      case 'ExportDefaultDeclaration': {
        exports.add('default');
        const d = node.declaration;
        if (d?.type === 'Identifier') {
          exportRefs.push({ name: d.name, line: lineOf(d) });
        } else if (d?.type === 'ObjectExpression') {
          // `export default { a, b, c }` —— 简写与 `a: a` 两种都算"引用了 a"
          for (const prop of d.properties) {
            if (!prop || prop.type !== 'Property' || prop.computed) continue;
            const v = prop.value;
            if (v && v.type === 'Identifier') exportRefs.push({ name: v.name, line: lineOf(prop) });
          }
        }
        break;
      }
      case 'ExportAllDeclaration':
        starExport.push(node.source.value);
        break;
      case 'FunctionDeclaration':
      case 'ClassDeclaration':
        if (node.id) bindings.add(node.id.name);
        break;
      case 'VariableDeclaration':
        for (const n of declaredNames(node)) bindings.add(n);
        break;
      default:
        break;
    }
    // 顶层 `var` 也会进 bindings（上面 VariableDeclaration 已覆盖）
  }
  return { absPath, exports, starExport, imports, bindings, exportRefs };
}

// ============================================================================
// 判据执行
// ============================================================================
const KNOWN_EXT = new Set(['.js', '.mjs', '.cjs', '.json', '.node']);

/** 把 import 的 source 解析成绝对路径（仅本地相对/绝对路径；裸包名不判） */
function resolveImport(fromFile, source) {
  if (!source || typeof source !== 'string') return null;
  if (!source.startsWith('.') && !path.isAbsolute(source)) return null; // 裸包名/内置模块
  const base = path.resolve(path.dirname(fromFile), source);
  const candidates = [];
  if (path.extname(base) && KNOWN_EXT.has(path.extname(base))) {
    candidates.push(base);
  } else if (path.extname(base)) {
    candidates.push(base); // 显式写了别的扩展名，也照实检查
  } else {
    candidates.push(`${base}.js`, `${base}.mjs`, `${base}.cjs`, path.join(base, 'index.js'), base);
  }
  for (const c of candidates) {
    if (fs.existsSync(c) && fs.statSync(c).isFile()) return c;
  }
  return null;
}

function checkModule(mod, byFile) {
  const findings = [];
  const rel = path.relative(ROOT, mod.absPath).split(path.sep).join('/');

  // ①② 文件内：export default / export { } 引用的标识符必须存在
  for (const ref of mod.exportRefs) {
    if (!ref.name) continue;
    if (!mod.bindings.has(ref.name)) {
      findings.push({
        kind: 'export-ref-undefined',
        file: rel,
        line: ref.line,
        symbol: ref.name,
        message: `导出清单引用了未定义的标识符 '${ref.name}'（本模块既未声明也未 import）—— import 该模块会抛 ReferenceError`,
      });
    }
  }

  // ③ 跨文件：具名 import 必须在目标模块的导出集里
  for (const imp of mod.imports) {
    const target = resolveImport(mod.absPath, imp.source);
    if (!target || !imp.names.length) continue;
    const tmod = byFile.get(target);
    if (!tmod) continue; // 不在扫描范围内（如指向 server 外的文件）⇒ 交给 ref-integrity.mjs
    if (tmod.starExport.length) continue; // 有 `export *` ⇒ 静态不可判，跳过（宁漏不误）
    for (const { imported, local } of imp.names) {
      if (!imported) continue;
      if (!tmod.exports.has(imported)) {
        findings.push({
          kind: 'named-import-missing',
          file: rel,
          line: imp.line,
          symbol: imported,
          message: `从 '${imp.source}' 具名导入 '${imported}'${local && local !== imported ? `（本地名 ${local}）` : ''}，但目标模块未导出该名字`,
          target: path.relative(ROOT, target).split(path.sep).join('/'),
        });
      }
    }
  }
  return findings;
}

function analyzeAll() {
  const files = walkJs(SERVER);
  const mods = [];
  const parseErrors = [];
  for (const f of files) {
    let src;
    try {
      src = fs.readFileSync(f, 'utf-8');
    } catch {
      continue;
    }
    try {
      mods.push(analyzeSource(src, f));
    } catch (e) {
      parseErrors.push({ file: path.relative(ROOT, f).split(path.sep).join('/'), error: String(e?.message ?? e) });
    }
  }
  return { mods, parseErrors, fileCount: files.length };
}

function runCheck() {
  const { mods, parseErrors, fileCount } = analyzeAll();
  const byFile = new Map(mods.map((m) => [m.absPath, m]));
  const findings = [];
  for (const m of mods) findings.push(...checkModule(m, byFile));
  for (const pe of parseErrors) {
    findings.push({ kind: 'parse-error', file: pe.file, line: 0, message: `解析失败：${pe.error}` });
  }
  return { findings, fileCount, modCount: mods.length };
}

// ============================================================================
// 自证：喂一对合成样本，判据必须真的有反应（防"判据空转"）
// ============================================================================
function selfTest() {
  const cases = [
    {
      name: 'export default 引用未定义标识符（本次事故形态）',
      files: { 'a.js': 'export function keep() {}\nexport default { keep, ghostFn };\n' },
      expect: 'export-ref-undefined',
    },
    {
      name: '具名 import 目标未导出（scanRoutes 形态）',
      files: {
        'a.js': 'export function present() {}\n',
        'b.js': "import { present, absent } from './a.js';\nexport const x = present || absent;\n",
      },
      expect: 'named-import-missing',
    },
    {
      name: 'export { } 引用未定义',
      files: { 'a.js': 'const ok = 1;\nexport { ok, nope };\n' },
      expect: 'export-ref-undefined',
      // acorn 自身就会以 SyntaxError 拒绝 `export { nope }`（报 "Export 'nope' is not defined"）——
      // 对本门禁而言这同样是"被抓到"，只是抓在解析阶段。两种结果都算通过。
      acceptParseError: true,
    },
    {
      name: '再导出（export { x } from）不得误报为未定义',
      files: {
        'a.js': 'export function real() {}\n',
        'b.js': "export { real, real as alias } from './a.js';\n",
      },
      expect: null,
    },
    {
      name: '对照：完全合法，必须零违规',
      files: {
        'a.js': 'export function f() {}\nexport const g = 1;\n',
        'b.js': "import { f, g } from './a.js';\nexport default { f, g };\n",
      },
      expect: null,
    },
  ];

  let ok = true;
  for (const c of cases) {
    // 用内存文件系统跑判据（不落盘）
    const mods = [];
    let parseFailed = null;
    for (const [name, src] of Object.entries(c.files)) {
      const abs = path.join(ROOT, '__selftest__', name);
      try {
        mods.push(analyzeSource(src, abs));
      } catch (e) {
        // acorn 对 `export { 未定义 }` 会直接抛 SyntaxError —— 也算"被抓到"
        parseFailed = String(e?.message ?? e);
      }
    }
    if (parseFailed && c.acceptParseError) {
      console.log(`  ✅ ${c.name}（期望被抓到）→ 捕获于解析阶段：${parseFailed.slice(0, 60)}`);
      continue;
    }
    if (parseFailed) {
      ok = false;
      console.log(`  ❌ ${c.name} → 解析阶段意外失败：${parseFailed.slice(0, 80)}`);
      continue;
    }
    const byFile = new Map(mods.map((m) => [m.absPath, m]));
    // 让 resolveImport 能命中内存里的"文件"
    const realExists = fs.existsSync;
    const realStat = fs.statSync;
    fs.existsSync = (p) => (byFile.has(path.resolve(p)) ? true : realExists(p));
    fs.statSync = (p) => (byFile.has(path.resolve(p)) ? { isFile: () => true, isDirectory: () => false } : realStat(p));
    let found;
    try {
      found = mods.flatMap((m) => checkModule(m, byFile)).map((f) => f.kind);
    } finally {
      fs.existsSync = realExists;
      fs.statSync = realStat;
    }
    const hit = c.expect === null ? found.length === 0 : found.includes(c.expect);
    if (!hit) ok = false;
    console.log(`  ${hit ? '✅' : '❌'} ${c.name}${c.expect === null ? '（期望 0 违规）' : `（期望命中 ${c.expect}）`}${found.length ? ` → 实际 [${[...new Set(found)].join(', ')}]` : ''}`);
  }
  return ok;
}

// ── 入口 ────────────────────────────────────────────────────────────────────
// 只有被直接执行时才跑检查；被 scripts/merge-integrity.mjs import 时只取分析函数
// （判据单一来源，不手抄第二份 —— 本仓反复吃过"同一判据多份实现"的亏）。
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);

export { walkJs, analyzeSource, checkModule, runCheck, analyzeAll, resolveImport, selfTest };

if (!isMain) {
  // 被 import（merge-integrity.mjs 复用判据）时到此为止：不执行检查、不 exit
  // —— 顶层 `process.exit` 一旦在 import 路径执行，会把调用者一起干掉。
} else if (SELFTEST) {
  console.log('module-loadable 自证：');
  const ok = selfTest();
  console.log(ok ? '\n✅ 自证通过：判据在两类形态上都有反应，且对合法样本零误报' : '\n❌ 自证失败：判据空转或误报');
  process.exit(ok ? 0 : 1);
} else {
  const { findings, fileCount, modCount } = runCheck();

  if (JSON_OUT) {
    console.log(JSON.stringify({ fileCount, modCount, findings }, null, 2));
  } else if (!findings.length) {
    console.log(`✅ 模块引用完整性通过（扫描 ${fileCount} 个 server/*.js，静态解析 ${modCount} 个模块，0 违规）`);
  } else {
    console.error(`❌ 模块引用完整性失败：${findings.length} 处违规（扫描 ${fileCount} 个文件）\n`);
    for (const f of findings) {
      console.error(`  [${f.kind}] ${f.file}${f.line ? `:${f.line}` : ''} — ${f.message}`);
    }
    console.error('\n提示：这类缺陷会让「import 该模块」直接抛错，表现为引擎/CLI 整体起不来，');
    console.error('而 node --test 会崩在 import 阶段（跑不到任何断言），因此必须由本静态门禁拦截。');
  }

  process.exit(findings.length ? 1 : 0);
}

