#!/usr/bin/env node
// ============================================================================
// scripts/error-contract-guard.mjs —— 错误形态一致性门禁（design §2.1.3.5）
//
// ── 为什么要有这道门 ─────────────────────────────────────────────────────────
// server/src/api/** 与 server/src/services/** 是对外契约层：裸 Error 不携带
// ErrorCode，路由层无法映射响应码、消费方无法区分「参数错」与「目标不可达」。
// AppError(code, message) 是统一形态。非受限目录允许裸 Error 但只减不增。
//
// ── 管法 ────────────────────────────────────────────────────────────────────
// · 受限目录（api/services）：裸 `throw new Error(...)` → 失败（必须 0）
// · 非受限目录：按文件计数裸 Error，与基线比对、只减不增
// · AppError / 自定义 Error 子类 → 通过
//
// 用法：
//   node scripts/error-contract-guard.mjs               # 检查
//   node scripts/error-contract-guard.mjs --selftest    # 自证判据不空转
//   node scripts/error-contract-guard.mjs --fix-baseline# 重生成基线
//   node scripts/error-contract-guard.mjs --json        # 机器可读输出
// ============================================================================
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE_FILE = path.join(ROOT, 'docs', '_errorstyle-baseline.json');

const RESTRICTED_DIRS = ['server/src/api', 'server/src/services'];
const SCAN_DIR = 'server/src';
const EXT = ['.js', '.ts', '.mjs'];

const BARE_ERROR_RE = /throw\s+new\s+Error\s*\(/g;

function collectFiles(rel, out) {
  const abs = path.isAbsolute(rel) ? rel : path.join(ROOT, rel);
  if (!fs.existsSync(abs)) return out;
  for (const ent of fs.readdirSync(abs, { withFileTypes: true })) {
    if (ent.name.startsWith('.') || ent.name === 'node_modules' || ent.name === 'dist') continue;
    const sub = path.isAbsolute(rel)
      ? path.join(rel, ent.name).replace(/\\/g, '/')
      : path.posix.join(rel.replace(/\\/g, '/'), ent.name);
    if (ent.isDirectory()) collectFiles(sub, out);
    else if (EXT.some((e) => ent.name.endsWith(e))) out.push(sub);
  }
  return out;
}

function isRestricted(file, restrictedDirs) {
  return restrictedDirs.some((d) => {
    const norm = d.replace(/\\/g, '/');
    return file.startsWith(norm + '/') || file === norm;
  });
}

/**
 * 查找不一致的错误抛出。
 * @param {string} scanDir - 扫描根目录（相对 ROOT）
 * @param {string[]} restrictedDirs - 受限目录列表（裸 Error 必须为 0）
 * @returns {{restricted:Array,nonRestrictedByFile:Record<string,number>}}
 */
export function findInconsistentThrows(scanDir, restrictedDirs) {
  const files = collectFiles(scanDir, []);
  const restricted = [];
  const nonRestrictedByFile = {};

  for (const f of files) {
    const abs = path.isAbsolute(f) ? f : path.join(ROOT, f);
    let src;
    try { src = fs.readFileSync(abs, 'utf8'); } catch { continue; }

    const lines = src.split('\n');
    let count = 0;
    for (let i = 0; i < lines.length; i++) {
      BARE_ERROR_RE.lastIndex = 0;
      if (BARE_ERROR_RE.test(lines[i])) {
        count++;
        if (isRestricted(f, restrictedDirs)) {
          restricted.push({ file: f, line: i + 1 });
        }
      }
    }
    if (count > 0 && !isRestricted(f, restrictedDirs)) {
      nonRestrictedByFile[f] = count;
    }
  }
  return { restricted, nonRestrictedByFile };
}

function loadBaseline() {
  try {
    return JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf8'));
  } catch {
    return { _comment: '错误形态基线：受限目录裸 Error 必须为 0；非受限只减不增。', bareErrorByFile: {} };
  }
}

/**
 * 按基线裁定错误形态检测结果。
 * @param {{restricted:Array,nonRestrictedByFile:Record<string,number>}} found
 * @param {{bareErrorByFile?:Record<string,number>}} baseline
 * @returns {{errors:string[],notes:string[]}}
 */
export function judge(found, baseline) {
  const errors = [];
  const notes = [];
  const baseByFile = baseline.bareErrorByFile || {};

  // Restricted: must be 0
  if (found.restricted.length > 0) {
    for (const r of found.restricted) {
      errors.push(`受限目录裸 Error：${r.file}:${r.line}`);
    }
  }

  // Non-restricted: only decrease
  for (const [file, count] of Object.entries(found.nonRestrictedByFile)) {
    const base = baseByFile[file] || 0;
    if (count > base) {
      errors.push(`非受限目录裸 Error 增长：${file} 基线 ${base} → 现测 ${count}`);
    }
  }

  // Check for baseline entries that no longer exist or decreased
  for (const [file, base] of Object.entries(baseByFile)) {
    const current = found.nonRestrictedByFile[file] || 0;
    if (current === 0 && base > 0) {
      notes.push(`基线条目 ${file} 已归零，可从基线中移除`);
    } else if (current < base) {
      notes.push(`基线条目 ${file} 已下降 ${base} → ${current}，可下调基线`);
    }
  }

  return { errors, notes };
}

function fixBaseline(found) {
  const doc = {
    _comment: '错误形态基线：受限目录裸 Error 必须为 0；非受限只减不增。',
    _generatedBy: 'node scripts/error-contract-guard.mjs --fix-baseline',
    bareErrorByFile: found.nonRestrictedByFile,
  };
  fs.writeFileSync(BASELINE_FILE, JSON.stringify(doc, null, 2) + '\n', 'utf8');
  const total = Object.values(found.nonRestrictedByFile).reduce((a, b) => a + b, 0);
  console.log(`[errorstyle] 已写入基线 ${path.relative(ROOT, BASELINE_FILE)}（${Object.keys(doc.bareErrorByFile).length} 文件，${total} 处裸 Error）`);
  return 0;
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--selftest')) return selftestMain();
  const fix = args.includes('--fix-baseline');
  const jsonOut = args.includes('--json');

  const found = findInconsistentThrows(SCAN_DIR, RESTRICTED_DIRS);
  const baseline = loadBaseline();

  if (fix) return fixBaseline(found);

  const { errors, notes } = judge(found, baseline);
  if (jsonOut) {
    console.log(JSON.stringify({ found, errors, notes }, null, 2));
    return errors.length ? 1 : 0;
  }

  if (found.restricted.length > 0) {
    console.log(`  受限目录裸 Error：${found.restricted.length} 处`);
    for (const r of found.restricted.slice(0, 20)) {
      console.log(`    ❌ ${r.file}:${r.line}`);
    }
    if (found.restricted.length > 20) console.log(`    ... 还有 ${found.restricted.length - 20} 个`);
  }
  const nrTotal = Object.values(found.nonRestrictedByFile).reduce((a, b) => a + b, 0);
  if (nrTotal > 0) {
    console.log(`  非受限目录裸 Error：${Object.keys(found.nonRestrictedByFile).length} 文件，${nrTotal} 处`);
  }
  for (const n of notes) console.log(`  ⚠ ${n}`);
  if (errors.length) {
    console.error(`❌ 错误形态门禁：${errors.length} 处违规`);
    return 1;
  }
  console.log(`✅ 错误形态门禁通过（受限 0 处裸 Error，非受限 ${nrTotal} 处）`);
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

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ec-selftest-'));
  const write = (name, content) => {
    const p = path.join(dir, name);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content, 'utf8');
    return p;
  };
  try {
    // ① 受限目录裸 Error → 报出
    write('api/route.js', 'throw new Error("bad");\n');
    t('① 受限目录裸 Error → 报出', () => {
      const found = findInconsistentThrows(dir, [path.join(dir, 'api')]);
      ok(found.restricted.length >= 1, `应报出受限裸 Error，实际 ${found.restricted.length}`);
    });

    // ② AppError → 通过（不报）
    write('api/route2.js', 'throw new AppError(1001, "bad");\n');
    t('② AppError → 通过（不报）', () => {
      const found = findInconsistentThrows(dir, [path.join(dir, 'api')]);
      const hasRoute2 = found.restricted.some((r) => r.file.includes('route2'));
      ok(!hasRoute2, 'AppError 不应报出');
    });

    // ③ 非受限目录超基线 → 报出
    write('core/helper.js', 'throw new Error("a");\nthrow new Error("b");\n');
    t('③ 非受限目录超基线 → 判失败', () => {
      const found = findInconsistentThrows(dir, [path.join(dir, 'api')]);
      const r = judge(found, { bareErrorByFile: {} });
      ok(r.errors.length >= 1, '无基线时非受限裸 Error 增长应报错');
    });

    // ④ 非受限目录在基线内 → 通过（非受限部分不报错）
    t('④ 非受限目录在基线内 → 通过', () => {
      const found = findInconsistentThrows(dir, [path.join(dir, 'api')]);
      const helperFile = Object.keys(found.nonRestrictedByFile).find((f) => f.includes('helper'));
      const r = judge(found, { bareErrorByFile: { [helperFile]: 2 } });
      const nrErrors = r.errors.filter((e) => !e.includes('受限目录'));
      ok(nrErrors.length === 0, `非受限部分应通过，实际 ${JSON.stringify(nrErrors)}`);
    });

    // ⑤ 非受限目录下降 → 提示可下调
    t('⑤ 非受限目录下降 → 提示可下调', () => {
      const found = findInconsistentThrows(dir, [path.join(dir, 'api')]);
      const helperFile = Object.keys(found.nonRestrictedByFile).find((f) => f.includes('helper'));
      const r = judge(found, { bareErrorByFile: { [helperFile]: 5 } });
      ok(r.notes.some((n) => n.includes('已下降')), '应提示可下调基线');
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