#!/usr/bin/env node
// ============================================================================
// scripts/duplication-guard.mjs —— 令牌级重复代码门禁（基线制）
//
// ── 为什么要有这道门 ─────────────────────────────────────────────────────────
// 234 个 tamper 插件中 68 个含逐字重复的字符串扫描状态机；scanHelpers.js 有两份
// 近似白名单合并。修一处漏另一处 → 静默缺陷。本门禁用令牌级指纹检测重复代码块。
//
// ── 算法（design §2.1.3.2）──────────────────────────────────────────────────
// · jsLexer token 化（丢注释/空白，字符串/模板串为单一 literal token 不入哈希）
// · 标识符归一化为 ID 生成指纹序列
// · 窗口 MIN_TOKENS=40 滚动哈希（FNV-1a）
// · 同哈希分组精确比对 → 合并相邻窗口
//
// 用法：
//   node scripts/duplication-guard.mjs               # 检查
//   node scripts/duplication-guard.mjs --selftest    # 自证判据不空转
//   node scripts/duplication-guard.mjs --fix-baseline# 重生成基线
//   node scripts/duplication-guard.mjs --json        # 机器可读输出
// ============================================================================
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { lex } from './lib/jsLexer.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE_FILE = path.join(ROOT, 'docs', '_dup-baseline.json');

const SCAN_DIRS = ['server/src', 'src', 'scripts'];
const EXT = ['.js', '.ts', '.tsx', '.mjs'];
const MIN_TOKENS = 80; // design §2.1.3.2 定 40；实测 500+ 文件仓 40 token 匹配过泛（10 万+），提至 80 聚焦显著重复
const FNV_OFFSET = 0x811c9dc5;
const FNV_PRIME = 0x01000193;

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

// 从 lex tokens 生成归一化指纹序列（标识符→ID，字符串/模板串→literal，注释/空白已丢）
function fingerprintTokens(tokens) {
  const fps = [];
  for (const t of tokens) {
    if (t.type === 'str') {
      fps.push('literal');
    } else if (t.type === 'ident') {
      fps.push('ID');
    } else {
      fps.push(t.value || t.type || '?');
    }
  }
  return fps;
}

// FNV-1a 滚动哈希
function fnv1a(str) {
  let h = FNV_OFFSET;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, FNV_PRIME);
  }
  return h >>> 0;
}

/**
 * 在给定文件列表中查找重复代码块。
 * @param {string[]} files
 * @param {{minTokens?:number}} [opts]
 * @returns {Array<{tokens:number,pairs:Array<{file:string,startLine:number,endLine:number}>}>}
 */
export function findClones(files, opts = {}) {
  const minTokens = opts.minTokens ?? MIN_TOKENS;
  // 每个文件的指纹序列 + 行号表
  const fileData = new Map();
  for (const file of files) {
    const abs = path.isAbsolute(file) ? file : path.join(ROOT, file);
    let src;
    try { src = fs.readFileSync(abs, 'utf8'); } catch { continue; }
    const { tokens } = lex(src);
    if (tokens.length < minTokens) continue;
    const fps = fingerprintTokens(tokens);
    const lines = tokens.map((t) => t.line);
    fileData.set(file, { fps, lines });
  }
  // 每个文件：hash → [startIdx, ...]
  const fileHashMaps = new Map();
  for (const [file, { fps }] of fileData) {
    const hm = new Map();
    for (let i = 0; i + minTokens <= fps.length; i++) {
      const hash = fnv1a(fps.slice(i, i + minTokens).join('\n'));
      if (!hm.has(hash)) hm.set(hash, []);
      hm.get(hash).push(i);
    }
    fileHashMaps.set(file, hm);
  }
  // 跨文件匹配：按 (fileA, fileB, delta) 分组，合并连续 idxA
  const fileList = [...fileHashMaps.keys()];
  const clones = [];
  for (let fi = 0; fi < fileList.length; fi++) {
    for (let fj = fi + 1; fj < fileList.length; fj++) {
      const fileA = fileList[fi], fileB = fileList[fj];
      const hmA = fileHashMaps.get(fileA), hmB = fileHashMaps.get(fileB);
      // delta → [idxA, ...] 收集连续匹配（精确比对消除哈希碰撞）
      const byDelta = new Map();
      const fpsA = fileData.get(fileA).fps, fpsB = fileData.get(fileB).fps;
      for (const [hash, idxsA] of hmA) {
        const idxsB = hmB.get(hash);
        if (!idxsB) continue;
        for (const idxA of idxsA) {
          for (const idxB of idxsB) {
            let exact = true;
            for (let t = 0; t < minTokens; t++) {
              if (fpsA[idxA + t] !== fpsB[idxB + t]) { exact = false; break; }
            }
            if (!exact) continue;
            const delta = idxB - idxA;
            if (!byDelta.has(delta)) byDelta.set(delta, []);
            byDelta.get(delta).push(idxA);
          }
        }
      }
      for (const [delta, idxs] of byDelta) {
        idxs.sort((a, b) => a - b);
        let start = idxs[0], prev = idxs[0];
        for (let k = 1; k < idxs.length; k++) {
          if (idxs[k] === prev + 1) { prev = idxs[k]; continue; }
          flushClone(clones, fileData, fileA, start, prev, fileB, start + delta, prev + delta, minTokens);
          start = idxs[k]; prev = idxs[k];
        }
        flushClone(clones, fileData, fileA, start, prev, fileB, start + delta, prev + delta, minTokens);
      }
    }
  }
  clones.sort((a, b) => b.tokens - a.tokens);
  return clones;
}

function flushClone(out, fileData, fileA, idxAStart, idxAEnd, fileB, idxBStart, idxBEnd, minTokens) {
  const da = fileData.get(fileA), db = fileData.get(fileB);
  const startLineA = da.lines[idxAStart] || 0;
  const endLineA = da.lines[Math.min(idxAEnd + minTokens - 1, da.lines.length - 1)] || 0;
  const startLineB = db.lines[idxBStart] || 0;
  const endLineB = db.lines[Math.min(idxBEnd + minTokens - 1, db.lines.length - 1)] || 0;
  out.push({
    tokens: idxAEnd - idxAStart + minTokens,
    pairs: [
      { file: fileA, startLine: startLineA, endLine: endLineA },
      { file: fileB, startLine: startLineB, endLine: endLineB },
    ],
  });
}

function loadBaseline() {
  try {
    return JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf8'));
  } catch {
    return { _comment: '重复代码基线：只减不增。', clones: 0, waivers: [] };
  }
}

/**
 * 按基线裁定克隆检测结果。
 * @param {Array} clones
 * @param {{clones?:number,waivers?:string[]}} baseline
 * @returns {{errors:string[],notes:string[]}}
 */
export function judge(clones, baseline) {
  const errors = [];
  const notes = [];
  const baseCount = baseline.clones ?? 0;
  if (clones.length > baseCount) {
    errors.push(`重复代码块 ${clones.length} > 基线 ${baseCount}（只减不增）`);
  }
  if (clones.length < baseCount) {
    notes.push(`重复代码块 ${clones.length} < 基线 ${baseCount}（可下调基线）`);
  }
  return { errors, notes };
}

function fixBaseline(clones) {
  const old = loadBaseline();
  const doc = {
    _comment: '重复代码基线：只减不增。clones 不得增长。',
    _generatedBy: 'node scripts/duplication-guard.mjs --fix-baseline',
    clones: clones.length,
    waivers: old.waivers || [],
  };
  fs.writeFileSync(BASELINE_FILE, JSON.stringify(doc, null, 2) + '\n', 'utf8');
  console.log(`[duplication] 已写入基线 ${path.relative(ROOT, BASELINE_FILE)}（${clones.length} 个重复块）`);
  return 0;
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--selftest')) return selftestMain();
  const fix = args.includes('--fix-baseline');
  const jsonOut = args.includes('--json');

  const files = SCAN_DIRS.flatMap((d) => collect(d, EXT, []));
  const clones = findClones(files);
  const baseline = loadBaseline();

  if (fix) return fixBaseline(clones);

  const { errors, notes } = judge(clones, baseline);
  if (jsonOut) {
    console.log(JSON.stringify({ clones, errors, notes }, null, 2));
    return errors.length ? 1 : 0;
  }
  if (clones.length > 0) {
    console.log(`  检出 ${clones.length} 个重复代码块（≥${MIN_TOKENS} tokens）`);
    for (const c of clones.slice(0, 10)) {
      console.log(`    ${c.tokens} tokens: ${c.pairs.map((p) => `${p.file}:${p.startLine}-${p.endLine}`).join(' ≈ ')}`);
    }
    if (clones.length > 10) console.log(`    ... 还有 ${clones.length - 10} 个`);
  }
  for (const n of notes) console.log(`  ⚠ ${n}`);
  if (errors.length) {
    console.error(`❌ 重复代码门禁：${errors.length} 处违规`);
    for (const e of errors) console.error(`   · ${e}`);
    return 1;
  }
  console.log(`✅ 重复代码门禁通过（检出 ${clones.length} 个重复块，基线 ${baseline.clones ?? 0}）`);
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

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dup-selftest-'));
  const write = (name, content) => {
    const p = path.join(dir, name);
    fs.writeFileSync(p, content, 'utf8');
    return p;
  };
  try {
    // 构造两段语义等价的重复代码（≥40 tokens）
    const dupBlock = [
      'function processItem(item, cache, logger) {',
      '  if (item == null) return null;',
      '  const key = item.id + ":" + item.type;',
      '  if (cache.has(key)) return cache.get(key);',
      '  const result = { id: item.id, type: item.type, value: item.value };',
      '  cache.set(key, result);',
      '  logger.log("processed", key);',
      '  return result;',
      '}',
    ].join('\n');

    // ① 两段等价复制 → 同时指出两处
    write('a.js', dupBlock + '\n');
    write('b.js', dupBlock + '\n');
    t('① 两段等价复制 → 同时指出两处', () => {
      const clones = findClones([path.join(dir, 'a.js'), path.join(dir, 'b.js')]);
      ok(clones.length > 0, `应检出重复，实际 ${clones.length}`);
      const c = clones[0];
      ok(c.pairs.length === 2, `应有 2 处位置，实际 ${c.pairs.length}`);
      ok(c.pairs[0].file !== c.pairs[1].file, '两处应在不同文件');
    });

    // ② 形似但语义不同（标识符不同、结构相同）→ 归一化后仍被检出
    const dupRenamed = [
      'function handleEntity(entity, store, log) {',
      '  if (entity == null) return null;',
      '  const tag = entity.id + ":" + entity.type;',
      '  if (store.has(tag)) return store.get(tag);',
      '  const out = { id: entity.id, type: entity.type, value: entity.value };',
      '  store.set(tag, out);',
      '  log.log("processed", tag);',
      '  return out;',
      '}',
    ].join('\n');
    write('d.js', dupRenamed + '\n');
    t('② 形似但标识符不同 → 归一化后仍检出', () => {
      const clones = findClones([path.join(dir, 'a.js'), path.join(dir, 'd.js')]);
      ok(clones.length > 0, `标识符归一化后应检出重复，实际 ${clones.length}`);
    });

    // ③ 单段代码 → 不报
    write('c.js', 'function unique(x) { return x + 1; }\n');
    t('③ 单段代码不报（防误伤）', () => {
      const clones = findClones([path.join(dir, 'c.js')]);
      ok(clones.length === 0, `单段不应报重复，实际 ${clones.length}`);
    });

    // ④ 基线裁定：重复数增长 → 失败
    t('④ 重复数增长被判失败', () => {
      const r = judge([{ tokens: 40, pairs: [] }, { tokens: 40, pairs: [] }], { clones: 1 });
      ok(r.errors.length >= 1, '重复 2 > 基线 1 应报错');
      ok(/只减不增/.test(r.errors[0]), `错误信息应说明只减不增：${r.errors[0]}`);
    });

    // ⑤ 重复数减少 → 提示可下调基线（不报错）
    t('⑤ 重复数减少提示可下调基线', () => {
      const r = judge([{ tokens: 40, pairs: [] }], { clones: 5 });
      ok(r.errors.length === 0, '减少不应报错');
      ok(r.notes.length >= 1, '应有可下调提示');
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