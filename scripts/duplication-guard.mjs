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
// ── 数据表豁免（2026-10-14 T-6b 起因）─────────────────────────────────────────
// 按 token 窗口判重时，**同一类数据的不同副本**（SQL 关键字表、常见名表…）必然互相
// 命中：实测一张 MORE_VERSIONED_WORDS 表与仓内既有数据表产生 2370 条「重复」，而真实
// 代码重复一条没多。这些噪声把基线刷成几万条，**反而掩盖真正的代码重复**。
//
// 判据刻意保守：窗口内**全部** token 必须是 str / num 或结构分隔符，任何
// ident / 运算符 / 调用出现即不豁免 ⇒ 只放过「纯字面量数据表」，绝不放过逻辑代码。
// 效果方向是**基线下调**（门禁对真代码重复更严），不是放宽。
const LITERAL_TABLE_PUNCT = new Set([',', '(', ')', '[', ']', '{', '}', ';', ':', '.']);

/**
 * [D93] 跳过 `new Set(` / `new Map(` / `new Set([` 形式的容器构造前缀。
 * 抽成独立函数是为了让 isLiteralTableWindow 的圈复杂度留在软限内（原先内联 if 链 19 > 15）。
 * @param {Array<{type:string,value:string}>} tokens 窗口 token
 * @param {number} i 当前下标
 * @returns {number} 跳过后的下标（不是该形态则原样返回）
 */
function skipContainerCtor(tokens, i) {
  const isIdent = (t) => !!t && t.type === 'ident';
  const isPunct = (t, v) => !!t && t.type === 'punct' && t.value === v;
  if (!(isIdent(tokens[i]) && tokens[i].value === 'new')) return i;
  if (!(isIdent(tokens[i + 1]) && /^(Set|Map)$/.test(tokens[i + 1].value))) return i;
  let j = i + 2;
  if (isPunct(tokens[j], '(')) j++;
  if (isPunct(tokens[j], '[')) j++;
  return j;
}

/**
 * 该克隆窗口是否「纯字面量数据表」（可豁免）。
 *
 * 允许**一个表头**（`const NAME = [` / `export const NAME = [` / `let` / `var`）——
 * 真实数据表都长这样，若把表头也算进窗口，任何表都豁免不了（selftest ④ 抓过这个）。
 * 表头之后必须**全是 str / num / 结构分隔符**；任何 ident / 运算符 / 调用即不豁免
 * ⇒ 只放过「纯字面量数据表」，绝不放过逻辑代码。
 * [D93] 表头额外允许 `new Set([` / `new Map([` 容器构造包裹（见 skipContainerCtor 的注释：
 * 往 KNOWN_CFG_KEYS 加一个键名就滑出 3 条假重复的真实成本）。
 * @param {Array<{type:string,value:string}>} tokens 窗口内的 token
 * @returns {boolean}
 */
function isLiteralTableWindow(tokens) {
  const isIdent = (t) => !!t && t.type === 'ident';
  const isPunct = (t, v) => !!t && t.type === 'punct' && t.value === v;
  let i = 0;
  if (isIdent(tokens[i])) {
    i++; // export / const / let / var
    if (isIdent(tokens[i])) i++; // default / const / NAME
    if (isIdent(tokens[i])) i++; // const / NAME
    if (isPunct(tokens[i], '=')) i++;
    i = isPunct(tokens[i], '[') ? i + 1 : skipContainerCtor(tokens, i);
  }
  const rest = tokens.slice(i);
  if (!rest.length) return false;
  return rest.every(
    (t) => t.type === 'str' || t.type === 'num' || (t.type === 'punct' && LITERAL_TABLE_PUNCT.has(t.value))
  );
}

export function findClones(files, opts = {}) {
  return findClonesWithStats(files, opts).clones;
}

/**
 * 同 findClones，但额外返回被数据表豁免的条数（供 --json 审计）。
 * @param {string[]} files
 * @param {{minTokens?:number}} [opts]
 * @returns {{clones:Array<object>, literalTableSkipped:number}}
 */
/**
 * 把克隆列表按「纯字面量数据表」豁免规则分区（[T-6b]）。
 * 判据见 isLiteralTableWindow；取窗口 token 用行号二分（lex 的 tokens 按 line 递增）。
 * @param {Array<object>} clones 原始克隆
 * @param {Map<string,{tokens:Array<object>}>} fileData 每文件的 token 序列
 * @returns {{clones:Array<object>, literalTableSkipped:number, skippedSamples:Array<object>}}
 */
function partitionLiteralTables(clones, fileData) {
  const windowTokens = (d, s, e) => {
    let lo = 0, hi = d.tokens.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (d.tokens[mid].line < s) lo = mid + 1; else hi = mid; }
    const start = lo;
    hi = d.tokens.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (d.tokens[mid].line <= e) lo = mid + 1; else hi = mid; }
    return d.tokens.slice(start, lo);
  };
  const kept = [];
  const skippedSamples = [];
  let literalTableSkipped = 0;
  for (const c of clones) {
    // 两处窗口都是「纯字面量表」才豁免（任一侧含逻辑即保留）
    const pureLiteral = c.pairs.every((p) => {
      const d = fileData.get(p.file);
      if (!d || !d.tokens) return false;
      return isLiteralTableWindow(windowTokens(d, p.startLine, p.endLine));
    });
    if (pureLiteral) {
      literalTableSkipped++;
      // 留样本：豁免量必须可核对（「全是数据表」这句话要能被抽查）
      if (skippedSamples.length < 10) skippedSamples.push(c);
    } else kept.push(c);
  }
  return { clones: kept, literalTableSkipped, skippedSamples };
}

/**
 * 逐文件读入并算指纹序列（读不到 / token 数不足的文件直接跳过）。
 * @param {string[]} files
 * @param {number} minTokens 少于它的文件不参与克隆检测
 * @returns {Map<string,{fps:string[], lines:number[], tokens:Array<object>}>}
 */
function collectFileFingerprints(files, minTokens) {
  const fileData = new Map();
  for (const file of files) {
    const abs = path.isAbsolute(file) ? file : path.join(ROOT, file);
    let src;
    try { src = fs.readFileSync(abs, 'utf8'); } catch { continue; }
    const { tokens } = lex(src);
    if (tokens.length < minTokens) continue;
    fileData.set(file, { fps: fingerprintTokens(tokens), lines: tokens.map((t) => t.line), tokens });
  }
  return fileData;
}

/**
 * 建逐文件 hash 表并做跨文件匹配（[D70] 自 findClonesWithStats 拆出：原来「收集 / 匹配 /
 * 分区」三件事挤在一个函数里，圈复杂度顶到 18）。
 * @param {string[]} files
 * @param {Map<string,object>} fileData collectFileFingerprints 的产物
 * @param {number} minTokens
 * @returns {{fileHashMaps:Map<string,Map<string,number[]>>, clones:Array<object>}}
 */
function matchAcrossFiles(files, fileData, minTokens) {

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
  // 每个文件：hash → [startIdx, ...]
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
  return { fileHashMaps, clones };
}

function findClonesWithStats(files, opts = {}) {
  const minTokens = opts.minTokens ?? MIN_TOKENS;
  const fileData = collectFileFingerprints(files, minTokens);
  const { clones } = matchAcrossFiles(files, fileData, minTokens);
  return partitionLiteralTables(clones, fileData);
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
  const { clones, literalTableSkipped, skippedSamples } = findClonesWithStats(files);
  const baseline = loadBaseline();

  if (fix) return fixBaseline(clones);

  const { errors, notes } = judge(clones, baseline);
  if (jsonOut) {
    // [T-6b] literalTableSkipped 一并输出：数据表豁免量必须可审计，不许静默
    console.log(JSON.stringify({ clones, literalTableSkipped, skippedSamples, errors, notes }, null, 2));
    return errors.length ? 1 : 0;
  }
  if (clones.length > 0) {
    console.log(`  检出 ${clones.length} 个重复代码块（≥${MIN_TOKENS} tokens）`);
    for (const c of clones.slice(0, 10)) {
      console.log(`    ${c.tokens} tokens: ${c.pairs.map((p) => `${p.file}:${p.startLine}-${p.endLine}`).join(' ≈ ')}`);
    }
    if (clones.length > 10) console.log(`    ... 还有 ${clones.length - 10} 个`);
  }
  // [T-6b] 豁免量始终打印（不是只在出错时）：让「数据表不算重复」这条口径本身可见
  console.log(`  数据表豁免 ${literalTableSkipped} 条（纯字面量窗口，两侧皆表才豁免）`);
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

    // ④ [T-6b] 纯字面量数据表（两张同构关键字表）→ 豁免不报，且豁免量可审计
    const wordTable = (prefix) => [
      `const ${prefix} = [`,
      ...['SELECT', 'UNION', 'ALL', 'DISTINCT', 'FROM', 'WHERE', 'AND', 'OR', 'ORDER', 'BY',
        'GROUP', 'HAVING', 'LIMIT', 'OFFSET', 'INSERT', 'UPDATE', 'DELETE', 'INTO', 'VALUES', 'SET',
        'DROP', 'CREATE', 'TABLE', 'DATABASE', 'VERSION', 'JOIN', 'ON', 'BETWEEN', 'LIKE', 'NULL',
        'IS', 'IN', 'NOT', 'AS', 'GROUP_CONCAT', 'CURRENT_USER', 'SESSION_USER', 'SUBSTRING', 'CONCAT',
        'IFNULL', 'NULLIF', 'COALESCE', 'BENCHMARK', 'CONVERT', 'SLEEP', 'CHAR', 'CAST', 'COUNT',
        'ASCII', 'BINARY', 'SCHEMA', 'MID', 'ORD', 'USER', 'IF'].map((w) => `  "${w}",`),
      '];',
    ].join('\n') + '\n';
    write('t1.js', wordTable('A'));
    write('t2.js', wordTable('B'));
    t('④ 纯字面量数据表 → 豁免不报（豁免量可审计）', () => {
      const r = findClonesWithStats([path.join(dir, 't1.js'), path.join(dir, 't2.js')]);
      ok(r.clones.length === 0, `两张同构数据表不应报重复，实际 ${r.clones.length}`);
      ok(r.literalTableSkipped >= 1, `应记录豁免量，实际 ${r.literalTableSkipped}`);
    });

    // ⑤ [T-6b] 表里混进一个 ident（函数调用）→ 不豁免（判据不得过宽，把逻辑重复放过）
    write('t3.js', wordTable('C') + 'export function pick(list) { return list[0]; }\n');
    write('t4.js', wordTable('D') + 'export function take(list) { return list[0]; }\n');
    t('⑤ 数据表里含 ident → 仍判重复（豁免不得过宽）', () => {
      const r = findClonesWithStats([path.join(dir, 't3.js'), path.join(dir, 't4.js')]);
      ok(r.clones.length > 0, `含逻辑的同构窗口仍应报重复，实际 ${r.clones.length}`);
    });

    // ⑥ 基线裁定：重复数增长 → 失败
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