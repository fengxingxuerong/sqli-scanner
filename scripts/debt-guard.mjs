#!/usr/bin/env node
// ============================================================================
// scripts/debt-guard.mjs —— 技术债标记格式门禁（design §2.1.3.6）
//
// ── 为什么要有这道门 ─────────────────────────────────────────────────────────
// server/src 内约 23-26 处 TODO/FIXME/HACK/XXX 标记格式不一：有的裸 `// TODO 修一下`，
// 有的带日期但无批次归属。没有门禁 → 新标记随意加、旧标记无人闭环。
//
// ── 管法 ────────────────────────────────────────────────────────────────────
// · 统一格式：`// [TODO 2026-10-13 D53] 一句话简述`
//   类型 ∈ TODO/FIXME/HACK/XXX；第二段日期；第三段归属 D 批次；后接简述
// · 老标记全部进基线，只对**新增**标记判格式
// · 基线内标记消失 → 提示可下调
//
// 用法：
//   node scripts/debt-guard.mjs               # 检查
//   node scripts/debt-guard.mjs --selftest    # 自证判据不空转
//   node scripts/debt-guard.mjs --fix-baseline# 重生成基线
//   node scripts/debt-guard.mjs --json        # 机器可读输出
// ============================================================================
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE_FILE = path.join(ROOT, 'docs', '_debt-baseline.json');

const SCAN_DIRS = ['server/src', 'src', 'scripts'];
const EXT = ['.js', '.ts', '.tsx', '.mjs'];

// 统一格式正则：// [TODO 2026-10-13 D53] 简述
const UNIFIED_RE = /^\s*\/\/\s*\[(TODO|FIXME|HACK|XXX)\s+(\d{4}-\d{2}-\d{2})\s+(D\d+|[A-Z][-A-Z0-9]*)\]\s+(.+)/;
// 宽松检测：任何注释行含 TODO/FIXME/HACK/XXX 全词（不匹配 XXX.MySQL 等）
const LOOSE_RE = /\b(TODO|FIXME|HACK|XXX)\b/;

function collectFiles(rel, out) {
  const abs = path.isAbsolute(rel) ? rel : path.join(ROOT, rel);
  if (!fs.existsSync(abs)) return out;
  for (const ent of fs.readdirSync(abs, { withFileTypes: true })) {
    if (ent.name.startsWith('.') || ['node_modules', 'dist', 'build', 'coverage'].includes(ent.name)) continue;
    const sub = path.isAbsolute(rel)
      ? path.join(rel, ent.name).replace(/\\/g, '/')
      : path.posix.join(rel.replace(/\\/g, '/'), ent.name);
    if (ent.isDirectory()) collectFiles(sub, out);
    else if (EXT.some((e) => ent.name.endsWith(e))) out.push(sub);
  }
  return out;
}

/**
 * 扫描技术债标记。
 * @param {string[]} scanDirs - 扫描目录
 * @returns {{markers:Array<{type,file,line,date?,batch?,summary?,unified:boolean}>}}
 */
export function scanDebtMarkers(scanDirs) {
  const markers = [];
  for (const d of scanDirs) {
    const files = collectFiles(d, []);
    for (const f of files) {
      const abs = path.isAbsolute(f) ? f : path.join(ROOT, f);
      let src;
      try { src = fs.readFileSync(abs, 'utf8'); } catch { continue; }
      const lines = src.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        // Skip non-comment lines (must be // or * or /* to be a comment)
        if (!trimmed.startsWith('//') && !trimmed.startsWith('*') && !trimmed.startsWith('/*')) continue;
        // Skip lines that look like they're inside string literals
        if (trimmed.includes('"TODO"') || trimmed.includes("'TODO'")) continue;

        const um = line.match(UNIFIED_RE);
        if (um) {
          markers.push({ type: um[1], file: f, line: i + 1, date: um[2], batch: um[3], summary: um[4], unified: true });
          continue;
        }
        const lm = line.match(LOOSE_RE);
        if (lm) {
          markers.push({ type: lm[1].toUpperCase(), file: f, line: i + 1, unified: false });
        }
      }
    }
  }
  return { markers };
}

function loadBaseline() {
  try {
    return JSON.parse(fs.readFileSync(BASELINE_FILE, 'utf8'));
  } catch {
    return { _comment: '技术债标记基线：老标记只减不增，新增必须统一格式。', markers: {} };
  }
}

/**
 * 按基线裁定技术债标记检测结果。
 * @param {{markers:Array}} found
 * @param {{markers?:object}} baseline
 * @returns {{errors:string[],notes:string[]}}
 */
export function judge(found, baseline) {
  const errors = [];
  const notes = [];
  const baseMarkers = baseline.markers || {};
  const baseKeys = new Set(Object.keys(baseMarkers));

  for (const m of found.markers) {
    const key = `${m.file}::${m.line}`;
    if (baseKeys.has(key)) continue; // 基线豁免
    if (!m.unified) {
      errors.push(`新增裸标记格式违规：${m.file}:${m.line}（${m.type}，应使用 // [${m.type} YYYY-MM-DD D##] 简述）`);
    }
  }

  // Check for baseline entries that no longer exist
  const foundKeys = new Set(found.markers.map((m) => `${m.file}::${m.line}`));
  for (const key of baseKeys) {
    if (!foundKeys.has(key)) {
      notes.push(`基线条目 ${key} 已消失，可从基线中移除`);
    }
  }

  return { errors, notes };
}

function fixBaseline(found) {
  const old = loadBaseline();
  const oldMarkers = old.markers || {};
  const markers = {};
  for (const m of found.markers) {
    const key = `${m.file}::${m.line}`;
    if (oldMarkers[key]) {
      markers[key] = oldMarkers[key];
    } else {
      markers[key] = {
        type: m.type,
        unified: m.unified,
        date: m.date || null,
        batch: m.batch || null,
        summary: m.summary || (m.unified ? '' : '裸标记待统一格式'),
        status: m.unified ? 'open' : 'unformatted',
      };
    }
  }
  const doc = {
    _comment: '技术债标记基线：老标记只减不增，新增必须统一格式。',
    _generatedBy: 'node scripts/debt-guard.mjs --fix-baseline',
    markers,
  };
  fs.writeFileSync(BASELINE_FILE, JSON.stringify(doc, null, 2) + '\n', 'utf8');
  const unified = Object.values(markers).filter((m) => m.unified).length;
  console.log(`[debt] 已写入基线 ${path.relative(ROOT, BASELINE_FILE)}（${Object.keys(markers).length} 个标记，${unified} 统一格式）`);
  return 0;
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--selftest')) return selftestMain();
  const fix = args.includes('--fix-baseline');
  const jsonOut = args.includes('--json');

  const found = scanDebtMarkers(SCAN_DIRS);
  const baseline = loadBaseline();

  if (fix) return fixBaseline(found);

  const { errors, notes } = judge(found, baseline);
  if (jsonOut) {
    console.log(JSON.stringify({ found, errors, notes }, null, 2));
    return errors.length ? 1 : 0;
  }

  const unified = found.markers.filter((m) => m.unified).length;
  const bare = found.markers.filter((m) => !m.unified).length;
  console.log(`  技术债标记：${found.markers.length} 个（统一格式 ${unified}，裸标记 ${bare}）`);
  for (const n of notes.slice(0, 10)) console.log(`  ⚠ ${n}`);
  if (notes.length > 10) console.log(`  ... 还有 ${notes.length - 10} 条提示`);
  if (errors.length) {
    console.error(`❌ 技术债门禁：${errors.length} 处新增裸标记格式违规`);
    for (const e of errors.slice(0, 10)) console.error(`    ${e}`);
    return 1;
  }
  console.log(`✅ 技术债门禁通过（${found.markers.length} 个标记，${unified} 统一格式，${bare} 基线豁免）`);
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

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'debt-selftest-'));
  const write = (name, content) => {
    const p = path.join(dir, name);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content, 'utf8');
    return p;
  };
  try {
    // ① 裸 `// TODO 修一下` → 报出格式违规
    write('bad.js', '// TODO 修一下\n');
    t('① 裸标记 → 报出格式违规', () => {
      const found = scanDebtMarkers([dir]);
      ok(found.markers.length >= 1, `应检出标记，实际 ${found.markers.length}`);
      ok(!found.markers[0].unified, '裸标记应 unified=false');
      const r = judge(found, { markers: {} });
      ok(r.errors.length >= 1, '无基线时应报格式违规');
    });

    // ② 合规标记 → 通过
    write('good.js', '// [TODO 2026-10-13 D61] 修复某问题\n');
    t('② 合规标记 → 通过', () => {
      const found = scanDebtMarkers([dir]);
      const goodMarker = found.markers.find((m) => m.file.includes('good.js'));
      ok(goodMarker, '应检出合规标记');
      ok(goodMarker.unified, '合规标记应 unified=true');
      ok(goodMarker.date === '2026-10-13', `日期应解析正确，实际 ${goodMarker.date}`);
      ok(goodMarker.batch === 'D61', `批次应解析正确，实际 ${goodMarker.batch}`);
      const r = judge(found, { markers: {} });
      const goodErrors = r.errors.filter((e) => e.includes('good.js'));
      ok(goodErrors.length === 0, '合规标记不应报错');
    });

    // ③ 基线内已删除标记 → 提示可下调
    t('③ 基线内已删除标记 → 提示可下调', () => {
      const found = { markers: [] };
      const r = judge(found, { markers: { 'deleted.js::1': { type: 'TODO', status: 'open' } } });
      ok(r.notes.some((n) => n.includes('已消失')), '应提示基线条目已消失');
    });

    // ④ 基线内裸标记 → 豁免不报
    t('④ 基线内裸标记 → 豁免不报', () => {
      const found = scanDebtMarkers([dir]);
      const badFile = found.markers.find((m) => m.file.includes('bad.js'));
      const r = judge(found, { markers: { [`${badFile.file}::${badFile.line}`]: { type: 'TODO', status: 'open' } } });
      const badErrors = r.errors.filter((e) => e.includes('bad.js'));
      ok(badErrors.length === 0, '基线内裸标记应豁免');
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