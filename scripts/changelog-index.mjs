#!/usr/bin/env node
// ============================================================================
// scripts/changelog-index.mjs —— 生成 / 校验 CHANGELOG [Unreleased] 顶部的批次索引
//
// ── 为什么要有这个脚本 ───────────────────────────────────────────────────────
// [Unreleased] 里堆了 60+ 个批次、近 2000 行。读者要找一个批次只能 Ctrl+F，而「手工维护
// 一份索引」必然过期（本仓反复踩过「文档现状段过期」）。所以索引必须由正文机械生成：
//   · 唯一真源是正文里的 `### YYYY-MM-DD 批次 Dxxx · 标题` 行；
//   · 脚本只重写两个标记之间的内容，**正文一个字不动**（不删历史是本仓的既定口径）。
//
// ── 用法 ─────────────────────────────────────────────────────────────────────
//   node scripts/changelog-index.mjs            # 校验（默认；过期则 exit 1）
//   node scripts/changelog-index.mjs --check    # 同上
//   node scripts/changelog-index.mjs --write    # 重生成
//   node scripts/changelog-index.mjs --selftest # 自证判据不空转
// ============================================================================
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FILE = path.join(ROOT, 'CHANGELOG.md');
const START = '<!-- changelog-index:start -->';
const END = '<!-- changelog-index:end -->';
const ENTRY = /^### (\d{4}-\d{2}-\d{2}) 批次 (D\d+) · (.+)$/;

/**
 * 解析 [Unreleased] 段内的批次条目（按正文顺序）。
 * @param {string[]} lines CHANGELOG 全文按行拆分
 * @returns {{batch:string, date:string, title:string}[]}
 */
function parseEntries(lines) {
  const start = lines.findIndex((l) => l.startsWith('## [Unreleased]'));
  if (start < 0) throw new Error('找不到 `## [Unreleased]` 段');
  const end = lines.findIndex((l, i) => i > start && l.startsWith('## ['));
  const stop = end < 0 ? lines.length : end;
  const out = [];
  for (let i = start; i < stop; i++) {
    const m = ENTRY.exec(lines[i]);
    if (m) out.push({ date: m[1], batch: m[2], title: m[3].replace(/\|/g, '\\|') });
  }
  return out;
}

/**
 * 生成索引块（含首尾标记）。
 * 空段（刚发版完）返回占位说明 —— 发版是正常路径，不该让门禁红。
 * @param {{batch:string, date:string, title:string}[]} entries 批次条目
 * @returns {string[]} 索引块的行
 */
function renderBlock(entries) {
  if (!entries.length) {
    return [START, '当前没有未发布批次（最近一次发版见下方版本段落）。', END];
  }
  const newest = entries[0];
  const oldest = entries[entries.length - 1];
  const head = [
    START,
    `**本段覆盖 ${entries.length} 个批次（${oldest.batch}–${newest.batch}，${oldest.date} → ${newest.date}）**。`
      + '正文按时间倒序排列；',
    '下表是同一批次的索引，便于按编号或关键词定位。**索引只是导航，正文未做任何删改**',
    '（被推翻的旧结论原样保留，这是本仓的既定口径）。新增批次后跑',
    '`node scripts/changelog-index.mjs --write` 重生成，`--check` 校验是否过期。',
    '',
    '| 批次 | 日期 | 主题 |',
    '|---|---|---|',
  ];
  const rows = entries.map((e) => `| ${e.batch} | ${e.date.slice(5)} | ${e.title} |`);
  return [...head, ...rows, END];
}

/**
 * 把索引块替换进全文（只动两个标记之间）。
 * @param {string[]} lines CHANGELOG 全文
 * @param {string[]} block 新索引块
 * @returns {string[]} 替换后的全文
 */
function spliceBlock(lines, block) {
  const s = lines.indexOf(START);
  const e = lines.indexOf(END);
  if (s < 0 || e < 0 || e < s) throw new Error(`找不到索引标记（${START} / ${END}）`);
  return [...lines.slice(0, s), ...block, ...lines.slice(e + 1)];
}

/**
 * 计算索引重写后的全文（纯函数，不碰磁盘）。
 * @param {string} text CHANGELOG 全文
 * @returns {{next:string, count:number}} 新全文与批次条数
 */
function buildIndex(text) {
  const lines = text.split('\n');
  const entries = parseEntries(lines);
  const block = renderBlock(entries);
  return { next: spliceBlock(lines, block).join('\n'), count: entries.length };
}

/**
 * 校验或重写一个 CHANGELOG 文件。
 * @param {string} file 文件路径
 * @param {{write?:boolean, quiet?:boolean}} [opts] write=重写；quiet=不打印正常路径
 * @returns {number} 退出码（0 一致/已写；1 过期或出错）
 */
function run(file, opts = {}) {
  const { write = false, quiet = false } = opts;
  const before = fs.readFileSync(file, 'utf8');
  let built;
  try {
    built = buildIndex(before);
  } catch (e) {
    console.error(`[changelog-index] ✗ ${e.message}`);
    return 1;
  }
  if (built.next === before) {
    if (!quiet) console.log(`[changelog-index] ✓ 索引与正文一致（${built.count} 个批次）`);
    return 0;
  }
  if (!write) {
    if (!quiet) {
      console.error('[changelog-index] ✗ 索引已过期（与正文批次不一致）');
      console.error('    修法：node scripts/changelog-index.mjs --write');
    }
    return 1;
  }
  fs.writeFileSync(file, built.next, 'utf8');
  if (!quiet) console.log(`[changelog-index] 已重写索引（${built.count} 个批次）`);
  return 0;
}

/**
 * 自证：过期必报、写完必过、幂等、新增批次后必重新过期。
 * @returns {number} 退出码
 */
function selftest() {
  let failed = 0;
  const t = (name, fn) => {
    try { fn(); console.log(`  ✔ ${name}`); }
    catch (e) { failed++; console.log(`  ✖ ${name}\n    ${e.message}`); }
  };
  const ok = (v, m) => { if (!v) throw new Error(m); };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'changelog-index-'));
  const file = path.join(dir, 'CHANGELOG.md');
  fs.writeFileSync(file, [
    '## [Unreleased]', '', START, END, '',
    '### 2026-10-31 批次 D2 · 乙', '正文', '',
    '### 2026-10-30 批次 D1 · 甲', '正文', '',
  ].join('\n'));
  try {
    t('① 索引为空（过期）→ check 失败', () => {
      ok(run(file, { quiet: true }) === 1, '应判过期');
    });
    t('② --write 后 check 通过', () => {
      ok(run(file, { write: true, quiet: true }) === 0, 'write 应成功');
      ok(run(file, { quiet: true }) === 0, '写后应一致');
    });
    t('③ 幂等：重复 write 不改内容', () => {
      const before = fs.readFileSync(file, 'utf8');
      run(file, { write: true, quiet: true });
      ok(fs.readFileSync(file, 'utf8') === before, '重复 write 不应改变内容');
    });
    t('④ 新增批次但没更新索引 → check 失败', () => {
      fs.appendFileSync(file, '\n### 2026-11-01 批次 D3 · 丙\n正文\n');
      ok(run(file, { quiet: true }) === 1, '新增批次后应判过期');
    });
    t('⑤ 空 Unreleased（刚发版）→ 写占位且 check 通过', () => {
      fs.writeFileSync(file, [
        '## [Unreleased]', '', START, END, '',
        '## [1.3.0] - 2026-10-31', '正文', '',
      ].join('\n'));
      ok(run(file, { write: true, quiet: true }) === 0, '空段 write 应成功');
      ok(run(file, { quiet: true }) === 0, '空段应一致（发版是正常路径，不该红）');
      ok(fs.readFileSync(file, 'utf8').includes('当前没有未发布批次'), '应写入占位说明');
    });
  } finally {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* 夹具在 tmpdir */ }
  }
  console.log(failed ? `\n❌ selftest ${failed} 条失败` : '\n✅ selftest 全绿');
  return failed ? 1 : 0;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  if (process.argv.includes('--selftest')) {
    process.exitCode = selftest();
  } else {
    process.exitCode = run(FILE, { write: process.argv.includes('--write') });
  }
}
