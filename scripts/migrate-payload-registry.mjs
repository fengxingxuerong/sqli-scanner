#!/usr/bin/env node
/**
 * migrate-payload-registry.mjs —— E5「payload 声明式」第二步：把 `PAYLOAD_REGISTRY`
 * 的数据部分从 JS 数组迁移成 JSON 数据文件，并给出可复现的导出证据。
 *
 * 背景：`payloadRegistry.js` 里 98–817 行是纯数据（720 行 / 占该文件绝大部分体积），
 * 817 行之后才是逻辑（高危池门禁、selectPayloads 筛选、版本过滤）。第一步
 * （`payloadSchema.js`）已机械证明这 681 条能被 schema 完整描述且 JSON-safe ——
 * 本脚本就是那次证明的**执行者**。
 *
 * 硬约束（导出前逐条自检，任何一条不过就 exit 1 且不写文件）：
 *   ① 全部条目 JSON-safe（YAML/JSON 装不下 undefined / 函数 / Symbol / BigInt）
 *   ② 字段不越界（都在 payloadSchema.KNOWN_FIELDS 内 —— 否则 DSL 化会静默丢字段）
 *   ③ schema 校验全通过 + id 无重复
 *   ④ **保持原数组顺序**（顺序 = 投放优先级，不是可排序字段）
 *
 * 用法：
 *   node scripts/migrate-payload-registry.mjs                 # 导出到 server/src/engine/payloads/registry.json
 *   node scripts/migrate-payload-registry.mjs --stdout        # 打到 stdout（人工核对用，不写盘）
 *   node scripts/migrate-payload-registry.mjs --out <path>
 *
 * 退出码：0 = 导出成功（或核对一致）；1 = 自检失败
 */
import { writeFileSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { PAYLOAD_REGISTRY } from '../server/src/engine/payloadRegistry.js';
import {
  validatePayloadEntries,
  isJsonSafe,
  toDslEntry,
  KNOWN_FIELDS,
} from '../server/src/engine/payloadSchema.js';

const REPO = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const DEFAULT_OUT = path.join(REPO, 'server', 'src', 'engine', 'payloads', 'registry.json');

function parseArgs(argv) {
  const opts = { stdout: false, out: DEFAULT_OUT };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--stdout') opts.stdout = true;
    else if (argv[i] === '--out') opts.out = path.resolve(argv[i + 1] || '');
    else if (argv[i].startsWith('--out=')) opts.out = path.resolve(argv[i].slice(6));
  }
  return opts;
}

/**
 * 从 payloadRegistry.js 的**源码文本**里抽行内注释，归并成每条 payload 的 note。
 *
 * 为什么必须从源码抽、不能从运行时对象拿：注释不是数据，import 出来的数组里没有它。
 * 而这些注释是**知识**（"为什么加这条 payload"、"这条的实战价值"），数据外置时丢掉
 * 就等于把决策理由从仓库里抹掉。规则：条目上方的连续 `//` 行整段并入该条目的 note；
 * 纯装饰的 `====…` 包边去掉但保留其中文字（分组标题往往带补全批次/依据）。
 *
 * @param {string} src payloadRegistry.js 的全文
 * @returns {{notes: Map<string,string>, entries: number, orphan: number}}
 */
function extractNotesFromSource(src) {
  const lines = src.split('\n');
  const start = lines.findIndex((l) => /^export const PAYLOAD_REGISTRY = \[/.test(l));
  if (start < 0) throw new Error('未找到 PAYLOAD_REGISTRY 定义起始行');
  let end = -1;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^\];/.test(lines[i])) { end = i; break; }
  }
  if (end < 0) throw new Error('未找到 PAYLOAD_REGISTRY 数组结束行');

  // 分组标题的两种实际形态：`==== 标题 ====` 与 `---- 标题 ----`
  const TITLE_RE = /^(?:=+|-{2,})\s.*\s(?:=+|-{2,})$/;

  const notes = new Map();
  const sectionOnly = []; // 归属不到任何条目的注释（段落级/数组首尾），由调用方打印出来人工过一遍
  let entries = 0;
  let block = []; // { text, isTitle }
  let lastId = null; // 最近一条出现的条目（供「段尾注释」回溯）

  const append = (id, text) => {
    if (!id || !text) return;
    notes.set(id, notes.has(id) ? `${notes.get(id)}\n${text}` : text);
  };

  const flush = (nextId) => {
    if (!block.length) return;
    const endsWithTitle = block[block.length - 1].isTitle;
    if (endsWithTitle) {
      // 块以分组标题结尾 ⇒ 这个标题开启的是**下一段**，所以标题之前的内容属于**上一段**：
      // 追加到上一条目，标题本身丢弃（纯组织信息）。实测 186 行「Oracle 标准驱动不支持堆叠查询」
      // 正是这个形态 —— 若按"归属下一条"处理会被错挂到 SQLite 段的第一条上。
      const before = block
        .slice(0, -1)
        .map((b) => (b.isTitle ? `[分组] ${b.text}` : b.text))
        .join('\n');
      if (before) {
        if (lastId) append(lastId, before);
        else sectionOnly.push(before);
      }
    } else {
      const text = block.map((b) => (b.isTitle ? `[分组] ${b.text}` : b.text)).join('\n');
      if (nextId) notes.set(nextId, text);
      else sectionOnly.push(text);
    }
    block = [];
  };

  for (let i = start + 1; i < end; i += 1) {
    const raw = lines[i].trim();
    if (raw.startsWith('//')) {
      const body = raw.replace(/^\/\/+\s?/, '');
      if (/^[=\-\s]*$/.test(body)) continue; // 纯装饰行
      const isTitle = TITLE_RE.test(body);
      const text = isTitle
        ? body.replace(/^(?:=+|-{2,})\s*/, '').replace(/\s*(?:=+|-{2,})$/, '').trim()
        : body;
      if (text) block.push({ text, isTitle });
      continue;
    }
    if (raw === '' || raw === ',') continue; // 空行不断块：注释与条目之间常隔着空行
    const m = raw.match(/^\{\s*id:\s*'([^']+)'/);
    if (m) {
      flush(m[1]);
      entries += 1;
      lastId = m[1];
    }
  }
  flush(null); // 数组末尾可能还有一块注释

  return { notes, entries, orphan: sectionOnly.length, sectionOnly };
}

function selfCheck(entries) {
  const problems = [];

  const notSafe = entries.filter((e) => !isJsonSafe(e));
  if (notSafe.length) problems.push(`JSON-safe 失败 ${notSafe.length} 条：${notSafe.slice(0, 5).map((e) => e.id).join(', ')}`);

  const unknownFields = new Set();
  for (const e of entries) for (const k of Object.keys(e)) if (!KNOWN_FIELDS.includes(k)) unknownFields.add(k);
  if (unknownFields.size) problems.push(`出现 schema 未建模字段：${[...unknownFields].join(', ')}`);

  const r = validatePayloadEntries(entries);
  if (r.failed.length) {
    problems.push(`schema 校验失败 ${r.failed.length} 条：${r.failed.slice(0, 5).map((f) => `${f.id}: ${f.errors.join('|')}`).join('; ')}`);
  }
  if (r.duplicateIds.length) problems.push(`重复 id ${r.duplicateIds.length} 个：${r.duplicateIds.slice(0, 5).join(', ')}`);

  return { problems, stats: r };
}

const opts = parseArgs(process.argv.slice(2));
const entries = Array.isArray(PAYLOAD_REGISTRY) ? PAYLOAD_REGISTRY : [];

// 行内注释 → note：必须从**源码文本**取（运行时数组里没有注释）
const SRC = path.join(REPO, 'server', 'src', 'engine', 'payloadRegistry.js');
const { notes, entries: srcEntryCount, orphan, sectionOnly } = extractNotesFromSource(readFileSync(SRC, 'utf8'));

if (!entries.length) {
  console.error('[migrate] PAYLOAD_REGISTRY 为空 —— 取数源变了？');
  process.exit(1);
}

// 归属自检（先做）：源码扫到的条目数必须等于运行时数组长度，否则 note 会**串行错位**——
// 那种错误不会让任何断言变红，只会把 A 条的理由挂到 B 条上，故这里硬失败。
if (srcEntryCount !== entries.length) {
  console.error(`[migrate] 源码扫描条目数 ${srcEntryCount} ≠ 运行时数组 ${entries.length} —— note 归属不可信，中止`);
  process.exit(1);
}
if (orphan) {
  // 段落级注释（多出现在数组首尾）不作为失败，但必须打印出来人工过一遍 —— 静默丢知识是这次迁移最不能接受的失败形态。
  console.error(`[migrate] 注意：${orphan} 处注释未归属到任何条目，内容如下（请人工确认是否该保留）：`);
  for (const s of sectionOnly) console.error('  § ' + s.split('\n').join(' / '));
}

// toDslEntry 做一次深层 JSON 往返（丢 undefined），保证落盘内容与运行时读回的完全一致；
// note 放在 id 之后（per-line 格式下最可读），其余字段顺序不变。
const payload = entries.map((e) => {
  const base = toDslEntry(e);
  const note = notes.get(e.id);
  return note ? { id: base.id, note, ...base } : base;
});

const { problems, stats } = selfCheck(payload);
if (problems.length) {
  console.error('[migrate] 自检失败，未写任何文件：');
  for (const p of problems) console.error('  · ' + p);
  process.exit(1);
}
// 落盘格式：**每条一行**。实测三种（681 条）—— 紧凑 149.7 KB / 每条一行 151.7 KB / 缩进 2 空格 219.6 KB。
// 相比缩进格式省 68 KB，且每行一条让 diff 能定位到具体条目（缩进格式一个字段改动只显示一行变化，
// 看不出改的是哪条 payload）。
const text = '[\n' + payload.map((e) => '  ' + JSON.stringify(e)).join(',\n') + '\n]\n';

if (opts.stdout) {
  process.stdout.write(text);
  console.error(`[migrate] ${entries.length} 条 / ${Buffer.byteLength(text)} 字节 → stdout`);
  process.exit(0);
}

writeFileSync(opts.out, text, 'utf8');
const bytes = Buffer.byteLength(text);
const readBack = JSON.parse(readFileSync(opts.out, 'utf8'));
const same = readBack.length === payload.length && JSON.stringify(readBack) === JSON.stringify(payload);
console.error(
  `[migrate] 写出 ${path.relative(REPO, opts.out)}：${payload.length} 条 / ${(bytes / 1024).toFixed(1)} KB` +
    `（schema ok=${stats.okCount}/${stats.total}，读回一致=${same ? 'yes' : 'NO'}）`,
);
const withNote = payload.filter((e) => e.note);
console.error(
  `[migrate] 注释迁移：源码注释块归属 ${notes.size} 条 → 落盘 note ${withNote.length} 条` +
    `（${withNote.reduce((a, e) => a + Buffer.byteLength(e.note), 0)} 字节）`,
);
process.exit(same ? 0 : 1);
