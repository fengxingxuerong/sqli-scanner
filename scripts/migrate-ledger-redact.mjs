#!/usr/bin/env node
// ============================================================================
// migrate-ledger-redact.mjs —— 旧台账凭据脱敏迁移（默认 dry-run，不删任何数据）
//
// 背景：2026-11-02 之前 recordScan 直接落原始报告，历史台账的 report.json / poc/*.txt
// 可能含 auth/proxy/Cookie/Authorization 明文。本次迁移只做**原地脱敏重写**：
//   · 可解析的 report.json → redactPersistedReport；
//   · poc/*.txt → redactPocText；
//   · meta.json 的 target URL → 掩掉 URL 内嵌凭据（user:pass@host）。
// 不删除目录、不重建索引；不可解析的文件原样跳过并列出，交人工处理。
//
// 用法：
//   node scripts/migrate-ledger-redact.mjs               # dry-run，只打印将改动的文件
//   node scripts/migrate-ledger-redact.mjs --apply       # 实际重写（建议先备份整目录）
//   node scripts/migrate-ledger-redact.mjs --dir <path>  # 指定台账根（默认 server/data/ledger）
// ============================================================================
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { redactPersistedReport, redactPocText } from '../server/src/services/reportRedaction.js';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const APPLY = process.argv.includes('--apply');
const dirArg = process.argv.indexOf('--dir');
const LEDGER = dirArg !== -1 && process.argv[dirArg + 1]
  ? resolve(process.argv[dirArg + 1])
  : resolve(ROOT, 'server/data/ledger');

function walk(dir) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, ent.name);
    if (ent.isDirectory()) walk(p);
    else if (ent.isFile()) files.push(p);
  }
}

function changed(original, next) {
  return original !== next;
}

const files = [];
walk(LEDGER);
let planned = 0;
let applied = 0;
let skipped = 0;

for (const file of files) {
  const name = file.split(/[\\/]/).pop();
  if (name === 'report.json') {
    try {
      const original = readFileSync(file, 'utf8');
      const next = JSON.stringify(redactPersistedReport(JSON.parse(original)), null, 2);
      if (!changed(original, next)) continue;
      planned += 1;
      console.log(`[plan] report.json → ${file}`);
      if (APPLY) {
        writeFileSync(file, next, 'utf8');
        applied += 1;
      }
    } catch (e) {
      skipped += 1;
      console.warn(`[skip] 无法解析/处理的 report.json（${file}）：${e?.message || e}`);
    }
    continue;
  }
  if (name.endsWith('.txt') && /[\\/]poc[\\/]/.test(file)) {
    const original = readFileSync(file, 'utf8');
    const next = redactPocText(original);
    if (!changed(original, next)) continue;
    planned += 1;
    console.log(`[plan] poc → ${file}`);
    if (APPLY) {
      writeFileSync(file, next, 'utf8');
      applied += 1;
    }
    continue;
  }
  if (name === 'meta.json' || name === 'index.jsonl') continue; // 仅含脱敏后的 target URL（见下）
}

// meta/index 的 target URL 只掩内嵌凭据，不动其他字段（避免破坏历史列表）
for (const file of files) {
  const name = file.split(/[\\/]/).pop();
  if (name !== 'meta.json' && name !== 'index.jsonl') continue;
  try {
    const original = readFileSync(file, 'utf8');
    if (name === 'meta.json') {
      const j = JSON.parse(original);
      if (typeof j?.target === 'string') j.target = redactPocText(j.target);
      const next = JSON.stringify(j, null, 2);
      if (!changed(original, next)) continue;
      planned += 1;
      console.log(`[plan] meta target → ${file}`);
      if (APPLY) { writeFileSync(file, next, 'utf8'); applied += 1; }
    } else {
      const next = original.split('\n').map((line) => {
        if (!line.trim()) return line;
        try {
          const j = JSON.parse(line);
          if (typeof j?.target === 'string') j.target = redactPocText(j.target);
          return JSON.stringify(j);
        } catch {
          return line;
        }
      }).join('\n');
      if (!changed(original, next)) continue;
      planned += 1;
      console.log(`[plan] index target → ${file}`);
      if (APPLY) { writeFileSync(file, next, 'utf8'); applied += 1; }
    }
  } catch (e) {
    skipped += 1;
    console.warn(`[skip] 无法处理的 ${name}（${file}）：${e?.message || e}`);
  }
}

console.log(`\n[migrate-ledger-redact] ${APPLY ? '已应用' : 'dry-run'}：计划 ${planned} 个文件，实际写入 ${applied} 个，跳过 ${skipped} 个。`);
console.log('提示：执行 --apply 前请先备份整个台账目录；本脚本不删除任何文件。');
