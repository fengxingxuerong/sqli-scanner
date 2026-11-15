// ============================================================================
// tests/versionSync.indent.guard.test.js —— [D294] 版本号判据不得被 JSON 缩进绑架
// ============================================================================
// 真因（2026-11-15 远端 CI 日志取证）：Dependabot PR #28 升级前端依赖时把
// package-lock.json 重写成 **1 空格缩进**（master 是 2 空格）。合法的 lock、版本齐全，
// 但旧判据 `/^\s{2}"version"/` 与 `/^\s{6}"version"/` 读不到字段 ⇒ lint step34 报
// 「版本号不一致（2 处）」，并连带 test-server「接线-4」失败。
// 本守卫用**仓库真实文件的副本**做变形，不是合成 mock：
//   · 正向：两个 lock 改成 1 空格缩进后，10 处版本仍须全读到、0 mismatch；
//   · 反向：真删掉 lock 的 version 字段必须判红（防空转恒绿）；
//   · 静态：脚本不得再出现固定缩进正则，且必须用 JSON.parse（附反例自证）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync, existsSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readVersions, findMismatches } from '../../scripts/version-sync.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPT_SRC = readFileSync(join(REPO, 'scripts', 'version-sync.mjs'), 'utf8');
const COPIED_FILES = [
  'package.json',
  'src-tauri/tauri.conf.json',
  'src-tauri/Cargo.toml',
  'src-tauri/Cargo.lock',
  '.claude-plugin/plugin.json',
  'server/package.json',
  'package-lock.json',
  'server/package-lock.json',
];
const LOCK_FILES = ['package-lock.json', 'server/package-lock.json'];

function makeRoot() {
  const root = mkdtempSync(join(tmpdir(), 'vs-indent-'));
  for (const f of COPIED_FILES) {
    const src = join(REPO, f);
    const dest = join(root, f);
    mkdirSync(dirname(dest), { recursive: true });
    if (existsSync(src)) writeFileSync(dest, readFileSync(src, 'utf8'), 'utf8');
  }
  return root;
}

/** 把真实 lock 重排成 1 空格缩进（结构不变，只改排版）——PR #28 的形态。 */
function oneSpaceJson(orig) {
  return `${JSON.stringify(JSON.parse(orig), null, 1)}\n`;
}

test('D294-1) 1 空格缩进的两个 lock 仍须读出全部版本、0 mismatch（真实文件副本）', () => {
  const root = makeRoot();
  try {
    for (const f of LOCK_FILES) {
      writeFileSync(join(root, f), oneSpaceJson(readFileSync(join(REPO, f), 'utf8')), 'utf8');
    }
    const entries = readVersions(root);
    assert.equal(entries.length, 10, '目标清单应覆盖 10 处版本副本');
    const unread = entries.filter((e) => !e.version);
    assert.deepEqual(unread.map((e) => e.label), [],
      `合法 1 空格 lock 不得被读成「未找到版本号字段」：${unread.map((e) => e.label).join(', ')}`);
    assert.deepEqual(findMismatches(entries), [], '缩进差异不得造成版本号误判');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('D294-2) 反向自证：真删掉 lock 顶层和 packages[""] 的 version 必须判红', () => {
  const root = makeRoot();
  try {
    for (const f of LOCK_FILES) {
      const obj = JSON.parse(readFileSync(join(REPO, f), 'utf8'));
      delete obj.version;
      if (obj.packages?.['']) delete obj.packages[''].version;
      writeFileSync(join(root, f), `${JSON.stringify(obj, null, 1)}\n`, 'utf8');
    }
    const mismatches = findMismatches(readVersions(root));
    assert.ok(mismatches.length >= 4,
      `删掉两份 lock 的 4 个 version 副本后必须判红（实际 ${mismatches.length} 条）：${JSON.stringify(mismatches)}`);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

/** 静态判据：结构解析 + 不得残留固定缩进正则。可对任意源码片段复用（反例自证用）。 */
function assertStructureBased(src) {
  assert.ok(src.includes('JSON.parse'), '版本号读取未使用 JSON 结构解析');
  assert.ok(!src.includes(String.raw`/^\s{2}"version"\s*:\s*"`),
    '仍残留固定 2 空格缩进的顶层 version 正则（D294 前的缺陷形态）');
  assert.ok(!src.includes(String.raw`/^\s{6}"version"\s*:\s*"`),
    '仍残留固定 6 空格缩进的 packages[""] version 正则');
}

test('D294-3) 脚本源码必须结构解析且无缩进耦合', () => {
  assertStructureBased(SCRIPT_SRC);
});

test('D294-4) 静态判据反例自证：喂回旧形态片段必须被判红', () => {
  const legacy = String.raw`
const pickTop = (text) => { const m = text.match(/^\s{2}"version"\s*:\s*"([^"]+)"/m); return m ? m[1] : null; };
const pickRoot = (text) => { const m = text.match(/^\s{6}"version"\s*:\s*"([^"]+)"/m); return m ? m[1] : null; };
`;
  assert.throws(() => assertStructureBased(legacy),
    '旧形态（固定缩进正则、无 JSON.parse）必须被静态判据抓红，否则守卫空转');
});
