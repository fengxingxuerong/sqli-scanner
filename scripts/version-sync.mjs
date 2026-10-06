#!/usr/bin/env node
// ============================================================================
// version-sync.mjs —— 版本号一致性门禁
//
// ── 要防的是什么 ─────────────────────────────────────────────────────────────
// 本项目的版本号手工维护在**三个文件**里：
//   · package.json            （npm / GitHub Action / 文档）
//   · src-tauri/tauri.conf.json（Tauri 壳 + 安装包元数据）
//   · src-tauri/Cargo.toml    （Rust crate）
//
// 实测（2026-10-05）：前两者是 1.1.0，**Cargo.toml 孤悬 1.0.0**。
// 后果不是"不好看"，而是**桌面安装包对外报的版本与 npm 包不一致**——
// 用户装到的壳比 Web 前端旧一个小版本，而没有任何地方提示。
//
// 为什么值得单独立一道门禁：本仓已经因为同类问题吃过两次亏
//   · facts-sync：README 抄的测试数与实际采集值漂移
//   · artifact-drift：入库 e2e 报告不是当前代码跑出来的
// 形状完全一致——**同一个事实存在多份副本，缺一道互校**。
// 版本号是全项目最常被引用、又最容易被遗忘的那个"事实"，理应被同等对待。
//
// ── 用法 ─────────────────────────────────────────────────────────────────────
//   node scripts/version-sync.mjs           # 检查（不一致则退出码 1）
//   node scripts/version-sync.mjs --fix     # 把 package.json 的版本同步到其余两处
//   node scripts/version-sync.mjs --selftest # 自证判据非空转（喂合成样本必须反应）
// ============================================================================
import fs from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();

const TARGETS = [
  {
    file: path.join('package.json'),
    label: 'package.json',
    pick: (text) => {
      // 只取顶层 version：正则限定在第一个 "version" 键，避免命中 dependencies 里的嵌套版本
      const m = text.match(/^\s{2}"version"\s*:\s*"([^"]+)"/m);
      return m ? m[1] : null;
    },
    replace: (text, v) => text.replace(/^(\s{2}"version"\s*:\s*)"[^"]+"/m, `$1"${v}"`),
  },
  {
    file: path.join('src-tauri', 'tauri.conf.json'),
    label: 'src-tauri/tauri.conf.json',
    pick: (text) => {
      const m = text.match(/^\s{2}"version"\s*:\s*"([^"]+)"/m);
      return m ? m[1] : null;
    },
    replace: (text, v) => text.replace(/^(\s{2}"version"\s*:\s*)"[^"]+"/m, `$1"${v}"`),
  },
  {
    file: path.join('src-tauri', 'Cargo.toml'),
    label: 'src-tauri/Cargo.toml',
    pick: (text) => {
      // Cargo 的 version 在 [package] 段；这里匹配行首 version = "..."
      const m = text.match(/^version\s*=\s*"([^"]+)"/m);
      return m ? m[1] : null;
    },
    replace: (text, v) => text.replace(/^version\s*=\s*"[^"]+"/m, `version = "${v}"`),
  },
];

/** 读取全部目标文件的版本。缺失文件 / 缺失键都算失败，不静默跳过。 */
export function readVersions(root = ROOT) {
  const out = [];
  for (const t of TARGETS) {
    const abs = path.join(root, t.file);
    if (!fs.existsSync(abs)) {
      out.push({ label: t.label, version: null, error: '文件不存在' });
      continue;
    }
    const text = fs.readFileSync(abs, 'utf8');
    const v = t.pick(text);
    out.push({ label: t.label, version: v, error: v ? null : '未找到版本号字段' });
  }
  return out;
}

/** 以 package.json 为唯一基准，返回不一致项。 */
export function findMismatches(entries) {
  const pkg = entries.find((e) => e.label === 'package.json');
  if (!pkg || !pkg.version) return [{ label: '(基准)', detail: 'package.json 版本不可读' }];
  return entries
    .filter((e) => e.label !== 'package.json' && e.version !== pkg.version)
    .map((e) => ({ label: e.label, detail: e.error || `期望 ${pkg.version}，实际 ${e.version}` }));
}

// ── 主流程 ────────────────────────────────────────────────────────────────────
function main() {
  const args = process.argv.slice(2);

  // 自证：判据必须对**合成的不一致样本**有反应，否则这道门禁形同虚设。
  // 这与本仓其它门禁的 --selftest 同一思路（见 module-loadable / merge-integrity）。
  if (args.includes('--selftest')) {
    const cases = [
      { name: '三处一致 ⇒ 无差异', entries: [
        { label: 'package.json', version: '1.1.0' },
        { label: 'src-tauri/tauri.conf.json', version: '1.1.0' },
        { label: 'src-tauri/Cargo.toml', version: '1.1.0' },
      ], expect: 0 },
      { name: 'Cargo 落后一个版本 ⇒ 必须报出', entries: [
        { label: 'package.json', version: '1.1.0' },
        { label: 'src-tauri/tauri.conf.json', version: '1.1.0' },
        { label: 'src-tauri/Cargo.toml', version: '1.0.0' },
      ], expect: 1 },
      { name: '两处都落后 ⇒ 必须报出 2 条', entries: [
        { label: 'package.json', version: '2.0.0' },
        { label: 'src-tauri/tauri.conf.json', version: '1.0.0' },
        { label: 'src-tauri/Cargo.toml', version: '1.0.0' },
      ], expect: 2 },
      { name: '缺版本字段 ⇒ 必须报出（不得静默跳过）', entries: [
        { label: 'package.json', version: '1.1.0' },
        { label: 'src-tauri/tauri.conf.json', version: null, error: '未找到版本号字段' },
        { label: 'src-tauri/Cargo.toml', version: null, error: '未找到版本号字段' },
      ], expect: 2 },
    ];
    let failed = 0;
    for (const c of cases) {
      const got = findMismatches(c.entries).length;
      const ok = got === c.expect;
      if (!ok) failed++;
      console.log(`${ok ? '✔' : '✖'} selftest: ${c.name}（期望 ${c.expect}，实际 ${got}）`);
    }
    if (failed) {
      console.error(`\nversion-sync selftest 失败：${failed} 条判据对合成样本无反应（判据可能空转）`);
      process.exit(1);
    }
    console.log('\nversion-sync selftest 全部通过（判据非空转）');
    return;
  }

  const entries = readVersions();
  const mismatches = findMismatches(entries);

  console.log('版本号一致性检查：');
  for (const e of entries) {
    console.log(`  · ${e.label.padEnd(30)} ${e.version ?? '(读取失败)'}${e.error ? ` — ${e.error}` : ''}`);
  }

  if (args.includes('--fix')) {
    const pkg = entries.find((e) => e.label === 'package.json');
    if (!pkg?.version) {
      console.error('\n--fix 失败：无法读取 package.json 的版本号（基准不可用时拒绝改写）');
      process.exit(1);
    }
    for (const t of TARGETS) {
      if (t.label === 'package.json') continue;
      const abs = path.join(ROOT, t.file);
      if (!fs.existsSync(abs)) continue;
      const text = fs.readFileSync(abs, 'utf8');
      const cur = t.pick(text);
      if (cur === pkg.version) continue;
      fs.writeFileSync(abs, t.replace(text, pkg.version), 'utf8');
      console.log(`  ✔ 已同步 ${t.label}: ${cur} → ${pkg.version}`);
    }
    console.log(`\n已按 package.json（${pkg.version}）同步其余目标`);
    return;
  }

  if (mismatches.length) {
    console.error(`\n✖ 版本号不一致（${mismatches.length} 处）：`);
    for (const m of mismatches) console.error(`  · ${m.label}: ${m.detail}`);
    console.error('\n修法：改齐三处，或执行 `npm run version:fix` 以 package.json 为基准同步。');
    console.error('（桌面安装包版本来自 tauri.conf.json / Cargo.toml，不一致会让交付给客户的壳对不上版本号。）');
    process.exit(1);
  }

  console.log('\n✔ 版本号三处一致');
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('version-sync.mjs')) {
  main();
}