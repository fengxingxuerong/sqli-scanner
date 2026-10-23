#!/usr/bin/env node
// ============================================================================
// version-sync.mjs —— 版本号一致性门禁
//
// ── 要防的是什么 ─────────────────────────────────────────────────────────────
// 本项目的版本号手工维护在**七个文件、九处**里（D140 起）：
//   · package.json                        （npm / GitHub Action / 文档）
//   · src-tauri/tauri.conf.json           （Tauri 壳 + 安装包元数据）
//   · src-tauri/Cargo.toml                （Rust crate）
//   · src-tauri/Cargo.lock                （Rust 锁文件里**本仓包自己**的条目；D140 起纳入）
//   · server/package.json                 （引擎子包；D127 起纳入，此前长期停在 1.1.0）
//   · package-lock.json                   （根锁文件顶层 version）
//   · server/package-lock.json            （引擎锁文件顶层 version）
//   两个 npm lock 文件各还有第二份副本 `packages[""].version`，一并纳入。
//   形状完全一致的三次教训：README 测试数、e2e 基线、版本号——同一个事实多份副本，缺一道互校。
//
// 实测（2026-10-05）：前两者是 1.1.0，**Cargo.toml 孤悬 1.0.0**。
// 实测（2026-10-23，D127 补）：server/package.json 与两个 lock 文件仍停在 1.1.0，
// 而根 package.json 已是 1.1.1 —— 旧判据只看三处，看不见这三份副本。
// 实测（2026-10-23，D140 补）：`tauri build` 才把 Cargo.lock 里本仓包条目从 1.1.1 改成 1.2.0
// —— 亦即 D127 的 8 处互校仍漏了它，不真跑 cargo 就永远发现不了。
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
  {
    // 引擎子包：`npm run server` / Dockerfile 里的 `npm --prefix server ci` 都读它，
    // 与根包长期不同步（D127 实测 1.1.0 vs 1.1.1）——旧判据看不见。
    file: path.join('server', 'package.json'),
    label: 'server/package.json',
    pick: (text) => {
      const m = text.match(/^\s{2}"version"\s*:\s*"([^"]+)"/m);
      return m ? m[1] : null;
    },
    replace: (text, v) => text.replace(/^(\s{2}"version"\s*:\s*)"[^"]+"/m, `$1"${v}"`),
  },
  {
    // 锁文件顶层 version：`npm ci` 用它，也是 `npm ls` 报版本的来源之一。
    file: 'package-lock.json',
    label: 'package-lock.json',
    pick: (text) => {
      const m = text.match(/^\s{2}"version"\s*:\s*"([^"]+)"/m);
      return m ? m[1] : null;
    },
    replace: (text, v) => text.replace(/^(\s{2}"version"\s*:\s*)"[^"]+"/m, `$1"${v}"`),
  },
  {
    // 同一个 lock 里的第二份副本：packages[""].version（6 空格缩进，其余嵌套版本都在 10+ 空格）。
    file: 'package-lock.json',
    label: 'package-lock.json#packages[""]',
    pick: (text) => {
      const m = text.match(/^\s{6}"version"\s*:\s*"([^"]+)"/m);
      return m ? m[1] : null;
    },
    replace: (text, v) => text.replace(/^(\s{6}"version"\s*:\s*)"[^"]+"/m, `$1"${v}"`),
  },
  {
    file: path.join('server', 'package-lock.json'),
    label: 'server/package-lock.json',
    pick: (text) => {
      const m = text.match(/^\s{2}"version"\s*:\s*"([^"]+)"/m);
      return m ? m[1] : null;
    },
    replace: (text, v) => text.replace(/^(\s{2}"version"\s*:\s*)"[^"]+"/m, `$1"${v}"`),
  },
  {
    file: path.join('server', 'package-lock.json'),
    label: 'server/package-lock.json#packages[""]',
    pick: (text) => {
      const m = text.match(/^\s{6}"version"\s*:\s*"([^"]+)"/m);
      return m ? m[1] : null;
    },
    replace: (text, v) => text.replace(/^(\s{6}"version"\s*:\s*)"[^"]+"/m, `$1"${v}"`),
  },
  {
    // [D140 2026-10-23] Rust 锁文件里**本仓包自己**的版本条目。
    // 由来：D139 跑 `tauri build --no-bundle` 时 cargo 把这里从 1.1.1 改写成 1.2.0 ——
    // 也就是说 D127 的 8 处互校漏了它，**版本号在这一处一直是旧的**，只有真跑 cargo 才暴露。
    // 形状与 D127 那次完全一致：同一个事实又多一份副本，缺一道互校。
    file: path.join('src-tauri', 'Cargo.lock'),
    label: 'src-tauri/Cargo.lock（本仓包）',
    pick: (text) => {
      const m = text.match(/\nname = "sqli-scanner"\r?\nversion = "([^"]+)"/);
      return m ? m[1] : null;
    },
    replace: (text, v) =>
      text.replace(/(\nname = "sqli-scanner"\r?\nversion = )"[^"]+"/, `$1"${v}"`),
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
      // D127 新增判据必须自证：子包与锁文件的三份副本落后时也得红，
      // 否则「扩了覆盖面」只是嘴上说说（旧判据正是漏了这三处）。
      { name: 'D127 子包 + 两个 lock 副本落后 ⇒ 必须报出 3 条', entries: [
        { label: 'package.json', version: '1.2.0' },
        { label: 'src-tauri/tauri.conf.json', version: '1.2.0' },
        { label: 'src-tauri/Cargo.toml', version: '1.2.0' },
        { label: 'server/package.json', version: '1.1.0' },
        { label: 'package-lock.json', version: '1.1.0' },
        { label: 'package-lock.json#packages[""]', version: '1.1.0' },
      ], expect: 3 },
      // D140 新增判据必须自证：Rust 锁文件里本仓包的版本条目落后时也得红
      //（D139 实测：`tauri build` 才把它从 1.1.1 改成 1.2.0，说明此前 8 处互校漏了它）。
      { name: 'D140 Cargo.lock 本仓包条目落后 ⇒ 必须报出 1 条', entries: [
        { label: 'package.json', version: '1.2.0' },
        { label: 'src-tauri/tauri.conf.json', version: '1.2.0' },
        { label: 'src-tauri/Cargo.toml', version: '1.2.0' },
        { label: 'src-tauri/Cargo.lock（本仓包）', version: '1.1.1' },
      ], expect: 1 },
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
    console.error('\n修法：改齐全部位置，或执行 `npm run version:fix` 以 package.json 为基准同步。');
    console.error('（桌面安装包版本来自 tauri.conf.json / Cargo.toml；Docker/子包安装读 server/package.json；`npm ci` 读两个 lock —— 任一处不一致都会让交付物对不上版本号。）');
    process.exit(1);
  }

  console.log(`\n✔ 版本号全部一致（${entries.length} 处）`);
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('version-sync.mjs')) {
  main();
}