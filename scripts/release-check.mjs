#!/usr/bin/env node
// ============================================================================
// release-check.mjs —— 发布/打包前的**一致性**门禁
//
// ── 它管什么、不管什么 ────────────────────────────────────────────────────────
// 管：**发出去的东西对不对得上**（版本号、脏工作区、tag 与版本的关系）。
// 不管：编译能不能过、测试过不过 —— 那些由 pre-commit / CI 负责。
// 两者不可互相替代：CI 绿只说明"这一版代码自洽"，不说明"将要发布的产物是对的"。
//
// ── 为什么值得单独一道 ────────────────────────────────────────────────────────
// 本仓已经因为「同一个事实多份副本、缺一道互校」吃过三次亏：
//   · docs/_facts.json ↔ README 的测试数漂移（facts-sync 门禁）
//   · 入库 e2e 报告不是当前代码跑出来的（artifact-drift 门禁）
//   · Cargo.toml 的版本号孤悬 1.0.0（version-sync 门禁，本轮修复）
// 发布是这些事实**同时对外**的时刻，故在发布入口再收一次口。
//
// 具体拦什么：
//   ① 版本号三处一致（复用 version-sync 的判据，避免两套实现漂移）；
//   ② 工作区干净：脏工作区意味着「源码 ≠ 将被打进包的内容」，发出去的版本不可复现；
//   ③ 当前 tag（若存在）与 package.json 版本对应 —— tag 是发布产物唯一标识，
//      版本号与 tag 对不上时，下游按 tag 拉到的代码与自己以为的版本不是一回事。
//   ④ npm 端 @tauri-apps/* 与 src-tauri 的 Rust crate 必须同 major/minor 线 ——
//      tauri build 只在打包**末尾**才验这项，不一致要等几分钟编译后才炸；而根因
//      （npm 用 ^ 范围漂移、Rust 锁 Cargo.lock）在改动当天就存在，CI 又不构建 Tauri
//      ⇒ 提前到发布入口拦。D77 实测过一次：api 漂到 2.12.2 / crate 锁 2.11.5。
//      判据取数刻意用**两个 lock 文件**（package-lock.json / Cargo.lock，均已入库）：
//      fresh clone 没有 node_modules 也能查，且与 tauri build 自己读的是同一份事实。
//
// ── 用法 ─────────────────────────────────────────────────────────────────────
//   node scripts/release-check.mjs            # 检查（有问题退出码 1）
//   node scripts/release-check.mjs --allow-dirty  # 明确允许脏工作区（本地试打包用）
//   node scripts/release-check.mjs --selftest     # 自证判据非空转
// ============================================================================
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { findMismatches, readVersions } from './version-sync.mjs';

const ROOT = process.cwd();
const argv = process.argv.slice(2);

/** 跑一条 git 命令拿输出（失败返回 null，不抛） */
function git(...args) {
  const r = spawnSync('git', args, { cwd: ROOT, encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}

/** 列出工作区里未提交的改动（已暂存 + 未暂存 + 未跟踪） */
function dirtyPaths() {
  const out = git('status', '--porcelain') ?? '';
  return out.split(/\r?\n/).filter(Boolean).map((l) => l.slice(3).trim());
}

// ── 判据本体（拆出来以便 selftest 注入样本） ──────────────────────────────────
/**
 * @param {{versions: object[], dirty: string[], tag: string|null, pkgVersion: string|null,
 *          isRepo: boolean, allowDirty: boolean}} s
 * @returns {{level:'error'|'warn', msg:string}[]}
 */
export function judge(s) {
  const problems = [];

  // ① 版本号三处一致（判据来自 version-sync.mjs，不复制一份）
  const mism = findMismatches(s.versions);
  if (mism.length) {
    problems.push({
      level: 'error',
      msg: `版本号不一致（${mism.length} 处）：` +
        mism.map((m) => `${m.label} — ${m.detail}`).join('；'),
    });
  }

  // ② 工作区必须干净（脏 ⇒ 打包内容 ≠ 已提交内容，不可复现）
  if (!s.allowDirty && s.dirty.length) {
    const show = s.dirty.slice(0, 8).join(', ') + (s.dirty.length > 8 ? ` …共 ${s.dirty.length} 项` : '');
    problems.push({
      level: 'error',
      msg: `工作区有 ${s.dirty.length} 处未提交改动：${show}。\n` +
        '    打包会把当前磁盘内容发出去，而它与 git 记录不一致 ⇒ 产物不可复现、无法追溯。\n' +
        '    请先提交（或 stash），确需在脏状态下试打包请加 --allow-dirty。',
    });
  }

  // ③ tag ↔ 版本：仅在处于某 tag 上时核对（不在 tag 上属正常开发态，不报）
  if (s.tag && s.pkgVersion) {
    const tagVer = s.tag.replace(/^v/, '');
    if (tagVer !== s.pkgVersion) {
      problems.push({
        level: 'error',
        msg: `当前 HEAD 处于 tag ${s.tag}（版本 ${tagVer}），但 package.json 是 ${s.pkgVersion}。\n` +
          '    下游按 tag 拉取会拿到与版本号不符的代码。用 `npm run version:fix` 对齐后再发布。',
      });
    }
  }

  // ④ 提示而非拦截：不在任何 tag 上、却有未提交改动之外的情况（如 detached HEAD）
  if (s.isRepo && !s.tag) {
    problems.push({ level: 'warn', msg: '当前不在任何 tag 上（开发态）。发布前请打 tag 并与版本号一致。' });
  }

  return problems;
}

// ── 容器/部署配置的静态核对（无需 docker） ───────────────────────────────────
/**
 * compose 里 HOST 必须是 0.0.0.0，否则端口映射不可达。
 * 依据：server/index.js 是 `app.listen(PORT, HOST)`，HOST 写 127.0.0.1 等于只绑 lo；
 * 而 Docker 端口映射靠 DNAT 把流量送到容器 eth0 地址，收不到只听 lo 的 socket。
 * 隐蔽处：容器内 healthcheck 走 127.0.0.1 照常通过 ⇒ compose healthy 但外部访问不到。
 * 对外暴露面由 `ports` 的宿主绑定 + SCAN_API_TOKEN 控制，与 HOST 无关。
 */
export function checkComposeHost(text) {
  // 只认 environment 段里的 HOST=，避免命中注释里出现的 "HOST=127.0.0.1" 说明文字
  const m = text.match(/^\s*-\s*HOST=(\S+)\s*$/m);
  if (!m) return { level: 'warn', msg: 'docker-compose.yml 未显式设置 HOST（将回落到镜像默认 0.0.0.0）' };
  if (m[1] === '127.0.0.1' || m[1] === 'localhost') {
    return {
      level: 'error',
      msg: `docker-compose.yml 里 HOST=${m[1]} 会让引擎只绑回环，端口映射的流量到不了该 socket` +
        '（且容器内 healthcheck 走回环照常通过 ⇒ 会报 healthy 但外部不可达）。请改 HOST=0.0.0.0；' +
        '对外暴露面由 ports 的宿主绑定与 SCAN_API_TOKEN 控制。',
    };
  }
  if (m[1] !== '0.0.0.0') return { level: 'warn', msg: `compose HOST=${m[1]} 非预期值（应为 0.0.0.0）` };
  return null;
}

// ── npm ↔ Rust crate 版本线判据（拆出来以便 selftest 注入样本） ───────────────
/**
 * 同线判定只认 **major.minor**：tauri 的 patch 号在 npm 与 crate 两侧不同步
 * （实测 @tauri-apps/api 2.11 线最高 2.11.1，而 tauri crate 在 2.11.5）。
 * 任一侧读不到版本 ⇒ 报 error（parser 失效时宁可红，不许静默通过——
 * 与 artifact-drift「一个文件都没检查就不返回通过」同一条纪律）。
 * @param {Array<{npm:string, crate:string, npmVer:string|null, crateVer:string|null}>} pairs
 * @returns {{level:'error'|'warn', msg:string}[]}
 */
function judgeTauriLines(pairs) {
  const problems = [];
  const drift = [];
  const unknown = [];
  for (const p of pairs) {
    if (!p.npmVer || !p.crateVer) {
      unknown.push(`${p.npm}↔${p.crate}（npm=${p.npmVer ?? '读不到'} / crate=${p.crateVer ?? '读不到'}）`);
      continue;
    }
    const line = (v) => v.split('.').slice(0, 2).join('.');
    if (line(p.npmVer) !== line(p.crateVer)) {
      drift.push(`${p.npm}@${p.npmVer} ↔ crate ${p.crate}@${p.crateVer}`);
    }
  }
  if (unknown.length) {
    problems.push({
      level: 'error',
      msg: `读不到以下 npm↔crate 版本，判据失效（不许静默通过）：${unknown.join('；')}。\n` +
        '    package-lock.json 缺对应条目，或 Cargo.lock 结构变了 ⇒ 修采集，不是放行。',
    });
  }
  if (drift.length) {
    problems.push({
      level: 'error',
      msg: `Tauri npm 包与 Rust crate 不同线（${drift.length} 对）：${drift.join('；')}。\n` +
        '    tauri build 会在打包末尾才拦这项；根因多半是 npm 端 ^ 范围漂移。\n' +
        '    对齐方向：把 npm 端收敛到 crate 线（~ 范围），或更新 Cargo.lock 后重编。',
    });
  }
  return problems;
}

/** npm 包名 ↔ src-tauri 里的 crate 名（tauri build 自己的对拍表同源） */
const TAURI_LINE_PAIRS = [
  { npm: '@tauri-apps/api', crate: 'tauri' },
  { npm: '@tauri-apps/plugin-dialog', crate: 'tauri-plugin-dialog' },
  { npm: '@tauri-apps/plugin-fs', crate: 'tauri-plugin-fs' },
];

/**
 * 从 Cargo.lock 文本取指定 crate 的 version（块级精确匹配，近似名不命中）。
 * 只认 `[[package]]` 块内的 `name = "x"` + `version = "y"`；依赖数组里的裸字符串
 * （`dependencies = ["tauri-runtime"]`）不构成 `name = ` 行，天然不会误命中。
 * @param {string} lockText
 * @param {string} crateName
 * @returns {string|null}
 */
function cargoCrateVersion(lockText, crateName) {
  for (const block of String(lockText).split('[[package]]')) {
    const name = /^\s*name\s*=\s*"([^"]+)"/m.exec(block);
    if (!name || name[1] !== crateName) continue;
    const ver = /^\s*version\s*=\s*"([^"]+)"/m.exec(block);
    return ver ? ver[1] : null;
  }
  return null;
}

/**
 * 从 package-lock.json 取 npm 包的实际安装版本（取 lock 而非 node_modules：
 * fresh clone 无 node_modules 也能查，且 tauri build 读的就是这份事实）。
 * @param {string} lockText
 * @param {string} npmPkg
 * @returns {string|null}
 */
function npmLockVersion(lockText, npmPkg) {
  try {
    const lock = JSON.parse(lockText);
    return lock.packages?.[`node_modules/${npmPkg}`]?.version ?? null;
  } catch {
    return null;
  }
}

/**
 * 采集 npm↔crate 版本对（从两个 lock 文件文本；任一侧空文本 ⇒ null，
 * 由 judgeTauriLines 报「判据失效」而不是静默通过）。
 * @param {string} lockText package-lock.json 文本
 * @param {string} cargoText Cargo.lock 文本
 * @returns {Array<{npm:string, crate:string, npmVer:string|null, crateVer:string|null}>}
 */
function collectTauriPairs(lockText, cargoText) {
  return TAURI_LINE_PAIRS.map((p) => ({
    ...p,
    npmVer: lockText ? npmLockVersion(lockText, p.npm) : null,
    crateVer: cargoText ? cargoCrateVersion(cargoText, p.crate) : null,
  }));
}

/**
 * Tauri 版本线段（④）：从两个 lock 文件采集 → 打印 → 判定。
 * 单独成函数而非塞进 main：main 已近复杂度软上限，且「读文件/打印/判定」
 * 是与版本三处核对、脏工作区并列的一道独立判据，本就该有自己的名字。
 * @param {string} root 仓库根
 * @returns {{level:'error'|'warn', msg:string}[]}
 */
function checkTauriLines(root) {
  const readIf = (p) => {
    const abs = path.join(root, p);
    return fs.existsSync(abs) ? fs.readFileSync(abs, 'utf8') : '';
  };
  const pairs = collectTauriPairs(readIf('package-lock.json'), readIf('src-tauri/Cargo.lock'));
  for (const p of pairs) {
    console.log(`  · Tauri 线 ${`${p.npm} ↔ ${p.crate}`.padEnd(42)} ${p.npmVer ?? '?'} ↔ ${p.crateVer ?? '?'}`);
  }
  return judgeTauriLines(pairs);
}

function selftest() {
  const clean = { versions: [
    { label: 'package.json', version: '1.1.0' },
    { label: 'src-tauri/tauri.conf.json', version: '1.1.0' },
    { label: 'src-tauri/Cargo.toml', version: '1.1.0' },
  ], dirty: [], tag: 'v1.1.0', pkgVersion: '1.1.0', isRepo: true, allowDirty: false };

  const cases = [
    { name: '干净且 tag 与版本一致 ⇒ 无 error', s: clean, wantErr: 0 },
    { name: '版本不一致 ⇒ 必须报 error', s: { ...clean, versions: [
      { label: 'package.json', version: '1.1.0' },
      { label: 'src-tauri/tauri.conf.json', version: '1.1.0' },
      { label: 'src-tauri/Cargo.toml', version: '1.0.0' },
    ] }, wantErr: 1 },
    { name: '脏工作区 ⇒ 必须报 error', s: { ...clean, dirty: ['src/a.js'] }, wantErr: 1 },
    { name: '--allow-dirty 时脏工作区不再报 error', s: { ...clean, dirty: ['src/a.js'], allowDirty: true }, wantErr: 0 },
    { name: 'tag 与版本不一致 ⇒ 必须报 error', s: { ...clean, tag: 'v1.0.0' }, wantErr: 1 },
    { name: '不在 tag 上 ⇒ 只 warn 不 error', s: { ...clean, tag: null }, wantErr: 0 },
  ];

  let failed = 0;
  for (const c of cases) {
    const got = judge(c.s).filter((p) => p.level === 'error').length;
    const ok = got === c.wantErr;
    if (!ok) failed++;
    console.log(`${ok ? '✔' : '✖'} selftest: ${c.name}（期望 error ${c.wantErr}，实际 ${got}）`);
  }

  // compose HOST 判据同样要自证——否则它只是一段没人验证过的推理。
  const composeCases = [
    { name: 'compose HOST=0.0.0.0 ⇒ 通过', text: '    environment:\n      - HOST=0.0.0.0\n', wantErr: false },
    { name: 'compose HOST=127.0.0.1 ⇒ 必须报错（实测过的缺陷形态）',
      text: '    environment:\n      - HOST=127.0.0.1\n', wantErr: true },
    { name: 'HOST 只出现在注释里 ⇒ 不得误判为已设置', text: '    # 曾写 HOST=127.0.0.1，现已修\n', wantErr: false },
  ];
  for (const c of composeCases) {
    const r = checkComposeHost(c.text);
    const got = r?.level === 'error';
    const ok = got === c.wantErr;
    if (!ok) failed++;
    console.log(`${ok ? '✔' : '✖'} selftest: ${c.name}（期望 error ${c.wantErr}，实际 ${got}）`);
  }

  // Tauri 版本线判据自证（D77 实测过的漂移形态：crate 2.11.5 ↔ npm 2.12.2）
  const mkPairs = (npmVer, crateVer) => TAURI_LINE_PAIRS.map((p) => ({ ...p, npmVer, crateVer }));
  const tauriCases = [
    { name: '同 minor 线（patch 不同也放行：npm 2.11.1 ↔ crate 2.11.5）⇒ 无 error',
      pairs: mkPairs('2.11.1', '2.11.5'), wantErr: 0 },
    { name: 'npm 漂到下一 minor（2.12.2 ↔ crate 2.11.5，D77 实测形态）⇒ 报 error',
      pairs: mkPairs('2.12.2', '2.11.5'), wantErr: 1 },
    { name: '任一侧版本读不到 ⇒ 报 error（判据失效不许静默通过）',
      pairs: mkPairs(null, '2.11.5'), wantErr: 1 },
    { name: 'crate 侧读不到 ⇒ 报 error', pairs: mkPairs('2.11.1', undefined), wantErr: 1 },
  ];
  for (const c of tauriCases) {
    const got = judgeTauriLines(c.pairs).filter((p) => p.level === 'error').length;
    const ok = got === c.wantErr;
    if (!ok) failed++;
    console.log(`${ok ? '✔' : '✖'} selftest: Tauri 线 ${c.name}（期望 error ${c.wantErr}，实际 ${got}）`);
  }

  // Cargo.lock 采集器自证：从真实格式的文本里取指定 crate 的版本，
  // 取错块/取不到都会让判据失真 —— 这里钉住「取对块、拒绝近似名」。
  const fakeLock = [
    '[[package]]', 'name = "tauri-plugin-dialog"', 'version = "2.7.3"', '',
    '[[package]]', 'name = "tauri"', 'version = "2.11.5"',
    'dependencies = [', ' "tauri-runtime",', ']', '',
    '[[package]]', 'name = "tauri-plugin-fs"', 'version = "2.5.2"', '',
  ].join('\n');
  const cg = [
    { name: 'Cargo.lock 取 crate 版本（真实格式）', crate: 'tauri', want: '2.11.5' },
    { name: '取另一个 crate 不串块', crate: 'tauri-plugin-dialog', want: '2.7.3' },
    { name: '近似名不得命中（tauri-plugin-fs ≠ tauri-plugin）', crate: 'tauri-plugin', want: null },
    { name: '不存在的 crate 返回 null', crate: 'wry', want: null },
  ];
  for (const c of cg) {
    const got = cargoCrateVersion(fakeLock, c.crate);
    const ok = got === c.want;
    if (!ok) failed++;
    console.log(`${ok ? '✔' : '✖'} selftest: ${c.name}（期望 ${c.want}，实际 ${got}）`);
  }

  if (failed) {
    console.error(`\nrelease-check selftest 失败：${failed} 条判据对合成样本无反应`);
    process.exit(1);
  }
  console.log('\nrelease-check selftest 全部通过（判据非空转）');
}

// ── 主流程 ────────────────────────────────────────────────────────────────────
function main() {
  if (argv.includes('--selftest')) return selftest();

  const isRepo = git('rev-parse', '--git-dir') !== null;
  const pkgPath = path.join(ROOT, 'package.json');
  const pkgVersion = fs.existsSync(pkgPath)
    ? (JSON.parse(fs.readFileSync(pkgPath, 'utf8')).version ?? null)
    : null;
  const tag = git('describe', '--tags', '--exact-match');
  const dirty = dirtyPaths();

  const versions = readVersions();
  const problems = judge({
    versions, dirty, tag, pkgVersion, isRepo,
    allowDirty: argv.includes('--allow-dirty'),
  });

  console.log('发布前一致性检查：');
  console.log(`  · package.json 版本        ${pkgVersion ?? '(读取失败)'}`);
  console.log(`  · 当前 tag                ${tag ?? '(无，开发态)'}`);
  console.log(`  · 未提交改动              ${dirty.length} 处`);
  for (const e of versions) console.log(`  · ${e.label.padEnd(26)} ${e.version ?? '(读取失败)'}`);

  // ④ npm ↔ crate 同线（两个 lock 文件采集；fresh clone 无 node_modules 也能查）
  problems.push(...checkTauriLines(ROOT));

  const errors = problems.filter((p) => p.level === 'error');
  const warns = problems.filter((p) => p.level === 'warn');

  // 容器/部署配置核对（与 git 状态无关，即使脏工作区也照查）
  const composePath = path.join(ROOT, 'docker-compose.yml');
  if (fs.existsSync(composePath)) {
    const r = checkComposeHost(fs.readFileSync(composePath, 'utf8'));
    if (r?.level === 'error') errors.push(r);
    else if (r?.level === 'warn') warns.push(r);
  }

  if (warns.length) {
    console.log('');
    for (const w of warns) console.log(`⚠️  ${w.msg}`);
  }

  if (errors.length) {
    console.error('');
    for (const e of errors) console.error(`❌ ${e.msg}`);
    console.error('\n发布已阻止。修完后重跑 `npm run release:check`。');
    process.exit(1);
  }

  console.log('\n✔ 发布前一致性检查通过（注意：这只核对一致性，不替代 CI 与测试）');
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('release-check.mjs')) {
  main();
}
