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
