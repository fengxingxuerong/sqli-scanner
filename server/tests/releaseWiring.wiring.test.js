// ============================================================================
// tests/releaseWiring.wiring.test.js —— 发布门禁必须真的接在发布路径上
// ============================================================================
// 本仓最反复的一格：**判据写好了，却没有任何东西保证它被执行**。已登记在案的形态：
//   · ci.yml 两个 job 引用不存在的入口 + continue-on-error ⇒ 那两个 job 从未验证过任何东西；
//   · `verify-dialect-templates.mjs` 文档写"退出码 0 = 全通过"，三天没进过任何清单。
//
// 对**发布**门禁，这条尤其要紧：它与 CI 门禁不同——CI 只管这一版代码自洽，
// 而发布门禁管的是"将要发出去的东西对不对得上"。一个从未被执行的发布门禁，
// 在出事之前不会有任何症状；出事时它已经错过了唯一的拦截时机。
//
// ── 本文件钉什么 ─────────────────────────────────────────────────────────────
//   ① release-check 真的接在 package:mac / package:win 之前（唯一的发布入口）；
//   ② package.json / ci.yml 都登记了它，且 ci.yml 跑了 --selftest；
//   ③ 判据对合成分支有反应（真跑一次 selftest，不靠源码文本匹配蒙混）；
//   ④ compose 的 HOST 不是 127.0.0.1（本轮实测出的缺陷，判据必须挡住它）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPT = 'scripts/release-check.mjs';
const pkg = JSON.parse(readFileSync(join(REPO, 'package.json'), 'utf8'));
const ciYml = readFileSync(join(REPO, '.github/workflows/ci.yml'), 'utf8');
const scriptSrc = readFileSync(join(REPO, SCRIPT), 'utf8');

/** 与 versionSync/preCommitGates 同款的「只认 run 指令体」解析（注释假绿防护） */
function collectRunBodies(yaml) {
  const lines = yaml.split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^([ \t]*)(?:-[ \t]+)*run:[ \t]*(\|[-+]?)?[ \t]*(.*)$/.exec(lines[i]);
    if (!m) continue;
    if (m[3]) { out.push(m[3].replace(/\s+#.*$/, '')); continue; }
    const body = [];
    let j = i + 1;
    for (; j < lines.length; j++) {
      const line = lines[j];
      if (!line.trim()) continue;
      const ind = (line.match(/^[ \t]*/)[0]).length;
      if (ind <= m[1].length) break;
      if (!/^\s*#/.test(line)) body.push(line.trim());
    }
    out.push(body.join('\n'));
    i = j - 1;
  }
  return out;
}

test('接线-1) 打包入口真的先跑 release:check（唯一发布路径）', () => {
  for (const s of ['package:mac', 'package:win']) {
    assert.ok(pkg.scripts[s], `package.json 缺脚本 ${s}`);
    assert.ok(/release:check/.test(pkg.scripts[s]),
      `${s} 未先跑 release:check —— 发布门禁没接在打包之前，等于不存在`);
    // 必须是**在最前面**：否则前面的步骤失败会掩盖发布门禁，让它看起来"跑了"。
    assert.ok(pkg.scripts[s].trim().startsWith('npm run release:check'),
      `${s} 里 release:check 不在最前面：${pkg.scripts[s].trim().slice(0, 60)}…`);
  }
});

test('接线-2) package.json 与 ci.yml 都登记了它，且 ci.yml 跑了 selftest', () => {
  assert.ok(pkg.scripts['release:check'], 'package.json 缺 release:check');
  assert.ok(/release-check\.mjs/.test(pkg.scripts['release:check']), 'release:check 未指向脚本');
  const bodies = collectRunBodies(ciYml);
  assert.ok(bodies.some((b) => b.includes('release-check.mjs --selftest')),
    'ci.yml 未执行 release-check.mjs --selftest —— 判据空转无从暴露');
});

test('接线-3) 判据对合成分支真有反应（真跑，不靠文本匹配）', () => {
  const r = spawnSync(process.execPath, [join(REPO, SCRIPT), '--selftest'], {
    cwd: REPO, encoding: 'utf8',
  });
  assert.equal(r.status, 0, `release-check --selftest 失败：\n${r.stdout}\n${r.stderr}`);
  // 至少要有 8 条判据自证（本轮实测 9 条）—— 条数太少说明覆盖面被悄悄削了
  const n = (r.stdout.match(/selftest:/g) || []).length;
  assert.ok(n >= 8, `selftest 只自证了 ${n} 条判据，覆盖面可能被削减`);
});

test('接线-4) compose 的 HOST 不得为 127.0.0.1（本轮实测缺陷的回归防护）', () => {
  const compose = readFileSync(join(REPO, 'docker-compose.yml'), 'utf8');
  const m = compose.match(/^\s*-\s*HOST=(\S+)\s*$/m);
  assert.ok(m, 'docker-compose.yml 未显式设置 HOST');
  assert.notEqual(m[1], '127.0.0.1',
    'compose 的 HOST 回退成 127.0.0.1：引擎只绑回环 ⇒ 端口映射不可达，' +
    '而容器内 healthcheck 照常通过 ⇒ 会报 healthy 但外部访问不到');
  assert.equal(m[1], '0.0.0.0', `compose HOST 应为 0.0.0.0，实际 ${m[1]}`);
});

test('接线-5) 对外暴露面仍由 ports 绑定 + token 控制（不能只顾修 HOST 而放松边界）', () => {
  const compose = readFileSync(join(REPO, 'docker-compose.yml'), 'utf8');
  // 修 HOST 的正确做法是**收紧宿主侧**，不是把引擎也放开
  assert.ok(/ports:[\s\S]*?127\.0\.0\.1:4567:4567/.test(compose),
    'compose 的 ports 未绑定 127.0.0.1 —— 修 HOST 时误把暴露面放开了');
  assert.ok(/SCAN_API_TOKEN=\$\{SCAN_API_TOKEN:/.test(compose),
    'compose 撤掉了 SCAN_API_TOKEN 的 fail-closed 约束（${VAR:?}）');
});

test('接线-6) 判据复用了 version-sync 的实现（不得复制一份）', () => {
  assert.ok(/from '\.\/version-sync\.mjs'/.test(scriptSrc),
    'release-check 未复用 version-sync 的判据 —— 两份版本判据必然漂移');
});
