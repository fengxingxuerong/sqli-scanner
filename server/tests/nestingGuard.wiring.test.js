// ============================================================================
// tests/nestingGuard.wiring.test.js —— 嵌套深度门禁必须真的接上（2026-10-05）
//
// ── 本仓的核心纪律 ───────────────────────────────────────────────────────────
// 「一个没被任何东西执行的判据就是装饰」。本仓已经吃过两次亏：
//   · CI 里两个 job 指向**不存在的** run.js，且带 continue-on-error: true
//     ⇒ 每次 Cannot find module 却从不拦人，那两个 job 从未验证过任何东西；
//   · 版本号三处一致写好了门禁却只挂在 hook 上，CI 不跑 ⇒ 桌面安装包与 npm 包
//     版本对不上无人发现。
// 所以每加一道门禁，必须同时加**接线守卫**：断言它出现在 CI / pre-commit /
// ci-local / check:all 里。缺了就等于没加。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readCode } from './_srcScan.mjs';
import { readFileSync } from 'node:fs';

const repo = (p) => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8');

// parseRunBodies：抽出 CI yaml 里每个 `- run:` 的命令体。
// 必须容错：`steps:` 下的是 `      - run: xxx`（带短横前缀），不是顶格 `run:`。
const RUN_RE = /^([ \t]*)(?:-[ \t]+)*run:[ \t]*(\|[-+]?)?[ \t]*(.*)$/;
function parseRunBodies(yaml) {
  const out = [];
  const lines = yaml.split(/\r?\n/);
  let base = -1, body = [];
  for (const raw of lines) {
    const line = raw.replace(/\s+#.*$/, ''); // 去掉行尾注释
    if (/^\s*#/.test(line) || !line.trim()) continue; // 整行注释
    const m = line.match(RUN_RE);
    if (m) {
      if (base >= 0) out.push(body.join('\n'));
      base = m[1].length;
      body = [m[3]];
      if (!m[2]) out.push(body.join('\n')), (base = -1), (body = []);
      continue;
    }
    if (base >= 0 && line.length > base && /^\s+\S/.test(line)) body.push(line.slice(base));
  }
  if (base >= 0) out.push(body.join('\n'));
  return out;
}

test('接线-1) CI workflow 必须执行 nesting-guard（检查 + 自证各一步）', () => {
  const yaml = repo('.github/workflows/ci.yml');
  const runs = parseRunBodies(yaml);
  assert.ok(runs.length > 0, '解析不到任何 run 步骤 —— 解析器本身有问题，先自证');

  const check = runs.filter((r) => /nesting-guard\.mjs\s*$/.test(r.trim()));
  const self = runs.filter((r) => /nesting-guard\.mjs\s+--selftest\s*$/.test(r.trim()));
  assert.equal(check.length, 1, `CI 应恰好有 1 步执行 nestng-guard 检查，实际 ${check.length} 步`);
  assert.equal(self.length, 1, 'CI 必须同时跑 --selftest（钉住"判据不空转"），否则门禁可能整条失效而无人察觉');
});

test('接线-2) pre-commit 必须包含嵌套深度门禁', () => {
  const hook = repo('.husky/pre-commit');
  assert.match(hook, /run_gate\s+"嵌套深度[^"]*"\s+node\s+scripts\/nesting-guard\.mjs/,
    'pre-commit 里应有一条 run_gate 调用 nesting-guard');
});

test('接线-3) ci-local 清单必须包含嵌套深度门禁（自证 + 检查）', () => {
  const src = repo('scripts/ci-local.mjs');
  assert.match(src, /nesting-guard\.mjs\s+--selftest/, 'ci-local 应含 selftest 项');
  assert.match(src, /cmd:\s*'node scripts\/nesting-guard\.mjs'/, 'ci-local 应含检查项');
});

test('接线-4) package.json 提供可单独调用的脚本，且 check:all 串入检查', () => {
  const pkg = JSON.parse(repo('package.json'));
  assert.equal(pkg.scripts['nesting:guard'], 'node scripts/nesting-guard.mjs');
  assert.equal(pkg.scripts['nesting:selftest'], 'node scripts/nesting-guard.mjs --selftest');
  assert.equal(pkg.scripts['nesting:baseline'], 'node scripts/nesting-guard.mjs --fix-baseline');
  assert.ok(pkg.scripts['check:all'].includes('nesting:guard'),
    'check:all 必须串入 nesting:guard，否则本地全量校验漏掉这道门');
  assert.ok(pkg.scripts['check:all'].includes('nesting:selftest'),
    'check:all 也应含 selftest（与 release:check:selftest 的既有做法一致）');
});

// check:all 里漏了 selftest 那条在接线-4 里断言了；补一条让意图显式：
test('接线-5) check:all 串入 selftest（判据自证不得只在 CI 跑一次）', () => {
  const pkg = JSON.parse(repo('package.json'));
  // 上一条已断言；此处把"为什么"写清楚，避免后人以为冗余而删掉其中一处。
  assert.match(pkg.scripts['check:all'], /nesting:selftest/);
});

// ── 门禁脚本本身的形态守卫 ─────────────────────────────────────────────────
test('形态-6) 脚本不得在 import 时执行 CLI（否则 analyzeNesting 无法被测试导入）', () => {
  // scripts/ 在**仓库根**，不在 server/ 下（这处路径写错过一次，值得写清楚）
  const code = readCode(new URL('../../scripts/nesting-guard.mjs', import.meta.url));
  assert.ok(
    /isMain[\s\S]*process\.exit\(main\(\)\)/.test(code),
    '应先判断是否被直接执行再跑 CLI —— 无条件 process.exit(main()) 会让 import 杀掉测试进程'
  );
  assert.ok(
    !/^process\.exit\(main\(\)\);/m.test(code),
    '存在无条件的顶层 process.exit(main())，模块无法被安全 import'
  );
});

test('形态-7) 基线文件存在且结构合法（门禁不得因基线缺失而空转）', () => {
  const b = JSON.parse(repo('docs/_nesting-baseline.json'));
  assert.ok(b && typeof b === 'object', '基线应为对象');
  assert.ok(b.files && typeof b.files === 'object', '基线应含 files 字段');
  const entries = Object.entries(b.files);
  assert.ok(entries.length > 0, '基线不应为空（存量确有 ≥7 层的文件）');
  for (const [f, d] of entries) {
    assert.equal(typeof d, 'number', `${f} 的基线层级应为数字`);
    assert.ok(d >= 7, `${f} 基线 ${d} < 软上限 7，收进基线无意义`);
  }
  // 基线里的文件必须真实存在（否则基线会腐烂成永不生效的死名单）
  for (const f of entries.map(([f]) => f)) {
    assert.doesNotThrow(() => readFileSync(new URL(`../../${f}`, import.meta.url), 'utf8'),
      `基线文件 ${f} 不存在 —— 基线已腐烂`);
  }
});

test('形态-8) 基线里的每项都应被当前仓库"测到"（防基线虚高：手工填大值骗过门禁）', async () => {
  const b = JSON.parse(repo('docs/_nesting-baseline.json'));
  const { analyzeNesting } = await import('../../scripts/nesting-guard.mjs');
  // ⚠️ 这里必须用**原始文件内容**（readFileSync），不能用 readCode（剥注释）：
  //   analyzeNesting 内部已经逐字符跳过注释了，再剥一遍是双重处理 ——
  //   本测试最初就踩了这个坑：生成基线读原文件、校验基线读剥注释版，
  //   于是 injection.js 出现"基线 7 / 实测 5"的假矛盾，排查绕了一圈。
  //   口径必须与 scripts/nesting-guard.mjs 的 measureAll 完全一致。
  let checked = 0;
  for (const [f, d] of Object.entries(b.files)) {
    const actual = analyzeNesting(readFileSync(new URL(`../../${f}`, import.meta.url), 'utf8')).max;
    assert.ok(actual >= d,
      `${f}：基线记 ${d} 层，实际只有 ${actual} 层 —— 基线虚高（手工改大可永久豁免任何加深）`);
    checked++;
  }
  assert.ok(checked > 0, '应至少校验一项');
});