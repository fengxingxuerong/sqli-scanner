// ============================================================================
// server/tests/ciWorkflows.guard.test.js —— [D149 2026-10-24] 全部 workflow 的结构门禁
//
// 为什么要有：仓库里已有 4 个 workflow（ci / codeql / …），而它们的**结构错误**只有 GitHub
// 才知道（push 上去才红，本地无从验证）。本机跑不了 Actions，但结构是纯静态可判的：
//   · 丢 `runs-on` · `needs:` 指向不存在的 job · 空步骤 / `uses`+`run` 同写
//   · 第三方 action 未钉版本 · 同一文件 job 重名（YAML 重复键报错）
// 这类「本地全绿、CI 红」正是本仓反复治理的形态。
//
// 判据分两层：
//   ① 有牙：对**合成的不合规样本**逐条必须报出（每条规则一个反例，避免判据空转）；
//   ② 真实：对仓库里每个 workflow 文件跑一遍，必须 0 问题。
// 解析用 devDependency `yaml`（与 repo 其它脚本一致），重复键按 `uniqueKeys` 判为错误。
// ============================================================================
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import YAML from 'yaml';
import { lintWorkflowDoc } from '../../scripts/lib/workflowLint.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const WF_DIR = path.join(REPO, '.github', 'workflows');

/** 递归收集 workflow 文件（含子目录） */
function listWorkflows(dir = WF_DIR, out = []) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) listWorkflows(full, out);
    else if (/\.ya?ml$/i.test(ent.name)) out.push(full);
  }
  return out.sort();
}

const FILES = listWorkflows();

/** 解析 + 结构体检；YAML 解析失败也算问题（返回原因，不让它静默通过） */
function lintFile(full) {
  const rel = path.relative(REPO, full).split(path.sep).join('/');
  const text = readFileSync(full, 'utf8');
  let doc;
  try {
    doc = YAML.parse(text, { uniqueKeys: true });
  } catch (e) {
    return [`${rel} —— YAML 解析失败：${e.message}`];
  }
  return lintWorkflowDoc({ doc, file: rel, text });
}

// ── ① 判据有牙：每条规则都要对合成样本有反应 ─────────────────────────────────
test('自证：缺 runs-on / needs 断链 / 空步骤 / uses+run / 未钉版本 都必须被点名', () => {
  const base = (jobs) => ({ doc: { permissions: { contents: 'read' }, jobs }, file: 'synthetic.yml' });
  // 合规 job 的公共前缀：带上 timeout-minutes（D150 起必填），让下面的反例只暴露它要测的那条
  const okJob = (extra = {}) => ({ 'runs-on': 'ubuntu-latest', 'timeout-minutes': 10, ...extra });
  const cases = [
    ['缺 runs-on', base({ a: { 'timeout-minutes': 10, steps: [{ uses: 'actions/checkout@v4' }] } }), /缺 runs-on/],
    [
      '缺 timeout-minutes（默认上限 360 分钟，挂住会烧满配额）',
      base({ a: { 'runs-on': 'ubuntu-latest', steps: [{ run: 'true' }] } }),
      /缺 timeout-minutes/,
    ],
    ['timeout-minutes 为 0（非法）', base({ a: okJob({ 'timeout-minutes': 0, steps: [{ run: 'true' }] }) }), /非法值/],
    ['timeout-minutes 超过 360（非法）', base({ a: okJob({ 'timeout-minutes': 400, steps: [{ run: 'true' }] }) }), /非法值/],
    ['needs 指向不存在的 job', base({ a: okJob({ needs: ['ghost'], steps: [{ run: 'true' }] }) }), /依赖的 job「ghost」不存在/],
    ['steps 为空', base({ a: okJob({ steps: [] }) }), /steps 为空/],
    ['空步骤（既无 uses 也无 run）', base({ a: okJob({ steps: [{ name: 'x' }] }) }), /既无 uses 也无 run/],
    ['uses 与 run 同写', base({ a: okJob({ steps: [{ uses: 'actions/checkout@v4', run: 'true' }] }) }), /uses 与 run 同时存在/],
    ['未钉版本的 action', base({ a: okJob({ steps: [{ uses: 'actions/checkout' }] }) }), /未钉版本/],
    [
      '条件性豁免缺 with.toolchain ⇒ 必须报（豁免不许退化成「随便不钉」）',
      base({ a: okJob({ steps: [{ uses: 'dtolnay/rust-toolchain@master' }] }) }),
      /缺 with\.toolchain/,
    ],
    ['可复用工作流 job 不该写 runs-on', base({ a: { uses: 'o/r/.github/workflows/x.yml@v1', 'runs-on': 'ubuntu-latest' } }), /不该写 runs-on/],
    ['没有 jobs', { doc: { permissions: { contents: 'read' }, on: 'push' }, file: 'synthetic.yml' }, /没有 jobs/],
    [
      '缺顶层 permissions ⇒ 必须报（权限不由代码决定就无法评审）',
      { doc: { jobs: { a: okJob({ steps: [{ run: 'true' }] }) } }, file: 'synthetic.yml' },
      /缺顶层 permissions/,
    ],
    [
      'permissions 形态非法 ⇒ 必须报',
      { doc: { permissions: 42, jobs: { a: okJob({ steps: [{ run: 'true' }] }) } }, file: 'synthetic.yml' },
      /形态非法/,
    ],
  ];
  for (const [label, input, re] of cases) {
    const problems = lintWorkflowDoc(input);
    assert.ok(problems.some((p) => re.test(p)), `${label}：判据没反应（拿到 ${JSON.stringify(problems)}）`);
  }
  // 合规样本必须 0 问题（否则判据过严，会逼人放宽）
  const ok = lintWorkflowDoc(base({ a: okJob({ steps: [{ uses: 'actions/checkout@v4' }, { run: 'echo hi' }] }) }));
  assert.deepEqual(ok, [], `合规样本不该报问题：${JSON.stringify(ok)}`);
  // 本地 action / docker:// 不算未钉版本；条件性豁免在**带 with.toolchain** 时放行
  const local = lintWorkflowDoc(base({ a: okJob({ steps: [{ uses: './' }, { uses: 'docker://alpine:3' }] }) }));
  assert.deepEqual(local, [], `本地/容器 action 不该报未钉版本：${JSON.stringify(local)}`);
  const waived = lintWorkflowDoc(
    base({ a: okJob({ steps: [{ uses: 'dtolnay/rust-toolchain@master', with: { toolchain: '1.98.0' } }] }) })
  );
  assert.deepEqual(waived, [], `带 with.toolchain 的条件性豁免应放行：${JSON.stringify(waived)}`);
});

test('自证：硬编码凭据必须被点名，且 secrets 表达式本身不算凭据', () => {
  const bad = lintWorkflowDoc({
    doc: { permissions: { contents: 'read' }, jobs: { a: { 'runs-on': 'ubuntu-latest', 'timeout-minutes': 5, steps: [{ run: 'echo ghp_abcdefghijklmnopqrstuvwx' }] } } },
    file: 'synthetic.yml',
    text: 'jobs:\n  a:\n    env:\n      TOKEN: ghp_abcdefghijklmnopqrstuvwx\n',
  });
  assert.ok(bad.some((p) => /疑似硬编码GitHub PAT/.test(p)), `硬编码 PAT 必须报出：${JSON.stringify(bad)}`);
  const good = lintWorkflowDoc({
    doc: { permissions: { contents: 'read' }, jobs: { a: { 'runs-on': 'ubuntu-latest', 'timeout-minutes': 5, steps: [{ run: 'echo ${{ secrets.X }}' }] } } },
    file: 'synthetic.yml',
    text: 'jobs:\n  a:\n    env:\n      TOKEN: ${{ secrets.SCAN_API_TOKEN }}\n',
  });
  assert.deepEqual(good, [], `secrets 表达式不该被当成硬编码凭据：${JSON.stringify(good)}`);
});

test('自证：YAML 重复 job 名必须解析失败（重名 job 会被静默覆盖）', () => {
  let failed = false;
  try {
    YAML.parse('jobs:\n  a:\n    runs-on: ubuntu-latest\n  a:\n    runs-on: ubuntu-latest\n', { uniqueKeys: true });
  } catch {
    failed = true;
  }
  assert.equal(failed, true, 'uniqueKeys 应让重复 job 名解析失败，否则重名会被静默吞掉');
});

// ── ② 真实：仓库里每个 workflow 都必须干净，且收集非空 ────────────────────────
test('仓库 workflow 收集非空（防空转：目录/扩展名口径变了要立刻红）', () => {
  assert.ok(FILES.length >= 2, `只收集到 ${FILES.length} 个 workflow 文件，收集口径可能坏了`);
});

test('每个 workflow 都必须是合法 YAML 且结构合规（runs-on / needs / steps / 版本钉）', () => {
  const all = FILES.flatMap((f) => lintFile(f));
  assert.deepEqual(all, [], `workflow 结构问题：\n${all.join('\n')}`);
});