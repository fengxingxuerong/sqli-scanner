// ============================================================================
// tests/versionSync.wiring.test.js —— 版本号门禁"接没接线"必须自己被查到
// ============================================================================
// 本仓反复栽在同一格：判据写好了，但没有任何东西保证它被**执行**。已登记在案的：
//   · `verify-dialect-templates.mjs` 文档写着"退出码 0 = 全通过"，三天没进过任何清单；
//   · CI job 引用不存在的入口 + `continue-on-error` ⇒ **该 job 从未验证过任何东西**；
//   · tamper 数量硬编码在四个地方，加一个插件漏改三个。
// 所以 `scripts/version-sync.mjs` 自己也要过这一关：package.json / ci.yml /
// check:all 三处接线少任何一处，它就只是"本地能手动跑的一个脚本"，而不是门禁。
//
// ⚠️ 本文件**不**用裸 `includes('version-sync')` 扫全文——ci.yml 的注释里恰好提到了
//   它（"复现：npm run version:check"），那会造出**假绿**。这正是
//   artifactDrift.wiring.test.js 开头记录的"注释假绿"教训，此处复用其做法：
//   只认**指令体**（run: 的值），不认注释。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPT = 'scripts/version-sync.mjs';
const scriptSrc = readFileSync(join(REPO, SCRIPT), 'utf8');
const pkg = JSON.parse(readFileSync(join(REPO, 'package.json'), 'utf8'));
const ciYml = readFileSync(join(REPO, '.github/workflows/ci.yml'), 'utf8');

/**
 * 从 ci.yml 抽出所有 `run:` 的**指令体**（不含 YAML 键名、不含注释）。
 * 逐行解析，块边界 = 缩进回退到 <= run 键本身的缩进。
 *
 * ⚠️ 两个必须记住的坑（都是本文件自证时当场踩到的，不是假想）：
 *   ① YAML 的 step 形态是 `      - run: node xxx.mjs` —— **行首是 `- ` 不是 `run:`**。
 *      只写 `/^([ \t]*)run:/` 会一条都匹配不到，判据于是恒假绿。
 *   ② 别用「run: 之后所有缩进行」的正则：注释也是缩进的，会被一路吃到。
 *      这正是 artifactDrift.wiring.test.js 记录的"注释假绿"教训。
 * 故正则允许 `- `（含多个连续 dash）前缀，并把该行剩余部分的缩进算作 run 键的缩进。
 */
function collectRunBodies(yaml) {
  const lines = yaml.split(/\r?\n/);
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    // 形如:  "      - run: node alpha.mjs"  或  "      - run: |"
    const m = /^([ \t]*)(?:-[ \t]+)*run:[ \t]*(\|[-+]?)?[ \t]*(.*)$/.exec(lines[i]);
    if (!m) continue;
    const indent = m[1].length;
    const inline = m[3];
    if (inline) {
      // 单行形态：`- run: node alpha.mjs`（行尾 `# ...` 注释保留无害，不影响 includes 判定）
      out.push(inline.replace(/\s+#.*$/, ''));
      continue;
    }
    // 块形态：`run: |` 之后缩进更深的内容
    const body = [];
    let j = i + 1;
    for (; j < lines.length; j++) {
      const line = lines[j];
      if (!line.trim()) continue; // 空行不终止块
      const ind = (line.match(/^[ \t]*/)[0]).length;
      if (ind <= indent) break;
      // 跳过块内的注释行（'#' 开头）——它们不是指令
      if (!/^\s*#/.test(line)) body.push(line.trim());
    }
    out.push(body.join('\n'));
    i = j - 1; // for 会再 ++i，从块后第一行继续
  }
  return out;
}

// 判据自证：解析器本身不能出错，否则上面所有断言都是空转。
// 喂一段**已知内容**的 YAML，必须能捞出全部 run 指令体，且不把注释捞进来。
test('守卫自证-0) 指令体解析器对已知样本必须捞全、且不误收注释', () => {
  const sample = [
    'jobs:',
    '  a:',
    '    steps:',
    '      - run: node alpha.mjs',
    '      # 注释里提到 node alpha.mjs，不该被捞成指令',
    '      - run: |',
    '        node beta.mjs',
    '        node gamma.mjs',
    '      - run: node delta.mjs   # 行尾注释',
  ].join('\n');
  const bodies = collectRunBodies(sample);
  const flat = bodies.join('\n');

  assert.ok(flat.includes('node alpha.mjs'), '应捞到单行 run');
  assert.ok(flat.includes('node beta.mjs'), '应捞到块内第一行');
  assert.ok(flat.includes('node gamma.mjs'), '应捞到块内第二行');
  assert.ok(flat.includes('node delta.mjs'), '应捞到后续单行 run（不因块而漏）');
  // 独立注释行不得被当成指令体
  const standaloneComment = bodies.filter((b) => b.includes('注释里提到'));
  assert.equal(standaloneComment.length, 0,
    '独立注释行被误收为指令体 —— 这会造成"注释假绿"');
});

const runBodies = collectRunBodies(ciYml);
const isRealCommand = (needle) => runBodies.some((b) => b.includes(needle));

test('接线-1) ci.yml 的指令体里真的执行了 version-sync（检查 + 自证）', () => {
  assert.ok(isRealCommand('version-sync.mjs'),
    'ci.yml 没有任何 run 指令真正执行 version-sync.mjs —— 它只是"本地能手动跑的脚本"');
  // 自证那一步同样必须在：只跑检查不跑 selftest，判据空转时无人知晓。
  assert.ok(isRealCommand('version-sync.mjs --selftest'),
    'ci.yml 未执行 version-sync.mjs --selftest —— 判据空转无从暴露');
});

test('接线-2) package.json 的脚本与 check:all 都登记了它', () => {
  assert.ok(pkg.scripts['version:check'], 'package.json 缺 version:check 脚本');
  assert.ok(pkg.scripts['version:fix'], 'package.json 缺 version:fix 脚本');
  assert.ok(pkg.scripts['version:check'].includes(SCRIPT), 'version:check 未指向 version-sync.mjs');
  assert.ok(
    pkg.scripts['check:all']?.includes('version:check'),
    'check:all 未纳入 version:check —— 本地聚合入口会漏掉这道门禁'
  );
});

test('接线-3) 脚本本身实现了 --selftest 且 selftest 真能抓出漂移', () => {
  assert.ok(/--selftest/.test(scriptSrc), 'version-sync.mjs 未实现 --selftest');
  // 真跑一次，确认它对合成样本有反应（判据非空转）
  const r = spawnSync(process.execPath, [join(REPO, SCRIPT), '--selftest'], {
    cwd: REPO, encoding: 'utf8',
  });
  assert.equal(r.status, 0, `version-sync --selftest 失败：\n${r.stdout}\n${r.stderr}`);
  assert.ok(/selftest/.test(r.stdout), 'selftest 应打印判据自证结果');
});

test('接线-4) 检查模式在当前仓库真的通过（避免留下一个永远红的门禁）', () => {
  const r = spawnSync(process.execPath, [join(REPO, SCRIPT)], { cwd: REPO, encoding: 'utf8' });
  assert.equal(r.status, 0,
    `version-sync 在当前仓库失败：\n${r.stdout}\n${r.stderr}\n` +
    '（若是真不一致，请改齐三处或跑 npm run version:fix）');
});

test('接线-5) 三个目标文件都在门禁覆盖范围内（新增版本来源会漏检吗）', () => {
  // 判据：从脚本里列出被登记的目标，必须覆盖当前真实存在的三个版本来源。
  // 若日后新增第四处（如 VSIX manifest），这里会提示补登记。
  for (const f of ['package.json', 'src-tauri/tauri.conf.json', 'src-tauri/Cargo.toml']) {
    assert.ok(scriptSrc.includes(f.replace(/\\/g, '\\\\')) || scriptSrc.includes(f),
      `version-sync.mjs 未覆盖版本来源 ${f}`);
  }
});