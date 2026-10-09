// ============================================================================
// server/tests/orphanScripts.guard.test.js —— 「脚本写了但没人能发现」守卫
//
// 为什么必须有：
//   `e2e/**` 与 `scripts/**` 下的可执行脚本，只有出现在 ci.yml / package.json /
//   e2e/run-all.mjs / scripts/ci-local.mjs / 当前文档 / 别的代码里，才会被人（或机器）
//   再跑第二次。写出来时它是排障现场，接线断了它就变成**静默的死码**：
//   不红、不被引用、也没人知道它还能不能用。
//   2026-10-09 普查实测：197 个候选里 **45 个零引用**（一次性 diag/probe 38 个 +
//   还在用但没登记的 7 个），其中 `scripts/verify-tamper-breakage.mjs` 的断言已被
//   `ntlmAuth.test.js` 全部覆盖、自身在本机 OpenSSL 下还必红（des-ecb 不可用）。
//
// 口径（刻意严格，别照着"看起来提过一次"就放宽）：
//   ① **CHANGELOG.md / TODO.md / AUDIT-SEC-2026.md 不算接线** —— 它们是追加式历史，
//      提一次只代表"当时说过"，不代表现在还有人跑。把它们当接线，等于让守卫
//      在每一次写完战报后自动放行一个死脚本。
//   ② 匹配用 **token 边界**（按非标识符字符切词后比整词），不用子串 ——
//      子串会让 `tamper` 命中 `tamper-live`、`diag` 命中几十个名字。
//   ③ 代码文件的**注释行不参与**取词（注释里提名字不叫接线），文档/配置全文参与。
//      注意 `.md` 的 `#` 是标题不是注释 ⇒ 注释剥离只对代码扩展名开。
//   ④ **自引用不算接线** —— 必须存在除它以外的源。脚本在自己的用法串/日志 tag 里
//      打自己名字太常见，不排除的话任何孤儿都能把自己接上线（实测抓到一例）。
//   ⑤ **守卫自己也不当接线源**（④ 的推广，且是本文件第一次红的真因）：
//      `git add` 之前独立跑 5/5 绿，`git add` 之后在全量套件里红 —— 文件里的测试样本名
//      会由本文件贡献成 token，等于自己造样本、自己坐实。见下方 SELF。
//
// 判据三向（缺一即假绿）：
//   覆盖：每个候选要么被引用，要么进 violations（violations 必须为空）；
//   不空转：候选数 / 接线源数 / token 数各有分母下限，防止分类正则失效后恒绿；
//   自证：先钉住取词语义（吃 import、不吃注释）+ 正向对照（已知接线脚本必须非孤儿）
//        + 反向对照（人造零引用名字必须被抓出来）。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const NUL = String.fromCharCode(0);
/**
 * 本文件自己的仓库内路径。**守卫不得作为自己判据的接线源** ——
 * 2026-10-09 实测：`git add` 之前本文件独立跑 5/5 绿，`git add` 之后在全量套件里红，
 * 红的是反向对照那条：文件里的字面量 `zz-not-a-real-script-9001` 变成了**本文件贡献的 token**，
 * 于是这条测试亲手把"零引用样本"接上了线。正向对照那四个真名字同理会被自我坐实。
 */
const SELF = path.relative(REPO, fileURLToPath(import.meta.url)).split(path.sep).join('/');

/** 追加式历史：提及 ≠ 接线。 */
const HISTORY_FILES = new Set(['CHANGELOG.md', 'TODO.md', 'AUDIT-SEC-2026.md']);
const TEXT_EXT = /\.(mjs|cjs|js|ts|tsx|py|sh|ps1|yml|yaml|json|md|html|toml|ini|txt)$/;
const CODE_EXT = /\.(mjs|cjs|js|ts|tsx|py|sh)$/;

function isWiringSource(f) {
  if (f === SELF) return false; // 见 SELF 上方注释：守卫不能给自己管的对象接线
  if (HISTORY_FILES.has(f)) return false;
  if (!TEXT_EXT.test(f)) return false;
  if (f === 'package-lock.json') return false;
  if (f === 'package.json') return true;
  if (/^(docs|\.github|src-tauri|e2e|scripts|server|src)\//.test(f)) return true;
  return /^(README|SECURITY|CONTRIBUTING|action\.yml|Dockerfile|docker-compose|\.dockerignore|vite|vitest|eslint|tsconfig|sea-config)/.test(f);
}

/** 被管对象：e2e 与 scripts 下的可执行脚本（单测另有 ciWiring 守卫）。 */
function isManagedScript(f) {
  if (!/^(e2e|scripts)\//.test(f)) return false;
  if (/\.(mjs|cjs|js|py)$/.test(f) === false) return false;
  if (/\.test\.(mjs|js)$/.test(f)) return false;
  if (/(^|\/)(results|out|fixtures|node_modules|__pycache__)(\/|$)/.test(f)) return false;
  return true;
}

const stemOf = (f) => path.basename(f).replace(/\.[^.]+$/, '');

/** 从一行文本取词并归一（整词、路径尾段、去扩展名三种形态都进集合）。 */
function tokensFromLine(line) {
  const out = [];
  for (const raw of line.split(/[^A-Za-z0-9_.$/\-]+/)) {
    const tok = raw.replace(/^['"`(]+|['"`),;]+$/g, '');
    if (!tok) continue;
    out.push(tok);
    const base = tok.split('/').pop();
    out.push(base);
    const stem = base.replace(/\.[^.]+$/, '');
    if (stem) out.push(stem);
  }
  return out;
}

/** 一个文本里可算作"接线"的全部 token。 */
function collectTokens(text, isCode) {
  const set = new Set();
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    // 注释行不算接线；但只对代码开这个分支（md 的 `#` 是标题）
    if (isCode && (line.startsWith('//') || line.startsWith('#') || line.startsWith('*') || line.startsWith('/*'))) continue;
    for (const t of tokensFromLine(line)) set.add(t);
  }
  return set;
}

let tracked = [];
let gitSkip = false;
try {
  tracked = execFileSync('git', ['-C', REPO, 'ls-files', '-z'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
    .split(NUL)
    .filter(Boolean);
} catch (e) {
  // 显式 skip，不静默通过：拿不到文件清单时这条判据什么都判不了。
  gitSkip = 'git ls-files 不可用：' + (e && e.message ? e.message : String(e));
}

function scan() {
  // token → 贡献该 token 的接线源（记两个不同的就够了：≥2 个源说明它不是自引用）
  const owners = new Map();
  const add = (tok, src) => {
    const cur = owners.get(tok);
    if (!cur) owners.set(tok, [src]);
    else if (cur[0] !== src && cur.length < 2) cur.push(src);
  };
  let wiringFiles = 0;
  for (const f of tracked) {
    if (!isWiringSource(f)) continue;
    const abs = path.join(REPO, f);
    let st;
    try {
      st = statSync(abs);
    } catch {
      continue;
    }
    if (!st.isFile() || st.size > 3 * 1024 * 1024) continue;
    let text;
    try {
      text = readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    if (text.includes(NUL)) continue; // 二进制
    wiringFiles++;
    for (const t of collectTokens(text, CODE_EXT.test(f))) add(t, f);
  }
  const candidates = tracked.filter(isManagedScript);
  const orphans = candidates.filter((f) => !isWired(f, owners));
  return { owners, wiringFiles, candidates, orphans };
}

/**
 * 接线判定。**自引用不算接线**：脚本在自己的日志 tag / 用法串里提到自己的名字
 * 太常见（2026-10-09 实测 `scripts/probe-blob-400.mjs` 就是靠 `'User-Agent': 'probe-blob-400'`
 * 一行把自己接上线的）。必须存在**除它以外**的源。
 */
function isWired(f, owners) {
  const src = owners.get(stemOf(f));
  if (!src || src.length === 0) return false;
  if (src.length > 1) return true;
  return src[0] !== f;
}

test('自证①：取词吃静态 import 与文档反引号，但不吃代码注释', () => {
  const js = collectTokens(
    ["import x from './foo.js';", '// node scripts/bar.mjs', '  // 见 probe-baz.mjs'].join('\n'),
    true
  );
  assert.ok(js.has('foo'), 'import 的 ./foo.js 必须产成 foo/foo.js token');
  assert.ok(js.has('foo.js'));
  assert.ok(!js.has('bar'), '注释里的 scripts/bar.mjs 不算接线');
  assert.ok(!js.has('bar.mjs'));
  assert.ok(!js.has('probe-baz'));

  // 文档里的 `#` 是标题不是注释：整行都要参与取词
  const md = collectTokens('# 用法\n`node e2e/demo/tamper-sweep.mjs`', false);
  assert.ok(md.has('tamper-sweep'), '文档反引号里的脚本名必须算接线');
});

test('自证②：分母 —— 分类正则失效时不许退化成恒绿', () => {
  const { owners, wiringFiles, candidates } = scan();
  assert.ok(candidates.length >= 120, `候选脚本只剩 ${candidates.length} 个，isManagedScript 可能已失效`);
  assert.ok(wiringFiles >= 400, `接线源只剩 ${wiringFiles} 个，isWiringSource 可能已失效`);
  assert.ok(owners.size >= 10000, `token 只剩 ${owners.size} 个，取词逻辑可能已坏`);
});

test('自证③：正向对照 —— 已知接线的脚本必须判为非孤儿', () => {
  const { owners } = scan();
  for (const f of ['scripts/arch-guard.mjs', 'e2e/run-all.mjs', 'e2e/waf-real/tamper-sweep.mjs', 'e2e/waf-real/crs-equivalence.mjs']) {
    assert.ok(isWired(f, owners), `${f} 明明被 package.json/ci.yml 调着，却被判零引用 ⇒ 判据不可信`);
  }
});

test('自证④：反向对照 —— 零引用与"只被自己引用"都必须被抓住', () => {
  const { owners } = scan();
  // ① 谁都没提的名字
  assert.equal(isWired('scripts/zz-not-a-real-script-9001.mjs', owners), false);
  // ② 只有一个源，且那个源就是它自己 → 自引用，不算接线
  const selfOnly = new Map([['self-wired', ['scripts/self-wired.mjs']]]);
  assert.equal(isWired('scripts/self-wired.mjs', selfOnly), false, '脚本在自己的日志 tag 里打自己名字，不能算接线');
  // ③ 有一个别处的真源 → 算接线
  const byOther = new Map([['self-wired', ['docs/how-to.md']]]);
  assert.equal(isWired('scripts/self-wired.mjs', byOther), true);
});

test('零引用的可执行脚本必须为 0（要么接线，要么写进 e2e/README.md 的本地工具表）', { skip: gitSkip }, () => {
  const { orphans, candidates } = scan();
  assert.equal(
    orphans.length,
    0,
    `发现 ${orphans.length}/${candidates.length} 个脚本在 ci.yml / package.json / run-all.mjs / ci-local.mjs / 当前文档 / 代码 import 里都不出现（历史文件 CHANGELOG/TODO 的提及不算接线）。` +
      `进 CI：加进 .github/workflows/ci.yml + scripts/ci-local.mjs（两处都要，见 ciWiring.guard.test.js）或 e2e/run-all.mjs 的 LABS；` +
      `只作本地手动复跑：在 e2e/README.md「本地手动探针」表里写清用途与依赖，并在 ci.yml/package.json 之外被引用一次即可（该表本身就是接线源）。\n` +
      orphans.map((f) => '  - ' + f).join('\n')
  );
});
