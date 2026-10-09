// ============================================================================
// server/tests/lintScope.guard.test.js —— 守卫「lint 的作用域 = 仓库」
//
// 为什么必须有（2026-10-09 D25 实测）：`npm run lint` 是 CI 的门禁之一，但**没人验证过它
// 到底看了哪些文件**。实弹量了一次（`npx eslint . --format json` 与 `git ls-files` 做差）：
//   · 入库代码文件 1094 个，eslint 处理 1128 个；
//   · 静默漏检 1 个：`src/vite-env.d.ts`（被 `**/*.d.ts` 吞掉 —— 这条是合理的，
//     声明文件无可 lint，但要**显式登记**而不是靠一条通配符悄悄吞）；
//   · 多管 35 个：**根本没入库**的排障现场 —— `.box-agent-scratch/**`（含旧副本
//     ScanManager.orig.js、`*.new.js`）、`.workbuddy/tmp/**`、`.mock/**`、`.acl-recovery/**`。
//     后果不是"多扫了不相干文件"这么轻：门禁红绿会取决于本机磁盘上恰好躺着什么。
//     实测一开 eslint:recommended，这堆旧副本立刻暴 5 处违规 —— 那既不是仓库的问题，
//     也不该由仓库修。
//
// 本仓对 lint ignore 有一条现成的教训（eslint.config.js 第 29–35 行，2026-09-19）：
//   当年为了躲子代理的 unused import 把 9 个文件/目录整块 ignore，结果**被挡住的正是门禁自己**
//   （`e2e/acceptance.mjs` 是验收总控，语法错都没人查）。那次是"往里加 ignore 躲报错"，
//   这次防的是反方向："ignore 吞掉入库文件" 与 "ignore 之外的现场被当成仓库"。
//   两个方向一起钉，才叫作用域等于仓库。
//
// 判据三向：
//   ① 不漏：每个入库代码文件都必须**不被任何 ignore 命中**，除了一份带理由的显式清单；
//   ② 不越界：eslint.config.js 必须仍然 ignore 掉那几个已知的本机现场目录（防止有人
//      "顺手删掉"这几条，让 lint 重新依赖本机垃圾）；
//   ③ 自证 + 分母：先钉住本文件那台极简 glob 匹配器的语义（`**` 可跨目录、`*` 不跨），
//      再钉扫描面规模 —— 匹配器写错时 ①② 都可能恒绿。
//
// 口径边界（诚实标注，别把它当成"lint 覆盖率的证明"）：
//   这条守卫是**静态读 eslint.config.js 的 ignores 与 git 索引比对**，不是真跑 eslint
//   （真跑一次要 3–4 分钟，放进 `cd server && npm test` 会把单测套件拖成十分钟级）。
//   完整实证命令写在上面的实测段里，改动配置时手动跑一次即可。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const NUL = String.fromCharCode(0);

// 允许被 lint 排除的入库代码文件 —— 逐条给理由，空集之外的每一个都要写清是什么。
const ALLOWED_IGNORED = [
  {
    file: 'src/vite-env.d.ts',
    reason: 'TS 声明文件（vite/client 引用 + ImportMetaEnv 类型），无语句可 lint',
  },
];

// 极简 glob 匹配器，语义对齐 eslint flat-config 的 ignores 用法：
//   斜杠+双星       命中该目录下任意深度
//   双星+斜杠+模式  命中任意目录（含根）下的该模式
//   根级星点 log    只命中根目录下的（eslint 的无前导斜杠模式相对配置目录）
//   中缀星号        星号不跨斜杠
// ⚠️ 这段刻意写成行注释：本会话里已经两次因为块注释里写了含"星杠"序列的
//    glob / tamper 字面量（`**/*.d.ts`、版本注释收尾符）而被提前闭合成语法错。
function globToRe(pattern) {
  let re = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        // `**/` —— 任意深度（含零层）
        if (pattern[i + 2] === '/') {
          re += '(?:[^/]+/)*';
          i += 2;
        } else {
          re += '.*';
          i += 1;
        }
      } else {
        re += '[^/]*';
      }
    } else if ('.+?^${}()|[]\\'.includes(c)) {
      re += '\\' + c;
    } else {
      re += c;
    }
  }
  return new RegExp('^' + re + '$');
}

const isIgnoredBy = (file, patterns) => patterns.some((p) => globToRe(p).test(file));

let trackedCode = [];
let gitSkip = false;
try {
  trackedCode = execFileSync('git', ['-C', REPO, 'ls-files', '-z'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
    .split(NUL)
    .filter((f) => /\.(js|mjs|cjs|ts|tsx)$/.test(f));
} catch (e) {
  gitSkip = 'git ls-files 不可用：' + (e && e.message ? e.message : String(e));
}

async function loadIgnores() {
  const modPath = new URL('../../eslint.config.js', import.meta.url).href;
  const cfg = (await import(modPath)).default;
  const blocks = Array.isArray(cfg) ? cfg : [cfg];
  const ign = blocks.flatMap((b) => (b && Array.isArray(b.ignores) ? b.ignores : []));
  assert.ok(ign.length >= 15, `只读到 ${ign.length} 条 ignores —— 配置结构变了，本守卫的读取方式要跟着改`);
  return ign;
}

test('自证：glob 匹配器语义（** 跨目录、* 不跨、无前导斜杠相对根）', () => {
  assert.ok(globToRe('node_modules/**').test('node_modules/a/b/c.js'));
  assert.ok(globToRe('e2e/diag/**').test('e2e/diag/diag.mjs'));
  assert.ok(!globToRe('e2e/diag/**').test('e2e/diag2/x.mjs'), '目录前缀不能靠子串蒙对');
  assert.ok(globToRe('**/*.d.ts').test('src/vite-env.d.ts'));
  assert.ok(globToRe('**/*.d.ts').test('a/b/c.d.ts'));
  assert.ok(globToRe('*.log').test('x.log'));
  assert.ok(!globToRe('*.log').test('logs/x.log'), '无前导 ** 的模式不该跨目录');
  assert.ok(globToRe('**/.tmp-*').test('a/.tmp-probe.mjs'));
  assert.ok(globToRe('kanban-check-*/**').test('kanban-check-2026-09-30/a.js'));
  assert.ok(globToRe('kanban-check-*/**').test('kanban-check-x/b/other.js'), '一层目录名之后的任意深度都该命中');
  assert.ok(!globToRe('kanban-check-*/**').test('kanban-x/a.js'), '目录名前缀不能靠子串蒙对');
});

test('① 入库代码文件不得被 lint 静默忽略（除显式登记的一份清单）', { skip: gitSkip }, async () => {
  const ignores = await loadIgnores();
  const swallowed = trackedCode.filter(
    (f) => isIgnoredBy(f, ignores) && !ALLOWED_IGNORED.some((a) => a.file === f)
  );
  assert.deepEqual(
    swallowed,
    [],
    `${swallowed.length} 个入库代码文件被 eslint ignores 命中，却不在显式清单里 —— ` +
      `门禁看不见这些文件（2026-09-19 那次 e2e/acceptance.mjs 被整块 ignore 就是这个形状）。` +
      `确实不该 lint 的话，加进 ALLOWED_IGNORED 并写理由，别加通配符。`
  );
  assert.ok(trackedCode.length >= 900, `入库代码文件只剩 ${trackedCode.length} 个，文件集采集可能已坏`);
});

test('② 显式登记的每一条理由都必须还成立（防清单变成僵尸豁免）', { skip: gitSkip }, async () => {
  const ignores = await loadIgnores();
  for (const a of ALLOWED_IGNORED) {
    assert.ok(trackedCode.includes(a.file), `清单里的 ${a.file} 已不在库，该把这条豁免一起删掉`);
    assert.ok(
      isIgnoredBy(a.file, ignores),
      `清单说 ${a.file} 被忽略，但当前 ignores 没命中它 —— 理由与配置已经分叉`
    );
    assert.ok(a.reason && a.reason.length >= 8, `${a.file} 的豁免理由没写清`);
  }
});

test('③ 本机排障现场必须继续被排除（lint 的红绿不许取决于磁盘上躺着什么）', { skip: gitSkip }, async () => {
  const ignores = await loadIgnores();
  const mustIgnore = [
    '.box-agent-scratch/**',
    '.workbuddy/**',
    '.mock/**',
    '.acl-recovery/**',
    'e2e/diag/**',
    '.tmp-*',
  ];
  const missing = mustIgnore.filter((p) => !ignores.includes(p));
  assert.deepEqual(
    missing,
    [],
    `eslint.config.js 少了这几条本机现场排除：${missing.join(', ')} —— ` +
      `这些目录 gitignore 已排除、内容随机器变化，被 lint 吃进去就会让门禁结果依赖本机磁盘`
  );
});
