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
import { readFileSync } from 'node:fs';
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

/**
 * 从 eslint.config.js 的**源码文本**里静态读出全局 `ignores` 数组。
 *
 * [D40 2026-10-11] 为什么不再 `import()` 根配置：
 *   CI 的 `test-server` job 只做 `cd server && npm ci`，而 root 专属依赖（`@eslint/js`、
 *   `typescript-eslint`、`eslint-plugin-react-hooks`、`globals`）**一个都没装** ⇒
 *   从 server 侧 import 根 `eslint.config.js` 必然 `ERR_MODULE_NOT_FOUND`
 *   ⇒ 本文件 ①②③ 三条在 CI 上**恒红**（run #200/#201/#202 实测），本机却因 root
 *   `node_modules` 存在而恒绿 —— **判据的采集面与校验面不一致**（本仓老病，同族：
 *   facts 的"工作区 vs checkout"、continue-on-error 空转 job）。
 *   更根本的是：本文件顶部注释已写明这条守卫「**不是真跑 eslint**」，而 `import()`
 *   恰恰把配置真跑了一遍 —— 实现越过了判据。改文本解析后两者对齐。
 *
 * 解析规则：**先跳注释再取字符串字面量**（`//` 与 `/* *\/`）。
 * ⚠️ 不能简单地"按行剥 //"—— `'node_modules/**'` 这类条目本身含 `//`，会被误伤。
 * ⚠️ 本仓纪律：判据的文本源必须排除注释（D21 的教训 —— 注释里的反面示例被当成真分支）。
 *
 * @param {string} src eslint.config.js 全文
 * @returns {string[]} ignores 条目
 */
function extractIgnores(src) {
  const key = src.indexOf('ignores: [');
  assert.ok(key >= 0, 'eslint.config.js 里找不到 `ignores: [` —— 配置结构变了，本守卫的读取方式要跟着改');
  const out = [];
  let depth = 0;
  let i = src.indexOf('[', key);
  while (i < src.length) {
    const ch = src[i];
    if (ch === "'" || ch === '"' || ch === '`') {
      let j = i + 1;
      let buf = '';
      while (j < src.length && src[j] !== ch) {
        if (src[j] === '\\') { buf += src[j + 1] ?? ''; j += 2; continue; }
        buf += src[j];
        j += 1;
      }
      out.push(buf);
      i = j + 1;
      continue;
    }
    if (ch === '/' && src[i + 1] === '/') {
      const nl = src.indexOf('\n', i);
      i = nl < 0 ? src.length : nl;
      continue;
    }
    if (ch === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      i = end < 0 ? src.length : end + 2;
      continue;
    }
    if (ch === '[') depth += 1;
    if (ch === ']') {
      depth -= 1;
      if (depth === 0) break;
    }
    i += 1;
  }
  return out;
}

function loadIgnores() {
  const cfgPath = fileURLToPath(new URL('../../eslint.config.js', import.meta.url));
  const ign = extractIgnores(readFileSync(cfgPath, 'utf8'));
  assert.ok(ign.length >= 15, `只读到 ${ign.length} 条 ignores —— 配置结构变了，本守卫的读取方式要跟着改`);
  // 静态解析的边界：模板串/变量拼出的条目读不到真值 ⇒ 必须显式报，不许静默漏读
  const dynamic = ign.filter((s) => s.includes('${'));
  assert.deepEqual(dynamic, [], `ignores 里出现模板串 ⇒ 静态解析读不到真值，必须改回真值读取：${dynamic.join(', ')}`);
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

test('① 入库代码文件不得被 lint 静默忽略（除显式登记的一份清单）', { skip: gitSkip }, () => {
  const ignores = loadIgnores();
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

test('② 显式登记的每一条理由都必须还成立（防清单变成僵尸豁免）', { skip: gitSkip }, () => {
  const ignores = loadIgnores();
  for (const a of ALLOWED_IGNORED) {
    assert.ok(trackedCode.includes(a.file), `清单里的 ${a.file} 已不在库，该把这条豁免一起删掉`);
    assert.ok(
      isIgnoredBy(a.file, ignores),
      `清单说 ${a.file} 被忽略，但当前 ignores 没命中它 —— 理由与配置已经分叉`
    );
    assert.ok(a.reason && a.reason.length >= 8, `${a.file} 的豁免理由没写清`);
  }
});

test('③ 本机排障现场必须继续被排除（lint 的红绿不许取决于磁盘上躺着什么）', { skip: gitSkip }, () => {
  const ignores = loadIgnores();
  const mustIgnore = [
    '.box-agent-scratch/**',
    '.workbuddy/**',
    '.mock/**',
    '.acl-recovery/**',
    'e2e/diag/**',
    '.tmp-*',
    // [D187] 靶场检出目录（第三方源码 + venv，不入库）：不排除会让 lint 依赖本机拉起了哪些靶场
    '.verify-labs/**',
  ];
  const missing = mustIgnore.filter((p) => !ignores.includes(p));
  assert.deepEqual(
    missing,
    [],
    `eslint.config.js 少了这几条本机现场排除：${missing.join(', ')} —— ` +
      `这些目录 gitignore 已排除、内容随机器变化，被 lint 吃进去就会让门禁结果依赖本机磁盘`
  );
});
