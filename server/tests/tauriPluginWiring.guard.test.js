// ============================================================================
// server/tests/tauriPluginWiring.guard.test.js —— 守卫「桌面壳的 JS↔Rust 插件接线」
//
// 起因（2026-10-09，批次 D28，实测取证）：src/shared/tauriBridge.ts 用
//   const dialogSpec = '@tauri-apps/plugin-dialog';
//   const dialog = await import(dialogSpec);
//   await (dialog as any).save(...)
// 这种"变量形式动态导入 + as any"的组合，注释写的是"避免 Web 构建解析未安装的模块"。
// 代价是三层全是静默的：
//   ① 依赖表里根本没有这两个包（package.json / package-lock 都查无）⇒ 谁装依赖都不会带上它们；
//   ② Vite 不做静态分析 ⇒ 产物里留下运行时裸 import("@tauri-apps/plugin-dialog")，
//      在桌面壳里按 origin 解析 ⇒ 「导出报告」「导入请求文件」两条功能**发货即坏**；
//      实测旧 dist/assets/index-*.js 里确实逐字留着那条裸 import；
//   ③ TS 拿不到模块类型 ⇒ 只能 as any，插件改签名也不会报。
// 修好后（包入 dependencies + 字面量导入 + 去掉 3 处 as any）复跑构建：
//   产物里不再有裸 import，而 plugin:dialog / plugin:fs 的 IPC 名被真正打进了 chunk。
//
// 三条断言（缺一不可）：
//   ① 源码里出现的每一个 @tauri-apps/* 包名，必须在 package.json 的依赖里；
//   ② 依赖里每一个 @tauri-apps/plugin-*，必须在 Cargo.toml 有 crate、在 lib.rs 有 init()
//      —— 只装 JS 不注册 Rust = 运行时"命令不存在"，而那条路径上有 catch，会静默降级；
//   ③ 禁止"变量形式的 @tauri-apps/* 动态导入"复活（就是这个写法同时废掉打包、类型和依赖检查）。
// 另含：④ 取词自证；⑤ 分母（一条都扫不到就说明判据瞎了，不是"没问题"）。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, statSync, existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const NUL = String.fromCharCode(0);
/**
 * 本文件自己。**必须从扫描集里排除**：判据里带着合成样本
 * （`const dialogSpec = '@tauri-apps/plugin-dialog'` 那种反面例子），
 * 不排除的话守卫会扫到自己写的假样本 ⇒ 第一跑三条全红（2026-10-09 实测）。
 * 与 D25「守卫自己不当接线源」是同一形状的坑。
 */
const SELF = path.relative(REPO, fileURLToPath(import.meta.url)).split(path.sep).join('/');

const SRC_FILE = /\.(ts|tsx|js|mjs)$/;
const SPEC_RE = /@tauri-apps\/[a-z0-9][a-z0-9-]*/g;

let tracked = [];
let gitSkip = false;
try {
  tracked = execFileSync('git', ['-C', REPO, 'ls-files', '-z'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  }).split(NUL).filter(Boolean);
} catch (e) {
  gitSkip = 'git ls-files 不可用：' + (e && e.message ? e.message : String(e));
}

function readAll(pattern) {
  const files = tracked.filter(pattern);
  const out = [];
  for (const f of files) {
    const abs = path.join(REPO, f);
    try {
      if (!statSync(abs).isFile()) continue;
      out.push({ f, text: readFileSync(abs, 'utf8') });
    } catch {
      /* 不在磁盘上（已删）：跳过，不参与判据 */
    }
  }
  return out;
}

const sourceFiles = () =>
  readAll((f) => SRC_FILE.test(f) && !f.startsWith('src-tauri/') && !f.endsWith('.d.ts') && f !== SELF);

/** 源码里引用到的 @tauri-apps/* 包名（含 import / 动态 import / 字符串字面量）。 */
function specsInSource() {
  const map = new Map();
  for (const { f, text } of sourceFiles()) {
    for (const m of text.matchAll(SPEC_RE)) {
      if (!map.has(m[0])) map.set(m[0], []);
      map.get(m[0]).push(f);
    }
  }
  return map;
}

/** 纯函数：在一份源码文本里找"变量形式的 @tauri-apps 动态导入"（自证直接调它，不另写副本）。 */
function findVarFormInText(text) {
  const vars = new Set();
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\/\/.*$/, '');
    const decl = /(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*['"](@tauri-apps\/[a-z0-9-]*)['"]/.exec(line);
    if (decl) vars.add(decl[1]);
  }
  if (!vars.size) return [];
  const out = [];
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/\/\/.*$/, '');
    for (const v of vars) {
      if (new RegExp('import\\(\\s*' + v + '\\s*\\)').test(line)) out.push({ line: i + 1, varName: v });
    }
  });
  return out;
}

/**
 * 变量形式的动态导入 —— 只认"数据流真的来自 @tauri-apps 字面量"那一种，
 * 免得把仓库里其它 import(变量)（懒加载别的模块）误判成违规。
 */
function variableFormSpecifiers() {
  const hits = [];
  for (const { f, text } of sourceFiles()) {
    for (const h of findVarFormInText(text)) hits.push({ f, line: h.line, detail: h.varName });
  }
  return hits;
}

test('自证：取词与"变量形式"识别（判据瞎了就会一路恒绿）', () => {
  const fake = [
    "const dialogSpec = '@tauri-apps/plugin-dialog';",
    'const m = await import(dialogSpec);',
    "const ok = await import('@tauri-apps/api/core');",
    'const other = await import(someUnrelatedVar);',
  ].join('\n');
  // SPEC_RE 刻意不吃 `/`：`@tauri-apps/api/core` 归并成包名 `@tauri-apps/api` ——
  // 依赖表里存的就是包名，子路径不该参与比对。
  const specs = [...fake.matchAll(SPEC_RE)].map((m) => m[0]);
  assert.deepEqual(specs, ['@tauri-apps/plugin-dialog', '@tauri-apps/api'], '两个包名都要取到（子路径归并成包名）');
  // 真函数本身：只有"变量确实装着 @tauri-apps 字面量"那一行算，别的 import(变量) 不算
  const found = findVarFormInText(fake);
  assert.deepEqual(found.map((x) => x.line), [2], '第 2 行才算违规（第 3、4 行是合法形态）');
  assert.equal(found[0].varName, 'dialogSpec');
});

/**
 * ④ fs 调用与 capabilities 授权范围的配对表。
 * 现状（本机 src-tauri/gen/schemas/acl-manifests.json 里 fs.default_permission 的原文）：
 *   "This default permission set enables **read** access to the application specific
 *    directories (AppConfig, AppData, AppLocalData, AppCache, AppLog)…"
 * 而 capabilities/default.json 只写了 "fs:default" ⇒ 用户在保存/打开对话框里选的
 * **任意绝对路径**（D:\\reports\\x.md、~/Downloads/x.txt）既不在读范围也不在写范围。
 * 也就是说：本批修好了"包没装"，但桌面导出/导入还有第二半没修 —— 那是**安全范围决策**
 * （要不要放开 $DOWNLOAD/** 或 $HOME/**，还是改成只允许写入应用目录），需要人来定。
 * 所以这里用一张**显式豁免表**把欠账钉住：
 *   · 代码用到某函数、权限没授、也没在表里 ⇒ 红（新增未授权的 fs 用法）；
 *   · 权限已经授了、表里还留着豁免 ⇒ 红（豁免过期，必须删 —— 逼着这笔账真被还掉）。
 */
const FS_PERMS = {
  writeTextFile: 'fs:allow-write-text-file',
  readTextFile: 'fs:allow-read-text-file',
};
const KNOWN_UNGRANTED = {
  writeTextFile: 'D28 已知欠账：保存对话框返回任意绝对路径，fs:default 不含 ⇒ 需产品决策放开范围还是改写应用目录（见 TODO D28）',
  readTextFile: 'D28 已知欠账：打开对话框同理 ⇒ 与写同一笔决策',
};

function capabilityPermissions() {
  const dir = path.join(REPO, 'src-tauri', 'capabilities');
  if (!existsSync(dir)) return null;
  const all = new Set();
  for (const f of readdirSync(dir).filter((x) => /\.json$/.test(x))) {
    const j = JSON.parse(readFileSync(path.join(dir, f), 'utf8'));
    for (const p of j.permissions || []) all.add(typeof p === 'string' ? p : p?.identifier);
  }
  return all;
}

/**
 * 只看**真的导入 @tauri-apps/plugin-fs 的文件**：仓库里 Node 的 `fs` 模块也叫 fs
 * （fs.readFileSync / writeFileSync / rmSync…），不限定的话会把它们当成桌面调用，
 * 报出一堆"不在权限映射表里"的假缺陷（本条判据第一跑就是这样红的，实测）。
 */
function fsFunctionsUsedInSource() {
  const used = new Set();
  for (const { text } of sourceFiles()) {
    if (!text.includes('@tauri-apps/plugin-fs')) continue;
    for (const m of text.matchAll(/\bfs\.([A-Za-z]+)\(/g)) used.add(m[1]);
  }
  return used;
}

test('④ 桌面 fs 调用与 capabilities 范围必须配对（欠账要么还掉、要么显式登记）', { skip: gitSkip }, () => {
  const caps = capabilityPermissions();
  if (caps === null) {
    // capabilities 目录没了 = 桌面壳结构变了，这条判据无法判定 ⇒ 明确红，不许静默通过
    assert.fail('src-tauri/capabilities/ 不存在 —— 无法核对桌面 fs 授权范围，判据需要跟着改');
  }
  const used = fsFunctionsUsedInSource();
  // 下限取 2：tauriBridge 现在就用着 writeTextFile + readTextFile 两个。
  // 扫到 0 个不叫"没问题"，叫"限定条件写坏了 ⇒ 这条恒绿"。
  assert.ok(used.size >= 2, `只从导入 plugin-fs 的文件里扫到 ${used.size} 个 fs.* 调用（应 ≥2）`);
  const problems = [];
  for (const fn of used) {
    const perm = FS_PERMS[fn];
    if (!perm) {
      problems.push(`fs.${fn}() 不在权限映射表里 —— 新增的 fs 用法没人核对过授权范围`);
      continue;
    }
    // 只认**具体权限标识**在不在 capabilities 里。`fs:default` 不等于"都给了"——
    // 它是"应用目录只读"那一组，把用户任选路径的读写都排除在外（正是上面那段描述）。
    const granted = caps.has(perm);
    const exempt = Object.prototype.hasOwnProperty.call(KNOWN_UNGRANTED, fn);
    if (!granted && !exempt) {
      problems.push(`fs.${fn}() 需要 ${perm}，capabilities 没授、也没登记欠账`);
    }
    if (granted && exempt) {
      problems.push(`${perm} 已经在 capabilities 里了，但 KNOWN_UNGRANTED 还挂着 fs.${fn} 的豁免 ⇒ 欠账已还，删掉登记`);
    }
  }
  assert.deepEqual(problems, [], problems.join('\n'));
});

test('① 源码引用的每个 @tauri-apps 包都必须在依赖表里', { skip: gitSkip }, () => {
  const pkg = JSON.parse(readFileSync(path.join(REPO, 'package.json'), 'utf8'));
  const declared = new Set([
    ...Object.keys(pkg.dependencies || {}),
    ...Object.keys(pkg.devDependencies || {}),
  ]);
  const used = specsInSource();
  assert.ok(used.size >= 2, `只扫到 ${used.size} 个 @tauri-apps 引用 —— 取词可能已失效`);
  const missing = [...used.entries()].filter(([spec]) => !declared.has(spec));
  assert.deepEqual(
    missing,
    [],
    `${missing.length} 个 @tauri-apps 包被源码引用却没进 package.json 依赖：` +
      missing.map(([s, fs]) => `\n  - ${s}（用于 ${fs.slice(0, 3).join(', ')}）`).join('') +
      `\n后果：npm ci 不会安装它 ⇒ 构建产物里留下运行时裸 import，桌面壳按 origin 解析必失败；` +
      `而"变量形式动态导入"会让 Vite 完全不报，构建照样绿。`
  );
});

test('② 依赖里的每个 plugin 包都必须在 Rust 侧注册（JS 装了 Rust 没装 = 运行时命令不存在）', { skip: gitSkip }, () => {
  const pkg = JSON.parse(readFileSync(path.join(REPO, 'package.json'), 'utf8'));
  const jsPlugins = Object.keys({ ...(pkg.dependencies || {}) }).filter((k) => k.startsWith('@tauri-apps/plugin-'));
  assert.ok(jsPlugins.length >= 1, '依赖里没有任何 @tauri-apps/plugin-* —— 判据的假设变了');
  const cargo = readFileSync(path.join(REPO, 'src-tauri', 'Cargo.toml'), 'utf8');
  const lib = readFileSync(path.join(REPO, 'src-tauri', 'src', 'lib.rs'), 'utf8');
  const unregistered = jsPlugins.filter((k) => {
    const crate = 'tauri-plugin-' + k.replace('@tauri-apps/plugin-', '');
    const fn = 'tauri_plugin_' + crate.split('-').slice(2).join('_') + '::init';
    return !cargo.includes(crate) || !lib.includes(fn);
  });
  assert.deepEqual(
    unregistered,
    [],
    `这写 JS 插件包已声明但 Rust 侧未注册：${unregistered.join(', ')} —— ` +
      `调用会得到"插件命令不存在"，而本仓那条路径外面套着 catch，会静默降级成"看起来没这功能"。`
  );
});

test('③ 禁止"变量形式的 @tauri-apps 动态导入"（它同时废掉打包、类型与依赖检查）', { skip: gitSkip }, () => {
  const hits = variableFormSpecifiers();
  assert.deepEqual(
    hits,
    [],
    `${hits.length} 处变量形式的 Tauri 模块引用：` +
      hits.map((h) => `\n  - ${h.f}:${h.line} import(${h.detail})`).join('') +
      `\n必须写成字面量 import('@tauri-apps/plugin-…')：否则 Vite 不静态分析（产物留裸 import，` +
      `桌面壳里解析不到），TS 也拿不到模块类型（只能 as any）。Web 侧不必担心体积：` +
      `调用点前面有 tauriAvailable 提前 return，这个 chunk 永不被加载。`
  );
});
