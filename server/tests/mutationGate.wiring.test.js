// mutationGate.wiring.test.js —— 变异门禁自身的接线守卫
// ============================================================================
// 变异门禁（scripts/mutation-check.mjs）防的是「断言不敏感」，但它自己也会空转：
//   ① 只接进 ci.yml 或 ci-local.mjs 一边（本地跑得再好，CI 根本不跑 → 等于没门禁）；
//   ② 目标表里的模块/测试文件被改名或删除 → 挂载失效，判定静默失去意义
//      （挂载错 = 存活率失真，这是变异门禁最高频的失效形态）；
//   ③ 恢复保护被删 → 一次中断就把源码永久改坏。
// 这三条都是「脚本还在、门禁已死」，只能靠源码文本守卫钉住。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../..');
const SCRIPT_REL = 'scripts/mutation-check.mjs';
const script = readFileSync(path.join(REPO, SCRIPT_REL), 'utf8');
const ciYml = readFileSync(path.join(REPO, '.github/workflows/ci.yml'), 'utf8');
const ciLocal = readFileSync(path.join(REPO, 'scripts/ci-local.mjs'), 'utf8');

// 从脚本文本里抽出目标表（不 import：脚本一 import 就会跑主流程）
// ────────────────────────────────────────────────────────────────────────────
// 路径基准取决于条目的 runner：
//   runner: 'server'（缺省）→ 路径相对 server/
//   runner: 'frontend'      → 路径相对仓库根
// 两侧的文件都以 `src/` 开头（server/src/… vs src/…），**光看路径分不出来**，
// 只能靠 runner 字段 ⇒ 判据 ⑦ 专门钉「前端形态必须显式声明 runner」。
const targetsBlock = (() => {
  const from = script.indexOf('const TARGETS');
  const to = script.indexOf('const EQUIVALENT');
  return script.slice(from === -1 ? 0 : from, to === -1 ? script.length : to);
})();

/** 按顶层 {…} 切出条目（先剥行注释，避免注释里的括号/引号干扰配对） */
function parseEntries(block) {
  const bare = block.split('\n').map((l) => l.replace(/\/\/.*$/, '')).join('\n');
  const objs = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < bare.length; i += 1) {
    const c = bare[i];
    if (c === '{') {
      if (depth === 0) start = i;
      depth += 1;
    } else if (c === '}') {
      depth -= 1;
      if (depth === 0 && start !== -1) {
        objs.push(bare.slice(start, i + 1));
        start = -1;
      }
    }
  }
  return objs
    .map((obj) => {
      const file = (obj.match(/file:\s*'([^']+)'/) || [])[1];
      if (!file) return null;
      return {
        runner: (obj.match(/runner:\s*'([^']+)'/) || [])[1] || 'server',
        file,
        tests: [...obj.matchAll(/'([^']+\.test\.[jt]sx?)'/g)].map((m) => m[1]),
      };
    })
    .filter(Boolean);
}

const entries = parseEntries(targetsBlock);
const baseOf = (entry) => (entry.runner === 'frontend' ? REPO : path.join(REPO, 'server'));
const targetFiles = entries.map((e) => e.file);
const testFiles = entries.flatMap((e) => e.tests.map((p) => ({ runner: e.runner, path: p })));

test('① 变异门禁同时接进 ci.yml 与 ci-local.mjs（只接一边 = 空转）', () => {
  assert.ok(ciYml.includes(SCRIPT_REL), 'ci.yml 必须跑 mutation-check');
  assert.ok(ciLocal.includes(SCRIPT_REL), 'ci-local.mjs 必须跑 mutation-check（否则本地门禁与 CI 不同步）');
});

test('② 目标表非空，且每个目标模块都存在（模块被删/改名 → 门禁静默失效）', () => {
  assert.ok(targetFiles.length >= 8, `目标模块数应 ≥8，当前 ${targetFiles.length}`);
  for (const e of entries) {
    assert.ok(
      existsSync(path.join(baseOf(e), e.file)),
      `目标模块不存在：${e.file}（runner=${e.runner}，基准 ${baseOf(e)}）—— 路径基准写错也会这样报`,
    );
  }
});

test('③ 挂载的测试文件全部存在（挂载错是变异门禁最高频的失效形态）', () => {
  assert.ok(testFiles.length >= targetFiles.length, '每个目标至少挂一个测试文件');
  for (const t of testFiles) {
    assert.ok(
      existsSync(path.join(baseOf(t), t.path)),
      `挂载的测试文件不存在：${t.path}（runner=${t.runner}）`,
    );
  }
  // detect.js 曾长期「没有专属测试 + 52% 行覆盖」，挂载不许被摘掉
  assert.ok(
    testFiles.some((t) => t.path === 'tests/detect.orchestration.test.js'),
    'scan/detect.js 的专属测试必须在挂载表里',
  );
});

test('④ 每个目标模块至少有一种算子可命中的形态（否则该模块在门禁里是空转）', () => {
  const shapes = [' && ', ' || ', ' === ', ' !== ', 'return true', 'return false', 'continue;'];
  for (const e of entries) {
    const src = readFileSync(path.join(baseOf(e), e.file), 'utf8');
    assert.ok(shapes.some((s) => src.includes(s)), `${e.file} 里没有任何算子可命中形态 —— 该目标 0 位点`);
  }
});

test('⑤ 恢复保护三件套齐备（中断/退出都必须还原源码）', () => {
  for (const sig of ['exit', 'SIGINT', 'SIGTERM']) {
    assert.ok(script.includes(`'${sig}'`), `缺少 ${sig} 恢复兜底`);
  }
});

test('⑥ 存活即失败的语义不得被放宽（等价变异只能走白名单）', () => {
  assert.ok(script.includes('survivors.length > 0 && !reportOnly'), '存活必须导致非零退出');
  assert.ok(script.includes('MAX_SURVIVORS') || script.includes('EQUIVALENT'),
    '等价变异必须走显式白名单，不允许放宽阈值');
});

test('⑦ 前端目标必须显式声明 runner —— 两侧路径都以 src/ 开头，靠路径分不出来', () => {
  // [2026-10-03] 变异门禁的守卫面从 server 扩到 src/（前端零变异覆盖的补缺）。
  // server/src/engine/… 与 src/shared/… 看起来同形，漏写 runner 会让判据把前端文件
  // 拼到 server/ 下 ⇒ ② 报「模块不存在」，而真问题是**基准写错**，不是模块被删。
  for (const e of entries) {
    const looksFrontend = /\.tsx?$/.test(e.file) || e.tests.some((p) => p.startsWith('src/tests/'));
    if (looksFrontend) {
      assert.strictEqual(e.runner, 'frontend',
        `${e.file} 是前端形态（.ts 或 src/tests/ 挂载），必须显式写 runner: 'frontend'`);
    }
    if (e.runner === 'frontend') {
      assert.ok(e.tests.length > 0, `${e.file} 前端目标必须挂至少一个测试文件`);
      assert.ok(e.tests.every((p) => p.startsWith('src/tests/')),
        `${e.file} 的前端挂载必须落在 src/tests/ 下（走 vitest），实际：${e.tests.join(', ')}`);
    }
  }
  // 自证：解析器确实读到条目了（目标表结构被整段改写 ⇒ 上面几条可能在拿空集合比）
  assert.ok(entries.length >= 8, `目标表解析出 ${entries.length} 条，少于 8 —— 提取器可能已失效`);
  assert.ok(entries.every((e) => e.file.length > 0), '存在空 file 条目');
});
