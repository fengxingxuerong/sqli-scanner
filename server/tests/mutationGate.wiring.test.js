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
const targetFiles = [...script.matchAll(/file:\s*'([^']+)'/g)].map((m) => m[1]);
const testFiles = [...script.matchAll(/'(tests\/[^']+\.test\.js)'/g)].map((m) => m[1]);

test('① 变异门禁同时接进 ci.yml 与 ci-local.mjs（只接一边 = 空转）', () => {
  assert.ok(ciYml.includes(SCRIPT_REL), 'ci.yml 必须跑 mutation-check');
  assert.ok(ciLocal.includes(SCRIPT_REL), 'ci-local.mjs 必须跑 mutation-check（否则本地门禁与 CI 不同步）');
});

test('② 目标表非空，且每个目标模块都存在（模块被删/改名 → 门禁静默失效）', () => {
  assert.ok(targetFiles.length >= 8, `目标模块数应 ≥8，当前 ${targetFiles.length}`);
  for (const f of targetFiles) {
    assert.ok(existsSync(path.join(REPO, 'server', f)), `目标模块不存在：${f}`);
  }
});

test('③ 挂载的测试文件全部存在（挂载错是变异门禁最高频的失效形态）', () => {
  assert.ok(testFiles.length >= targetFiles.length, '每个目标至少挂一个测试文件');
  for (const t of testFiles) {
    assert.ok(existsSync(path.join(REPO, 'server', t)), `挂载的测试文件不存在：${t}`);
  }
  // detect.js 曾长期「没有专属测试 + 52% 行覆盖」，挂载不许被摘掉
  assert.ok(
    testFiles.includes('tests/detect.orchestration.test.js'),
    'scan/detect.js 的专属测试必须在挂载表里',
  );
});

test('④ 每个目标模块至少有一种算子可命中的形态（否则该模块在门禁里是空转）', () => {
  const shapes = [' && ', ' || ', ' === ', ' !== ', 'return true', 'return false', 'continue;'];
  for (const f of targetFiles) {
    const src = readFileSync(path.join(REPO, 'server', f), 'utf8');
    assert.ok(shapes.some((s) => src.includes(s)), `${f} 里没有任何算子可命中形态 —— 该目标 0 位点`);
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
