// ============================================================================
// tests/benchmarkLabResultShape.guard.test.js —— [D315] Benchmark 裁判结果行结构守卫
// ============================================================================
// 真因（2026-11-22 实测）：`scanOne()` 的超时分支只返回 { vulns:-1, techniques, requests,
// verdict }，缺 `detail`；主循环展示行写的是 `r.detail.length` ⇒ 单条用例超时立刻
// TypeError 崩掉整轮，**把「一条证据不足」放大成「整个裁判无结论」**。
// query 全量 210 条跑到第 83 条（BenchmarkTest01393）命中该缺陷，D283 报的 111/111
// 自此无法复现（崩溃点之前的行还被 `tail` 吞掉）。
//
// 判据只钉两件事（行为层 + 消费层），不认注释：
//   ① 超时分支与正常分支字段同形（`detail` 必须是数组，不能靠消费侧猜）；
//   ② 消费侧不得裸取（`?.length`），单条异常不能中断整轮。
// 自证：把源码还原成缺陷版（裸 `.length` / 去掉 `detail: []`）两条判据必须各自红。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SRC = readFileSync(join(REPO, 'e2e', 'benchmark-lab', 'run.mjs'), 'utf8');

/** 取 `if (Date.now() - t0 > TIMEOUT_MS)` 分支体（到下一个 `}` 前）。 */
function timeoutBranch(src) {
  const start = src.indexOf('Date.now() - t0 > TIMEOUT_MS');
  assert.notEqual(start, -1, 'run.mjs 找不到 TIMEOUT_MS 超时分支 —— 重构后需同步本守卫');
  return src.slice(start, start + 600);
}

test('D315-1 超时分支必须带回 detail 数组（与正常分支同形）', () => {
  const branch = timeoutBranch(SRC);
  assert.match(branch, /detail\s*:\s*\[\s*\]/,
    '超时分支缺 `detail: []` ⇒ 主循环访问 r.detail.length 会 TypeError');
  assert.match(branch, /vulns\s*:\s*-1/, '超时分支的 vulns 必须是 -1（证据不足哨兵）');
  assert.match(branch, /requests\s*:\s*0/, '超时分支的 requests 必须是 0（不能假装测过）');
});

test('D315-2 消费侧不得裸取 detail.length（单条异常不能中断整轮）', () => {
  const bare = SRC.split(/\r?\n/)
    .filter((l) => !/^\s*\/\//.test(l))
    .filter((l) => /r\.detail\.length/.test(l));
  assert.deepEqual(bare, [], `存在裸取 r.detail.length 的行：\n${bare.join('\n')}`);
  assert.match(SRC, /r\.detail\?\.length/, '展示行必须用可选链 r.detail?.length');
});

test('D315-3 正常分支仍产出 detail（防止修超时分支时把明细删了）', () => {
  assert.match(SRC, /detail:\s*vs\.map\(/, '正常分支必须继续映射命中明细');
});

// 自证：把两条判据分别套到「缺陷版源码」上，必须各自失败。
test('D315-4 缺陷注入自证：还原缺陷版后两条判据都要红', () => {
  const brokenBare = SRC.replace('r.detail?.length', 'r.detail.length');
  assert.notEqual(brokenBare, SRC, '注入点未命中（源码已变化，先修本自证）');
  const bareLines = brokenBare.split(/\r?\n/)
    .filter((l) => !/^\s*\/\//.test(l))
    .filter((l) => /r\.detail\.length/.test(l));
  assert.ok(bareLines.length > 0, '缺陷注入后 D315-2 应能看见裸取行');

  const brokenNoDetail = SRC.replace(/detail\s*:\s*\[\s*\]/, '');
  assert.notEqual(brokenNoDetail, SRC, '注入点未命中（超时分支已变化，先修本自证）');
  assert.doesNotMatch(timeoutBranch(brokenNoDetail), /detail\s*:\s*\[\s*\]/,
    '缺陷注入后 D315-1 应能判红');
});
