// ============================================================================
// server/tests/duplicateSymbol.guard.test.js —— 「同一份设施出现两份实现」守卫
//
// 为什么必须有（2026-09-23 勘查）：本项目两次踩到**同一个**病 —— 一个工具函数被复制成
// 两份，其中一份后来拿到了 bug 修复，另一份没有。两份都还在跑，于是「修复了」这个结论
// 只对一半的调用链成立，而**没有任何门禁会红**：
//
//   ① `stripEchoedPayload`：`ErrorDetector.js` 私有副本有 5 个剔除变体（含 SQL 转义，
//      修的是 recall-lab `/escape` 安全点误报），共享模块 `echoStrip.js` 只有 3 个变体；
//      走共享版的是主判据链（边界探测 / 布尔比对 / 定库）——同一个 P0 只修了一半。
//   ② `mergeExtracted`：`extractScope.js` 的副本是 2026-09-12「search 结果丢失」修复前的
//      形态（缺 search / meta 分支），全仓零调用但形态完整，改一行 import 即复活。
//
// 判据是**源码文本**，不 import —— import 只能证明「找得到」，证明不了「只有一份」。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const readSrc = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');

/**
 * 禁止在这些文件里出现这些符号的**定义**。
 * pattern 必须能区分「定义」与「调用」，否则 import 语句本身会被误判。
 */
const FORBIDDEN_DEFS = [
  {
    rel: '../src/engine/detectors/ErrorDetector.js',
    // 只匹配 `function stripEchoedPayload(` 这种定义形态，不匹配 `stripEchoedPayload(body, payload)` 调用
    pattern: /^\s*function\s+stripEchoedPayload\s*\(/m,
    symbol: 'stripEchoedPayload',
    why: '回显剔除的唯一实现在 echoStrip.js。ErrorDetector 私有副本会让定点修复不外溢到主判据链（详见文件头 ①）。',
  },
  {
    rel: '../src/engine/detectors/ErrorDetector.js',
    pattern: /^\s*function\s+normalizeEcho\s*\(/m,
    symbol: 'normalizeEcho',
    why: '回显归一化的唯一实现在 echoStrip.js。',
  },
  {
    rel: '../src/engine/extractScope.js',
    pattern: /^\s*export\s+function\s+mergeExtracted\s*\(/m,
    symbol: 'mergeExtracted',
    why: '提取结果合并的唯一实现在 scanHelpers.js。extractScope 版缺 search/meta 分支，是已修 P0 的化石形态（详见文件头 ②）。',
  },
  {
    rel: '../src/engine/extractScope.js',
    pattern: /^\s*export\s+function\s+hasExtractedData\s*\(/m,
    symbol: 'hasExtractedData',
    why: '「是否有提取数据」的唯一实现在 scanHelpers.js（导出名 hasData）。',
  },
];

/** 现役实现必须存在 —— 防「把唯一的一份也删了」这种反向事故 */
const REQUIRED_DEFS = [
  {
    rel: '../src/engine/echoStrip.js',
    pattern: /export\s+function\s+stripEchoedPayload\s*\(/,
    symbol: 'stripEchoedPayload',
  },
  {
    rel: '../src/engine/echoStrip.js',
    pattern: /export\s+function\s+normalizeEcho\s*\(/,
    symbol: 'normalizeEcho',
  },
  {
    rel: '../src/engine/scanHelpers.js',
    pattern: /export\s+function\s+mergeExtracted\s*\(/,
    symbol: 'mergeExtracted',
  },
  {
    rel: '../src/engine/scanHelpers.js',
    pattern: /export\s+function\s+hasData\s*\(/,
    symbol: 'hasData',
  },
];

test('守卫：工具函数不得在别处再开一份 private 副本', () => {
  const revived = [];
  for (const d of FORBIDDEN_DEFS) {
    let src;
    try {
      src = readSrc(d.rel);
    } catch (e) {
      // 文件被整个删掉也是一种通过（没有地方能放副本了）
      continue;
    }
    if (d.pattern.test(src)) revived.push(`${d.rel} :: ${d.symbol} —— ${d.why}`);
  }
  assert.deepEqual(revived, [], `以下位置重复定义了共享工具:\n${revived.join('\n')}`);
});

test('守卫：现役唯一实现仍然存在（防反向删除）', () => {
  const lost = [];
  for (const d of REQUIRED_DEFS) {
    const src = readSrc(d.rel);
    if (!d.pattern.test(src)) lost.push(`${d.rel} :: ${d.symbol}`);
  }
  assert.deepEqual(lost, [], `以下共享实现丢失:\n${lost.join('\n')}`);
});

test('守卫本身有效：判据能区分定义与调用（防正则失效导致断言空转）', () => {
  // 同一个文件里同时存在「export 定义」与「别处调用」，模式只应命中前者。
  const src = readSrc('../src/engine/echoStrip.js');
  const defCount = (src.match(/export\s+function\s+stripEchoedPayload\s*\(/g) || []).length;
  assert.equal(defCount, 1, 'echoStrip.js 里 stripEchoedPayload 的定义应恰好 1 处');
  // 能命中调用形态，说明「只匹配 ^\s*function 」的负向判据确实更严：它不应命中 export 定义
  assert.equal(
    /^\s*function\s+stripEchoedPayload\s*\(/m.test(src),
    false,
    '私有定义形态的正则不应命中 echoStrip.js 的 export 定义（否则两种形态在正则上无法区分，整套判据失效）'
  );
});
