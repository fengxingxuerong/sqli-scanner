// ============================================================================
// tests/authAudit.concurrent.test.js —— 审计台账在**并发写**下的可认领性（D224 2026-10-31）
//
// ── 它防的是什么（真发生过）──────────────────────────────────────────────
// `auth.jsonl` 是**全进程共享的单一文件**（不按 scanId 分），而 `node --test` 默认多文件
// 并发。旧断言写成「读文件的最后一行 == 我刚写的事件」，于是别的测试文件刚追加一条
// `allowed`，这边断言 `denied` 就红。
// 实测（HEAD 上 21 个文件 × 10 轮）：**失败 1 轮**，报
//   AssertionError: + actual 'allowed' - expected 'denied'
// —— 与任何被测逻辑无关，纯粹是断言依赖了共享文件的时序。这类红的代价比普通 flake 更高：
// 它出现在「安全审计」这条链上，读的人第一反应是「审计是不是坏了」。
//
// ── 判据 ────────────────────────────────────────────────────────────────
// ① recordAuthEvent 必须回传 eventId（否则调用方无法认领自己的事件）；
// ② 并发写 N 条后，每条都能用自己的 eventId 精确取回，且**互不混淆**；
// ③ 自证：判据对「按最后一行认领」的旧写法必须有反应（构造并发交错，证明旧写法会取错）。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { recordAuthEvent, findAuthEvents, readAuthEvents, _clearForTest } from '../src/services/authAudit.js';

test('① recordAuthEvent 回传 eventId（并发下认领事件的前提）', () => {
  _clearForTest();
  const r = recordAuthEvent({ operation: 'exploit', result: 'denied', reason: 'TEST' });
  assert.equal(r.ok, true);
  assert.equal(typeof r.eventId, 'string');
  assert.ok(r.eventId.length >= 8, `eventId 过短：${r.eventId}`);
});

test('② 并发交错写入后，每条事件都能用自己的 eventId 精确取回', async () => {
  _clearForTest();
  const N = 12;
  // 模拟真实的并发形态：同时发起写入，顺序不受控
  const results = await Promise.all(
    Array.from({ length: N }, (_, i) => Promise.resolve().then(() => recordAuthEvent({
      operation: 'exploit',
      target: `http://t${i}.example/`,
      result: i % 2 === 0 ? 'allowed' : 'denied',
      reason: i % 2 === 0 ? undefined : `R${i}`,
    })))
  );
  const ids = results.map((r) => r.eventId);
  assert.equal(new Set(ids).size, N, 'eventId 出现重复 —— 无法用于认领');

  // 每条都能按 id 精确取回，且内容对得上（证明 id → 事件的映射没串）
  for (const [i, id] of ids.entries()) {
    const mine = findAuthEvents({ eventId: id });
    assert.equal(mine.length, 1, `eventId ${id} 应恰好对应 1 条`);
    assert.equal(mine[0].target, `http://t${i}.example/`, '按 id 取回的事件不是当初写的那条');
    assert.equal(mine[0].result, i % 2 === 0 ? 'allowed' : 'denied');
  }
});

test('③ 自证：判据对「按最后一行认领」的旧写法有反应', async () => {
  _clearForTest();
  const mineRec = recordAuthEvent({ operation: 'exploit', target: 'http://mine/', result: 'denied', reason: 'MINE' });
  // 模拟另一个测试文件在此刻插进来写了一条 allowed
  recordAuthEvent({ operation: 'exploit', target: 'http://other/', result: 'allowed' });

  // 旧写法（读最后一行）现在会拿到别人的事件 —— 这必须能被观察到
  const lastByFile = readAuthEvents().at(-1);
  assert.equal(lastByFile.target, 'http://other/', '前提不成立：插队事件没成为最后一行');
  assert.notEqual(lastByFile.eventId, mineRec.eventId);

  // 新写法（按 eventId）仍然精确命中自己那条
  const mine = findAuthEvents({ eventId: mineRec.eventId });
  assert.equal(mine.length, 1);
  assert.equal(mine[0].target, 'http://mine/');
  assert.equal(mine[0].result, 'denied');

  // 并证明「按条件过滤」也不会被插队事件污染
  const denied = findAuthEvents({ operation: 'exploit', result: 'denied' });
  assert.ok(denied.every((e) => e.result === 'denied'), '按条件过滤仍混入了非 denied 事件');
});

test('④ 坏行容错：审计文件被截断/半行时不整体抛错（审计查看不该因一行坏掉而瞎）', () => {
  // readAuthEvents 用 flatMap + try/catch 逐行解析：坏行被丢弃，好行仍然返回。
  // 这里不真的去改共享文件（会影响并发中的其它测试），只验证空文件路径不抛。
  _clearForTest();
  assert.deepEqual(readAuthEvents(), [], '空文件应返回空数组而不是抛错');
});
