// @vitest-environment node
// ============================================================================
// src/tests/useEventsReconnectGuard.test.ts
// SSE 重连退避：连接"建立后立刻断开"时必须有终止路径
//
// ── 缺陷（实测确认，非推理）──────────────────────────────────────────────────
// useEvents.ts 的 onopen 里**无条件** `retryCount = 0`。
//
// 这在「先断线、后恢复」时是对的，但服务端「接受连接后立刻断开」时失效：
// 会话已回收（终态 TTL 后 dispose）、后端不再持有该扫描时，
// `/scan/:id/events` 很可能就是这个形态。此时每次尝试都是
//
//     onopen（retryCount = 0）→ onerror（retryCount = 1）→ 退避 1s → 再来
//
// ⇒ **永远达不到 MAX_RETRIES = 5**。
//
// 实测状态机（观察窗口 60 次尝试）：
//     现状逻辑：仍在重连（60 次），从不终止
//     ⇒ 无限重连、UI 永久停在 running、**没有任何报错**
//
// 正常断线后恢复的场景本来就对，所以这个缺陷只在最需要报错的故障形态下发作。
//
// ── 修法 ────────────────────────────────────────────────────────────────────
// 连接**稳定存活 STABLE_OPEN_MS（3s）后**才把计数归零；onerror 与组件卸载
// 都要取消该定时器，让计数在短暂抖动下照常累加。
// 阈值取 3s：跨得过一次网络抖动（典型 < 1s），又短到真正的长连接不会被误判。
//
// 本测试用**状态机**钉行为而不是读源码：读源码只能证明"写法在不在"，
// 状态机能证明"这么写会不会终止"—— 后者才是这个缺陷的本质。
// ============================================================================

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SRC = readFileSync(
  fileURLToPath(new URL('../hooks/useEvents.ts', import.meta.url)), 'utf8',
).replace(/\r\n/g, '\n');

const MAX_RETRIES = Number(/const MAX_RETRIES = (\d+);/.exec(SRC)?.[1] ?? 5);
const STABLE_OPEN_MS = Number(/const STABLE_OPEN_MS = (\d+);/.exec(SRC)?.[1] ?? 0);

/**
 * 复刻 useEvents 的重连状态机。
 * @param lives 每一次连接「稳定存活」的毫秒数；按序循环使用。
 * @returns 'error'（已达上限并置错）| 'connected'（连接稳定成立）
 */
function simulate(lives: number[], maxTicks = 60): { outcome: string; ticks: number } {
  let retryCount = 0;
  let ticks = 0;
  while (ticks < maxTicks) {
    ticks += 1;
    const life = lives[(ticks - 1) % lives.length];
    // onopen → 挂稳定期定时器；到点且仍是当前连接才归零
    const willStabilize = life >= STABLE_OPEN_MS;
    if (willStabilize) retryCount = 0;
    // onerror：没稳定住就不归零，计数累加
    if (!willStabilize) {
      retryCount += 1;
      if (retryCount > MAX_RETRIES) return { outcome: 'error', ticks };
    } else {
      return { outcome: 'connected', ticks };
    }
  }
  return { outcome: `still-retrying(${ticks})`, ticks };
}

describe('SSE 重连：连接立刻断开时必须有终止路径', () => {
  it('自证-0: 源码里读得到阈值常量（防守卫因改名而空转）', () => {
    expect(MAX_RETRIES).toBe(5);
    expect(STABLE_OPEN_MS).toBeGreaterThan(0);
    expect(SRC).toContain('const STABLE_OPEN_MS');
  });

  it('自证-1: 正常断线后恢复必须仍然连上（不得因本修复而变慢/失效）', () => {
    // 前两次失败、第三次连上并稳定 ⇒ 必须 connected
    expect(simulate([0, 0, 10_000]).outcome).toBe('connected');
  });

  it('缺陷-1: 每次连接都立刻断开 ⇒ 必须终止于 error，不得无限重连', () => {
    const r = simulate([0]);
    expect(r.outcome, `观察 ${r.ticks} 次后仍在重连 ⇒ UI 会永久停在 running 且无任何报错`)
      .toBe('error');
    // 终止点应当是 MAX_RETRIES + 1 次（即第 6 次）
    expect(r.ticks).toBe(MAX_RETRIES + 1);
  });

  it('缺陷-2: 抖动但都短于稳定期 ⇒ 同样必须终止', () => {
    // 网络抖动常见形态：连上、抖一下就断，每次都不足 3s
    expect(simulate([200, 500, 100, 800, 300, 900]).outcome).toBe('error');
  });

  it('缺陷-3: 偶尔抖一下但最终稳定 ⇒ 仍然应连上（计数被稳定期清零）', () => {
    // 第 3 次连上并存活 5s ⇒ 归零成功；此后再无失败
    expect(simulate([0, 0, 5000]).outcome).toBe('connected');
  });

  it('边界: 存活恰好等于阈值算稳定（判定用 >= 而非 >）', () => {
    expect(simulate([STABLE_OPEN_MS]).outcome).toBe('connected');
    expect(simulate([STABLE_OPEN_MS - 1]).outcome).toBe('error');
  });
});

describe('实现约束：稳定期定时器必须被正确清理', () => {
  // 若 onerror 不清定时器，那么一次已失败的连接会在 3s 后把 retryCount 清零，
  // 等于把这个修复绕过去 —— 行为上与原缺陷等价，但代码上看不出来。

  it('onerror 必须清除待归零的稳定期定时器', () => {
    const seg = SRC.slice(SRC.indexOf('current.onerror = ()'));
    const beforeRetry = seg.slice(0, seg.indexOf('retryCount += 1;'));
    expect(beforeRetry).toMatch(/stableTimer !== null[\s\S]*clearTimeout\(stableTimer\)/);
  });

  it('组件卸载必须清除稳定期定时器（否则成无主写入）', () => {
    const seg = SRC.slice(SRC.lastIndexOf('return () => {'));
    expect(seg).toMatch(/stableTimer !== null[\s\S]*clearTimeout\(stableTimer\)/);
  });

  it('onopen 里不得再出现无条件 retryCount = 0（那正是本缺陷的根因）', () => {
    const seg = SRC.slice(SRC.indexOf('current.onopen = ()'), SRC.indexOf('current.onmessage'));
    // 归零只允许出现在稳定期定时器回调里，且必须在 es === current 守卫之后
    const lines = seg.split('\n').filter((l) => /^\s*retryCount = 0;/.test(l));
    expect(lines.length, `onopen 里仍有 ${lines.length} 处裸归零语句`).toBe(0);
    expect(seg).toMatch(/if \(es === current\) retryCount = 0;/);
  });

  it('stableTimer 必须声明在 effect 作用域内（可被 onerror / 卸载访问）', () => {
    expect(SRC).toMatch(/let stableTimer: number \| null = null;/);
  });
});