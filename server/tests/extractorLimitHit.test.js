// ============================================================================
// tests/extractorLimitHit.test.js —— 请求上限熔断标志的生命周期（2026-10-05）
//
// ── 防的是什么 ───────────────────────────────────────────────────────────────
// `_limitHit` 是「请求已达 --max-requests」的**终止信号**（P1-FIX 2026-09-17）：
// Extractor._send 的 catch 里识别「请求上限已达」并置位，blindExtractor._sendBatch 的
// worker 检出后立即 break。不置位的话实测会空转 327,875 次 / 33 秒 CPU，
// 并把目标可达性污染成 unreachable。
//
// 修复前的真实缺陷（**不是** 缺字段这么简单，是状态泄漏）：
//   · 字段根本不在构造器里，只在 catch 里用 `/** @type {any} */ (this)._limitHit = true`
//     动态挂载，读取侧 blindExtractor 也靠同样的 any 逃逸 —— 两处都在绕过类型检查；
//   · 置位后**永不复位**。而 ScanManager 持有**一个** Extractor 实例
//     （ScanManager.js: `this.extractor = new Extractor()`），跨多个注入点、多轮提取复用。
//   ⇒ 一旦某个注入点撞上限，同一实例之后**所有**注入点的 worker 都会立刻 break，
//     表现为「后面的注入点静默提不出任何数据」，且没有任何错误提示。
//
// 反向的坑同样要避开：若只在构造器初始化 false 而**不复位**，就退化成全局熔断——
// 熔断本意是终止**本次**提取流程，不是让整个扫描实例瘫痪。
//
// ── 本文件的判据 ─────────────────────────────────────────────────────────────
// ① 字段在构造器里正式声明（不靠 any 动态挂）；
// ② 源码里不再有任何 `_limitHit` 的 `any` 逃逸；
// ③ 行为：撞上限后本次提取的 worker 会 break；
// ④ **回归核心**：撞上限之后，下一次提取必须能正常发包（不复位就会红）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readCode } from './_srcScan.mjs';
import { Extractor } from '../src/engine/Extractor.js';

const LIMIT_ERR = new Error('请求上限已达 (max-requests=100)');

/** 构造一个最小 ctx：先按条件抛上限错，之后正常应答。 */
function makeCtx({ hitLimitOnce = true, payload = 'OK' } = {}) {
  const sent = [];
  let limitUsed = false;
  return {
    sent,
    ctx: {
      httpClient: {
        async request(opts) {
          sent.push(opts);
          if (hitLimitOnce && !limitUsed) {
            limitUsed = true;
            throw LIMIT_ERR;
          }
          return { data: payload, status: 200 };
        },
      },
      target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
      point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: true },
      dbms: 'MySQL',
      scanId: 'limit-hit-test',
      config: { timeoutMs: 5000, retry: 0, extractConcurrency: 1, blindRobust: {} },
    },
  };
}

test('声明-1) _limitHit 在构造器里正式声明（不得靠 any 动态挂）', () => {
  const ex = new Extractor();
  assert.ok('_limitHit' in ex, '实例上没有 _limitHit 字段 —— 熔断状态无处安放');
  assert.equal(ex._limitHit, false, '新实例的 _limitHit 应为 false');
});

test('声明-2) 源码里不再有 _limitHit 的 any 逃逸', () => {
  // 剥注释是源码形态判据的默认前置（见 tests/_srcScan.mjs 的说明）：
  // 本文件自己、以及 Extractor/blindExtractor 的说明注释里都**引用了**这段代码形态
  // 用于解释历史；不剥注释的话判据会命中自己的说明文字 ⇒ 恒红的假失败。
  const code = readCode(new URL('../src/engine/Extractor.js', import.meta.url))
    + readCode(new URL('../src/engine/blindExtractor.js', import.meta.url));
  const escapes = code.match(/@type\s*\{\s*any\s*\}\s*\*\/\s*\(?[a-z]+\)?\._limitHit/g) || [];
  assert.equal(escapes.length, 0,
    `仍有 ${escapes.length} 处 _limitHit 的 any 逃逸：${escapes.join(' | ')}\n` +
    '字段既已在构造器声明，就不该再绕过类型检查。');
});

test('行为-3) 撞上限后本次提取停止发包（熔断本身仍然有效）', async () => {
  const ex = new Extractor();
  const { sent, ctx } = makeCtx({ hitLimitOnce: true });
  // 走公开入口（extractBoolean 会调用 _sendBatch → _send）。
  // 注意：`_sendBatch` 是 blindExtractor.js 的**模块私有函数**，Extractor 上没有同名方法，
  //   所以只能经公开入口驱动 —— 这也顺带证明了修复在真实调用路径上生效。
  await ex.extractBoolean(ctx, 'version()').catch(() => {});
  assert.equal(ex._limitHit, true, '撞上限后应置位 _limitHit');
  // 1 次预热（撞上限）+ 熔断后不应再有新的请求包
  assert.ok(sent.length <= 2,
    `熔断后仍发了 ${sent.length} 个请求（首包 + 至多 1 次在途），熔断应几乎立刻生效`);
});

test('回归-4) 撞上限后，下一次提取必须能正常发包（跨注入点不泄漏）', async () => {
  // 这是本文件的核心：修复前 _limitHit 永不复位 ⇒ 这里必然提不出任何数据。
  const ex = new Extractor();

  // 第一次提取：撞上限
  const first = makeCtx({ hitLimitOnce: true });
  await ex.extractBoolean(first.ctx, 'version()').catch(() => {});
  assert.equal(ex._limitHit, true, '第一次提取应置位熔断');

  // 第二次提取（模拟下一个注入点 / 下一轮）：同一个实例，必须能正常发包
  const second = makeCtx({ hitLimitOnce: false, payload: 'OK' });
  await ex.extractBoolean(second.ctx, 'version()').catch(() => {});
  assert.ok(second.sent.length >= 1,
    '第二次提取一个包都没发 —— 熔断状态泄漏到后续提取（原实现必然红在此）');
});

test('回归-5) 走公开入口时自动复位（调用方不需要手动清）', async () => {
  // 复位点在各入口的薄包装里；这里验证公开入口确实会复位，
  // 而不只验证 _resetLimitHit() 这个私有方法本身。
  // ⚠️ 原此处是 `assert.ok(sent.length >= 0, '占位')` —— 恒真，纯装饰。
  //   本条真正要证明的是"残留熔断标志不会让入口一个包都不发"，故必须断言**发了包**。
  const ex = new Extractor();
  ex._limitHit = true; // 模拟上一轮遗留的熔断状态

  const { sent, ctx } = makeCtx({ hitLimitOnce: false, payload: 'x' });
  await ex.extractBoolean(ctx, 'version()').catch(() => {});
  assert.ok(sent.length >= 1,
    `残留 _limitHit=true 时公开入口仍应正常发包，实际发了 ${sent.length} 个 —— 复位没生效`);
  assert.equal(ex._limitHit, false,
    '走公开入口后 _limitHit 应已被复位（入口薄包装负责），否则熔断会跨注入点泄漏');
});
