// 布尔盲注检测器：自定义检测锚点（--string 等）激活路径集成测试
// 用 mock httpClient 确定性返回「真响应含标记 / 假响应不含」，验证 detectMatch 短路正确判定。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { createTarget, createInjectionPoint } from '../src/engine/models.js';

function makeCtx(detectMatch, callBodies) {
  const detector = new BooleanBlindDetector();
  const point = createInjectionPoint('url', 'id', '1');
  const target = createTarget({ url: 'http://x/?id=1' });
  let calls = 0;
  const httpClient = {
    request: async () => {
      calls += 1;
      // 第 1 次=真条件响应，第 2 次=假条件响应
      return { data: callBodies[calls - 1] ?? '', status: 200 };
    },
  };
  const config = {
    blindRobust: { enabled: false }, // 即便开启也不影响：detectMatch 短路在前
    detectMatch: detectMatch || { string: null, notString: null, regexp: null, code: null },
  };
  const ctx = { httpClient, target, point, dbms: 'MySQL', config };
  return { detector, ctx };
}

test('detectMatch 激活：string 锚点 TRUE含/FALSE不含 → 判 vulnerable', async () => {
  const { detector, ctx } = makeCtx({ string: 'MARKER', notString: null, regexp: null, code: null }, ['page with MARKER here', 'plain page']);
  const result = await detector.detect(ctx);
  assert.equal(result.vulnerable, true);
  assert.equal(result.technique, 'boolean');
  assert.ok(result.evidence.includes('自定义锚点'), 'evidence 应标注自定义锚点');
});

test('detectMatch 激活：string 锚点错配 → 不判 vulnerable（证明锚点真实门控）', async () => {
  const { detector, ctx } = makeCtx({ string: 'NOPE', notString: null, regexp: null, code: null }, ['page with MARKER here', 'plain page']);
  const result = await detector.detect(ctx);
  assert.equal(result.vulnerable, false);
  assert.ok(result.evidence.includes('未命中'), '应标注锚点未命中');
});

test('detectMatch 激活：code 锚点 TRUE=200/FALSE=403 → 判 vulnerable', async () => {
  const { detector, ctx } = makeCtx({ string: null, notString: null, regexp: null, code: 200 }, ['a', 'b']);
  // 覆盖 mock 以返回不同状态码（callBodies 仅控 data，这里单独构造）
  ctx.httpClient.request = async (req) => {
    ctx._c = (ctx._c || 0) + 1;
    return ctx._c === 1 ? { data: 'a', status: 200 } : { data: 'b', status: 403 };
  };
  const result = await detector.detect(ctx);
  assert.equal(result.vulnerable, true);
});

test('detectMatch 未配置 → 不激活（走统计分支，不报自定义锚点）', async () => {
  const { detector, ctx } = makeCtx(null, ['x', 'y']);
  // 注意：此处 config.detectMatch 为全 null，normalizeDetectMatch 返回 null，
  // detect 不应进入 _detectWithMatch（不会在 evidence 写「自定义锚点」）。
  // 由于 legacy 统计分支依赖真实响应差异，这里仅断言「未激活 detectMatch 短路」：
  // 直接验证 normalizeDetectMatch 行为由 detectMatch.test.js 覆盖；此处确保 detect 不抛且返回结果对象。
  const result = await detector.detect(ctx);
  assert.ok(result && typeof result.vulnerable === 'boolean');
  assert.ok(!result.evidence || !result.evidence.includes('自定义锚点'));
});
