// [D32 实战 P0-1] 「签名/加密被拒」显形判据 —— 未检出 ≠ 没有洞
//
// 这条判据要消灭的失效：带 sign= 的接口上，注入值破坏了签名 ⇒ 目标恒回 400 ⇒
// 检测层看到「响应没有差异」⇒ 报告写「未检出」。使用者读到的是一句安全结论，
// 而实际一个注入都没抵达 SQL。所以两件事必须成立：
//   ① 结论层落到 inconclusive（reliable=false），不是 ok；
//   ② 两种成因分开表述 —— 连基线都被拒（脚本配错）vs 只有注入被拒（签名没覆盖该参数），
//      前者要改脚本、后者要把参数纳入签名，处置完全不同。
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  ScanValidityGuard,
  VALIDITY_DEFAULTS,
  evaluateTransformStatus,
  isRequestReject,
} from '../src/core/scanValidityGuard.js';

const ok = (status = 200) => ({ status, data: 'page', headers: {} });
const rej = (status = 400) => ({ status, data: '{"code":"sign error"}', headers: {} });

const ON = { transformActive: true };

describe('isRequestReject（判定族边界）', () => {
  test('400/415/422 算被拒；200/302/401/403/404/406/429/500/503 不算', () => {
    for (const s of [400, 415, 422]) assert.equal(isRequestReject({ status: s }), true, `${s} 应算被拒`);
    // 403/406/429/503 是既有 blocked 族；401 是会话族；404 是 path 段正常产物；
    // 5xx 是 target_error/selfInflicted 族 —— 收进来会让两套判据互相踩。
    for (const s of [200, 302, 401, 403, 404, 406, 429, 500, 503]) {
      assert.equal(isRequestReject({ status: s }), false, `${s} 不该算签名被拒`);
    }
    assert.equal(isRequestReject(null), false);
    assert.equal(isRequestReject({}), false);
  });
});

describe('evaluateTransformStatus（纯判据）', () => {
  const cfg = VALIDITY_DEFAULTS;
  test('基线连续被拒且从未成功 → baseline', () => {
    assert.equal(
      evaluateTransformStatus({ baselineRejects: 2, baselineRejectStreak: 2, baselineOk: 0, injectRejects: 0, injectOk: 0 }, cfg),
      'baseline',
    );
  });
  test('基线成功过一次 → 不再判脚本配错（改由注入成因判）', () => {
    assert.equal(
      evaluateTransformStatus({ baselineRejects: 9, baselineRejectStreak: 9, baselineOk: 1, injectRejects: 8, injectOk: 0 }, cfg),
      'injection',
    );
  });
  test('注入被拒不足下限、或有注入成功过 → 不判（避免把正常噪声写成结论）', () => {
    assert.equal(
      evaluateTransformStatus({ baselineRejects: 0, baselineRejectStreak: 0, baselineOk: 5, injectRejects: 7, injectOk: 0 }, cfg),
      null,
    );
    assert.equal(
      evaluateTransformStatus({ baselineRejects: 0, baselineRejectStreak: 0, baselineOk: 5, injectRejects: 40, injectOk: 1 }, cfg),
      null,
    );
  });
});

describe('守卫集成：状态、可靠度、中止与文案', () => {
  test('① 连基线都被拒 → transform_rejected + 不可靠 + 中止剩余检测', () => {
    const g = new ScanValidityGuard(ON);
    g.observeTransform({ injected: false, res: rej() });
    assert.equal(g.stickyStatus, 'ok', '单次被拒不下结论（阈值 2）');
    assert.equal(g.shouldAbort, false);
    g.observeTransform({ injected: false, res: rej() });
    assert.equal(g.stickyStatus, 'transform_rejected');
    const v = g.summary();
    assert.equal(v.reliable, false);
    assert.equal(v.status, 'transform_rejected');
    assert.equal(v.counts.transform.kind, 'baseline');
    assert.match(v.reason, /基线/);
    assert.match(v.advice, /密钥|字段集合/);
    // 中止是刻意的：签名不匹配时后面每条请求必然同样被拒，继续跑只是白烧预算
    // 并把「一个合法注入都没送达」的扫描写成满屏未检出。
    assert.equal(g.shouldAbort, true);
  });

  test('② 基线正常而注入全被拒 → 同状态但成因与文案换成「签名没覆盖该参数」', () => {
    const g = new ScanValidityGuard(ON);
    g.observeTransform({ injected: false, res: ok() });
    for (let i = 0; i < 8; i++) g.observeTransform({ injected: true, res: rej() });
    const v = g.summary();
    assert.equal(v.status, 'transform_rejected');
    assert.equal(v.counts.transform.kind, 'injection');
    assert.match(v.reason, /签名|加密/);
    assert.match(v.advice, /纳入签名/);
    assert.equal(v.reliable, false);
  });

  test('③ 未启用变换的扫描：同样的响应序列必须仍然 ok（默认路径零变化）', () => {
    const g = new ScanValidityGuard();
    for (let i = 0; i < 12; i++) g.observeTransform({ injected: i > 1, res: rej() });
    assert.equal(g.stickyStatus, 'ok');
    assert.equal(g.shouldAbort, false);
    assert.equal(g.summary().reliable, true);
    assert.equal(g.summary().counts.transform.baselineRejects, 0, '未启用时一个计数都不该动');
  });

  test('④ 传输失败不等于签名被拒（连不上 ≠ 签名错）', () => {
    const g = new ScanValidityGuard(ON);
    for (let i = 0; i < 6; i++) {
      g.observeTransform({ injected: false, res: null, error: new Error('ECONNREFUSED') });
      g.observeTransform({ injected: true, res: null, error: new Error('timeout') });
    }
    assert.equal(g.stickyStatus, 'ok');
    assert.equal(g.summary().counts.transform.netErr, 12);
    assert.equal(g.summary().counts.transform.baselineRejects, 0);
  });

  test('⑤ 403（WAF 拦截族）不得被算进签名被拒', () => {
    const g = new ScanValidityGuard(ON);
    for (let i = 0; i < 10; i++) g.observeTransform({ injected: true, res: rej(403) });
    assert.equal(g.stickyStatus, 'ok', '403 属既有 blocked 族，两套判据不许互踩');
    assert.equal(g.summary().counts.transform.injectRejects, 0);
  });

  test('⑥ 基线被拒后又成功一次 → 连续段与判定都复位（脚本时好时坏不能钉死）', () => {
    const g = new ScanValidityGuard(ON);
    g.observeTransform({ injected: false, res: rej() });
    g.observeTransform({ injected: false, res: rej() });
    assert.equal(g.stickyStatus, 'transform_rejected');
    g.observeTransform({ injected: false, res: ok() });
    // 粘滞不回滚（本仓统一口径）：状态与「成立那一刻」的数字留档，
    // 但**活计数**必须复位，否则下一轮判定挂在已经过去的连续段上。
    const v = g.summary();
    assert.equal(v.counts.transform.kind, 'baseline', '已成立的成因留档');
    assert.equal(v.counts.transform.baselineOk, 0, '快照是成立那一刻的，事后恢复不洗白');
    assert.equal(g.transform.baselineRejectStreak, 0, '活计数必须复位');
    assert.equal(g.transform.baselineOk, 1, '活计数必须记下「成功过一次」');
  });

  test('⑦ 严重度：先 blocked 后 transform_rejected，粘滞必须换成后者', () => {
    const g = new ScanValidityGuard(ON);
    for (let i = 0; i < 12; i++) g.observe({ req: { url: "http://t/p?id=1' AND 1=1-- -" }, res: { status: 403, data: 'blocked', headers: {} } });
    assert.equal(g.stickyStatus, 'blocked');
    g.observeTransform({ injected: false, res: rej() });
    g.observeTransform({ injected: false, res: rej() });
    assert.equal(g.stickyStatus, 'transform_rejected');
  });

  test('⑧ 阈值可经 config 覆盖（与其它判据同一旋钮口径）', () => {
    const g = new ScanValidityGuard({ ...ON, transformBaselineRejects: 5 });
    for (let i = 0; i < 4; i++) g.observeTransform({ injected: false, res: rej() });
    assert.equal(g.stickyStatus, 'ok');
    g.observeTransform({ injected: false, res: rej() });
    assert.equal(g.stickyStatus, 'transform_rejected');
  });

  test('⑨ transformActive 是开关不是阈值：不得混进 cfg（cfg 会被当可调参数读）', () => {
    const g = new ScanValidityGuard(ON);
    assert.equal(g.cfg.transformActive, undefined);
    assert.equal(g.transformActive, true);
    assert.equal(new ScanValidityGuard({ transformActive: false }).transformActive, false);
  });
});
