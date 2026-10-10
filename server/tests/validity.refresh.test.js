// ============================================================================
// validity.refresh.test.js —— 「配了自动续期却没续上」必须显形（批次 D36，实战 P0-2）
// ============================================================================
// 这条判据要消灭的失效：目标用 Bearer + refresh，access token 半小时过期，而 refresh 端点
// 配错了（url 写歪 / tokenField 指到空字段 / 需要 clientId 没带）。后半程每条请求都是 401，
// 检测层看到的是"响应没有差异"。可信度守卫**能**认出会话过期（既有 authLost 机制），但它给出的
// 建议是"重新登录并携带有效 Cookie 后复扫" —— 于是使用者去手工抓包重放，而真正该修的是那个
// 续期端点。本文件的断言就是"建议必须指向实际配了的那条链路"。
//
// 另一条纪律同样要钉：observeRefresh **只记账不改状态**。续期失败本身不是一个新的可信度状态
// （会话失效仍由 authLost 判、封禁仍由 blocked 判），否则两套判据会互相踩。
//
// ⚠ 一条实测边界：本守卫的 session_expired 只认 401 / 跳转登录页，**403 归 blocked 族**。
//   而不少 Bearer 目标正是用 403 表达令牌过期 ⇒ 那类目标的落点是 blocked 而不是 session_expired。
//   所以 blocked 的 advice 在"配了续期且失败"时必须额外提一句"403 未必是 WAF"，
//   两种状态各测一遍（见下方 describe）。
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { ScanValidityGuard } from '../src/core/scanValidityGuard.js';

const INJ_URL = "http://t.test/item?id=1%27%20AND%20%271%27=%271";
const BASE_URL = 'http://t.test/item?id=1';
const R401 = { status: 401, data: 'Unauthorized', headers: {} };
const R403 = { status: 403, data: 'Forbidden', headers: {} };
const R200 = { status: 200, data: 'page', headers: {} };

const obs = (g, n, make) => { for (let i = 0; i < n; i++) g.observe(make(i)); };
const inj = (g, n, res) => obs(g, n, () => ({ req: { url: INJ_URL }, res }));
const failRefresh = (g, why = '续期端点返回 400', n = 1) => {
  for (let i = 0; i < n; i++) g.observeRefresh({ ok: false, why, status: 400 });
};

describe('refreshActive 开关：零配置路径不得被新计数改动', () => {
  test('未配续期（refreshActive=false）⇒ observeRefresh 完全不记账', () => {
    const g = new ScanValidityGuard();
    g.observeRefresh({ ok: false, why: '不该被记' });
    g.observeRefresh({ ok: true });
    assert.deepEqual(g.summary().counts.refresh, { attempts: 0, successes: 0, failures: 0, lastWhy: '' },
      '字段必须恒存在（报告契约不随配置漂移），但值必须全 0');
  });

  test('配了续期 ⇒ attempts/successes/failures/lastWhy 逐项累计', () => {
    const g = new ScanValidityGuard({ refreshActive: true });
    g.observeRefresh({ ok: true, status: 200 });
    failRefresh(g, '续期响应里没有可用 token（试过 access_token；响应顶层键=code,msg）');
    const rf = g.summary().counts.refresh;
    assert.equal(rf.attempts, 2);
    assert.equal(rf.successes, 1);
    assert.equal(rf.failures, 1);
    assert.match(rf.lastWhy, /没有可用 token/, '最后一次失败原因要留着：它是"配错在哪"的唯一线索');
  });

  test('ok 缺失/非布尔按失败计（宁多记一次失败，也不把"没取到 token"记成成功）', () => {
    const g = new ScanValidityGuard({ refreshActive: true });
    g.observeRefresh({});
    g.observeRefresh({ ok: 'yes' });
    assert.equal(g.summary().counts.refresh.failures, 2);
    assert.equal(g.summary().counts.refresh.lastWhy, '未知原因');
  });

  test('构造参数不得漏进阈值配置（refreshActive/transformActive 是开关，不是阈值）', () => {
    const g = new ScanValidityGuard({ refreshActive: true, transformActive: true, windowSize: 60 });
    assert.equal(g.cfg.refreshActive, undefined);
    assert.equal(g.cfg.transformActive, undefined);
    assert.equal(g.cfg.windowSize, 60, '真阈值仍要生效');
    assert.equal(g.refreshActive, true);
    assert.equal(g.transformActive, true);
  });

  test('只记账不改状态：续期全失败但样本健康 ⇒ 仍是 ok（不新增状态、不中止）', () => {
    const g = new ScanValidityGuard({ refreshActive: true });
    inj(g, 20, R200);
    failRefresh(g, '续期端点返回 500', 5);
    const s = g.summary();
    assert.equal(s.status, 'ok', '续期失败不等于"扫描不可信"，会话是否真失效由 authLost 判');
    assert.equal(g.shouldAbort, false);
    assert.equal(s.counts.refresh.attempts, 5);
  });
});

describe('session_expired 文案：配过续期就指向续期', () => {
  test('续期失败 + 注入连续 401 ⇒ reason/advice 指向 bearerRefresh 链路', () => {
    const g = new ScanValidityGuard({ refreshActive: true });
    g.observe({ req: { url: BASE_URL }, res: R200 });
    // 真实时序：包装层是在**收到 401 的那一刻**去续期的，所以每次 401 前都有一次续期尝试。
    // （把 failRefresh 放到整段之后会拍到"快照里没有续期"的假象 —— 见下面那条粘滞语义测试。）
    obs(g, 3, () => {
      failRefresh(g, '续期端点返回 404');
      return { req: { url: INJ_URL }, res: R401 };
    });
    const s = g.summary();
    assert.equal(s.status, 'session_expired');
    assert.equal(s.reliable, false);
    assert.match(s.reason, /已配 Bearer 自动续期/);
    assert.match(s.reason, /续期尝试 3 次里失败 3 次/);
    assert.match(s.reason, /续期端点返回 404/, '最后一次原因必须原样进 reason，否则使用者还得去翻日志');
    assert.match(s.advice, /bearerRefresh\.url/);
    assert.match(s.advice, /tokenField/);
    assert.doesNotMatch(s.advice, /重新登录并携带有效 Cookie/, '把人支去手工抓包，是这次改动要消灭的那句建议');
    assert.match(s.advice, /未检出」?不成立|后半程/);
  });

  test('粘滞语义：状态锁定之后的续期失败不追回 reason（结论与数字同源）', () => {
    const g = new ScanValidityGuard({ refreshActive: true });
    obs(g, 3, () => ({ req: { url: INJ_URL }, res: R401 }));
    assert.equal(g.summary().status, 'session_expired');
    assert.match(g.summary().reason, /判定会话已失效/);
    // 状态已在上一条锁定；此后又失败了 5 次，不进 reason（与 unreachable 的 failStreak 峰值同口径：
    // 只有"当时那一刻"的数字参与文案，事后追加不改变已下的结论）。
    failRefresh(g, '续期端点返回 500', 5);
    const s = g.summary();
    assert.match(s.reason, /而基线请求未出现该特征/);
    assert.equal(s.counts.refresh.attempts, 0, '快照里没有的计数不得被事后追认');
    assert.equal(g.refresh.attempts, 5, '但守卫内部计数是真实的：报告取快照，排查取现值，两边都不骗人');
  });

  test('没配续期 ⇒ 保持既有建议（且不得出现"本次已配续期"这种假指认）', () => {
    const g = new ScanValidityGuard();
    inj(g, 3, R401);
    const s = g.summary();
    assert.equal(s.status, 'session_expired');
    assert.match(s.reason, /而基线请求未出现该特征，判定会话已失效/);
    assert.doesNotMatch(s.reason, /已配 Bearer 自动续期/);
    assert.match(s.advice, /重新登录并携带有效 Cookie/);
    assert.match(s.advice, /--refresh-url/, '原文案里"可以配续期"的引导要留着 —— 那是出路，不是假指认');
  });

  test('配了续期且成功过（failures=0）⇒ 也说"配过"：这时该查的是目标认不认这个 token', () => {
    const g = new ScanValidityGuard({ refreshActive: true });
    obs(g, 3, () => {
      g.observeRefresh({ ok: true });
      return { req: { url: INJ_URL }, res: R401 };
    });
    const s = g.summary();
    assert.equal(s.status, 'session_expired');
    assert.match(s.reason, /续期尝试 3 次里失败 0 次/);
    assert.match(s.advice, /bearerRefresh\.url/);
  });
});

describe('blocked 文案：403 型令牌过期不能被写成纯 WAF', () => {  test('配了续期且失败 + 满屏 403 ⇒ advice 先指向续期链路，再保留 WAF 出路', () => {
    const g = new ScanValidityGuard({ refreshActive: true });
    failRefresh(g, '续期端点返回 401');
    obs(g, 3, () => ({ req: { url: BASE_URL }, res: R200 }));
    inj(g, 20, R403);
    const s = g.summary();
    assert.equal(s.status, 'blocked', '本守卫的 403 归 blocked 族（session_expired 只认 401/跳登录页）');
    assert.equal(s.reliable, false);
    assert.match(s.advice, /403 表达令牌过期|403 其实是会话失效|403.*会话失效/s);
    assert.match(s.advice, /续期端点返回 401/);
    assert.match(s.advice, /WAF/, '不能把 WAF 这条真实可能抹掉：两种成因都要给出');
    assert.match(s.advice, /未测/);
  });

  test('没配续期 + 满屏 403 ⇒ 保持既有 WAF 文案（不凭空提续期）', () => {
    const g = new ScanValidityGuard();
    obs(g, 3, () => ({ req: { url: BASE_URL }, res: R200 }));
    inj(g, 20, R403);
    const s = g.summary();
    assert.equal(s.status, 'blocked');
    assert.match(s.advice, /疑似 WAF\/封 IP/);
    assert.doesNotMatch(s.advice, /本次配了 Bearer 自动续期/, '没配过就不能说配过');
    assert.equal(s.counts.refresh.attempts, 0);
  });

  test('配了续期且全成功 + 满屏 403 ⇒ 走原 WAF 文案（续期不是嫌疑时不甩锅给它）', () => {
    const g = new ScanValidityGuard({ refreshActive: true });
    for (let i = 0; i < 2; i++) g.observeRefresh({ ok: true });
    obs(g, 3, () => ({ req: { url: BASE_URL }, res: R200 }));
    inj(g, 20, R403);
    const s = g.summary();
    assert.equal(s.status, 'blocked');
    assert.match(s.advice, /疑似 WAF\/封 IP/);
    assert.doesNotMatch(s.advice, /本次配了 Bearer 自动续期但失败/);
    assert.equal(s.counts.refresh.successes, 2, '计数仍然可见（供报告与人工判断），只是不据此改建议');
  });
});

// ============================================================================
// 认证失效的第二种形态（D36 实战 P0-3，由 e2e/bearer-lab 实测抓出，不是推演）
// ============================================================================
// 既有 authLost 要求「注入请求连续 401 而基线请求没有」。但令牌一旦真的过期，
// **基线请求同样吃 401** —— 于是 baselineAuthHits>0 这条反证恒成立，那条判据在这类目标上
// **永不可达**（与 D35 的 transform_rejected「在单点+早剪目标上不可达」是同一类失效：
// 判据写得对，但在它要管的那类目标上收不到样本）。实测现场：
//   C1/C2 场景 70 条请求全 401 + 续期失败 25 次，verdict 仍是 no_vulnerability_detected、
//   reliable=true、reason=「目标可达性与会话状态正常」。
// expiredMidScan 补的就是这一段：进去过 ⇒ 此后连续出不去 ⇒ 判。
// ============================================================================
describe('expiredMidScan：进去过之后整段出不去（不分注入与否）', () => {
  test('前段有业务响应、此后连续 8 次全 401 ⇒ session_expired 且 reason 说"中途失效"', () => {
    const g = new ScanValidityGuard();
    obs(g, 3, () => ({ req: { url: BASE_URL }, res: R200 }));
    obs(g, 4, () => ({ req: { url: BASE_URL }, res: R401 })); // 基线也 401：旧判据正是被这里挡掉的
    assert.equal(g.summary().status, 'ok', '4 次未达 authStreakAll(8)，不得下结论');
    obs(g, 4, () => ({ req: { url: INJ_URL }, res: R401 }));
    const s = g.summary();
    assert.equal(s.status, 'session_expired');
    assert.equal(s.reliable, false);
    assert.equal(s.counts.expiredMidScan, true);
    assert.equal(s.counts.authChallengeStreak, 8);
    assert.match(s.reason, /前 \d+ 次请求得到过业务响应/);
    assert.match(s.reason, /连续 8 次/);
    assert.match(s.reason, /扫描进行中失效/);
    assert.match(s.advice, /--refresh-url|config\.bearerRefresh/);
    assert.match(s.advice, /--login-url/, '表单登录型目标的出路是自动重登，两种都要提');
  });

  test('同一形态 + 配了续期且失败 ⇒ reason 同时给出"中途失效"与"续期失败 N 次（最后一次…）"', () => {
    const g = new ScanValidityGuard({ refreshActive: true });
    obs(g, 2, () => ({ req: { url: BASE_URL }, res: R200 }));
    // 基线与注入交替：真实令牌过期就是这种纹理（基线也吃 401）。正因如此既有 authLost
    // 被 baselineAuthHits 这条反证挡住，必须由 expiredMidScan 接手。
    obs(g, 8, (i) => {
      g.observeRefresh({ ok: false, why: '续期端点返回 404', status: 404 });
      return { req: { url: i % 2 ? INJ_URL : BASE_URL }, res: R401 };
    });
    const s = g.summary();
    assert.equal(s.status, 'session_expired');
    assert.equal(s.counts.expiredMidScan, true);
    assert.match(s.reason, /已配 Bearer 自动续期，但续期尝试 8 次里失败 8 次/);
    assert.match(s.reason, /续期端点返回 404/);
    assert.match(s.advice, /bearerRefresh\.url/, '这时候最该修的是续期端点，不是叫人去手工抓包');
    assert.doesNotMatch(s.advice, /从未带上目标认得的凭据/);
  });

  test('正常自动续期的形态（401 与重试成功交替）绝不判：连续段必须被业务响应清零', () => {
    const g = new ScanValidityGuard({ refreshActive: true });
    obs(g, 30, (i) => (i % 3 === 0
      ? { req: { url: INJ_URL }, res: R401 }
      : { req: { url: INJ_URL }, res: R200 }));
    const s = g.summary();
    assert.equal(s.counts.expiredMidScan, false, '每 3 条一次 401 是"续期成功+重试"的正常纹理');
    assert.ok(s.counts.authChallengeStreak <= 1, `连续挑战段不该超过 1，实得 ${s.counts.authChallengeStreak}`);
    assert.ok(s.counts.nonChallengeHits >= 20, '业务响应必须被记进账里，否则 neverAuthenticated 会反过来误报');
    assert.equal(s.status, 'ok', '未过期且样本健康 ⇒ 既有结论路径一个字不改');
    assert.equal(s.reliable, true);
  });

  test('反向：满屏 401（基线也算）且从未有过业务响应 ⇒ 走 neverAuthenticated 分支', () => {
    const g = new ScanValidityGuard();
    obs(g, 12, (i) => ({ req: { url: i % 2 ? INJ_URL : BASE_URL }, res: R401 }));
    const s = g.summary();
    assert.equal(s.counts.neverAuthenticated, true);
    assert.equal(s.counts.expiredMidScan, false, '两种形态互斥：没进去过就谈不上"中途"');
    assert.match(s.reason, /没有任何一次得到过业务响应/);
    assert.match(s.advice, /--auth|requestFile/);
    assert.match(s.advice, /从未带上目标认得的凭据/);
  });

  test('传输失败不算"进去过"；503 算（它是应用在回应，只是应用病了）', () => {
    const g = new ScanValidityGuard();
    obs(g, 3, () => ({ req: { url: INJ_URL }, res: null })); // 失败：挑战与业务两本账都不计
    obs(g, 8, (i) => ({ req: { url: i % 2 ? INJ_URL : BASE_URL }, res: R401 }));
    assert.equal(g.summary().counts.neverAuthenticated, true, '全是失败+挑战 ⇒ 仍属"从未进去"');
    assert.equal(g.summary().counts.expiredMidScan, false);

    const g2 = new ScanValidityGuard();
    obs(g2, 2, () => ({ req: { url: INJ_URL }, res: { status: 503, data: 'down', headers: {} } }));
    obs(g2, 8, (i) => ({ req: { url: i % 2 ? INJ_URL : BASE_URL }, res: R401 }));
    assert.equal(g2.summary().counts.expiredMidScan, true, '503 也是"应用在回应"，此后连续出不去即中途失效');
  });
});
