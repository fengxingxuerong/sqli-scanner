// ============================================================================
// tests/fetchUsing.test.js —— D50 提取比较算子（--fetch-using gt|between）
//
// 判据三层：
//   ① 回归：默认 gt（未配置）行为不变——提取值与历史用例一致；
//   ② 等价：between 模式在确定性预言机上提取**同一**值（算子切换不得改结果）；
//   ③ 能力：WAF 模拟预言机（拦截一切含 `>` 的 payload）下 gt 失败、between 成功
//      ——这是本开关的存在理由；gt 失败时必须诚实返回 null，不得造值。
//   另钉探针算子审计（between 模式比较位不得含 `>`）与非法配置值硬拒。
//
// 时间通道同构三连（gt 回归 / between 等价 / blockGt 下 between 独占）。
// [D287] 三连改走批内三抽归因（D280 A2 语义）：JVM 预热噪声下单抽翻面的
// 「错值」形态不再单抽定生死，但三抽全错照样红、挂死照样红——判据不许变宽。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';
import { resolveFetchUsing } from '../src/engine/blindExtractor.js';

function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  return '';
}

// 布尔预言机：同时懂 gt / between 两种探针形状（cls 类探测与 between 字符探测同形）。
// blockGt=true 模拟「`>` 被 WAF 过滤」：含 `>` 的注入 payload 一律 403 空响应。
// seen 记录全部 payload 供算子审计。
function makeOracle(secret, { blockGt = false } = {}) {
  const seen = [];
  return {
    seen,
    async request(opts) {
      const q = extractQuery(opts);
      seen.push(q);
      if (q.includes('1=2')) return { data: '', status: 200 };
      if (blockGt && q.includes('>')) return { data: '', status: 403 };
      // 长度（gt）：(LENGTH((X)))>N
      const lenGt = q.match(/(?<![A-Za-z0-9_])(?:LENGTH|LEN)(?![A-Za-z0-9_])\(\(.*?\)+\s*>\s*(\d+)/);
      if (lenGt) return { data: Number(lenGt[1]) < secret.length ? 'OK' : '', status: 200 };
      // 长度（between）：(LENGTH((X))) BETWEEN a AND b —— 覆盖二分探针与 255 延伸预检
      const lenBt = q.match(/(?<![A-Za-z0-9_])(?:LENGTH|LEN)(?![A-Za-z0-9_])\(\(.*?\)+\s+BETWEEN\s+(\d+)\s+AND\s+(\d+)/);
      if (lenBt) {
        const a = Number(lenBt[1]);
        const b = Number(lenBt[2]);
        return { data: secret.length >= a && secret.length <= b ? 'OK' : '', status: 200 };
      }
      // 字符（between / cls 类探测同形）：ASCII(SUBSTRING((X),i,1)) BETWEEN a AND b
      const charBt = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s+BETWEEN\s+(\d+)\s+AND\s+(\d+)/i);
      if (charBt) {
        const code = secret.charCodeAt(Number(charBt[1]) - 1);
        return { data: code >= Number(charBt[2]) && code <= Number(charBt[3]) ? 'OK' : '', status: 200 };
      }
      // 字符（gt）：ASCII(SUBSTRING((X),i,1))>C
      const charGt = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
      if (charGt) {
        return { data: Number(charGt[2]) < secret.charCodeAt(Number(charGt[1]) - 1) ? 'OK' : '', status: 200 };
      }
      // 等值验证（两种模式都用）：ASCII(SUBSTRING((X),i,1))=C
      const eqM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*=\s*(\d+)/);
      if (eqM) return { data: Number(eqM[2]) === secret.charCodeAt(Number(eqM[1]) - 1) ? 'OK' : '', status: 200 };
      return { data: '', status: 200 };
    },
  };
}

function buildCtx(oracle, extra = {}) {
  return {
    httpClient: oracle,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, retry: 0, maxColumnsGuess: 10, ...extra },
  };
}

const ex = new Extractor();

// 带截止时间的提取：把「收敛条件写错 → 死循环」从挂死转成断言失败。
// （注入复验实证：between 误用 gt 收敛条件时 remaining 永不收敛，测试整体挂住。）
async function extractWithDeadline(fn, ms = 20000) {
  let timer;
  try {
    return await Promise.race([
      fn(),
      new Promise((_, rej) => {
        timer = setTimeout(() => rej(new Error(`提取超过 ${ms}ms 截止时间（疑似收敛条件写错导致死循环）`)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

// ── ① resolveFetchUsing 单测（非法值硬拒，不静默回落） ──────────────────

test('resolveFetchUsing：缺省/显式 gt → gt；between → between', () => {
  assert.equal(resolveFetchUsing(undefined), 'gt');
  assert.equal(resolveFetchUsing({}), 'gt');
  assert.equal(resolveFetchUsing({ fetchUsing: null }), 'gt');
  assert.equal(resolveFetchUsing({ fetchUsing: 'gt' }), 'gt');
  assert.equal(resolveFetchUsing({ fetchUsing: 'between' }), 'between');
});

test('resolveFetchUsing：非法值（in / 拼写错误 / 非字符串）抛错且点名参数', () => {
  for (const bad of ['in', 'btween', 'BETWEEN', 'GT', 123, {}]) {
    assert.throws(() => resolveFetchUsing({ fetchUsing: bad }), /fetchUsing 仅支持 'gt' \| 'between'/,
      `fetchUsing=${JSON.stringify(bad)} 必须硬拒（静默回落 = 传了没生效）`);
  }
});

// ── ② 布尔通道：gt 回归 + between 等价 ────────────────────────────────

test('布尔通道 gt（默认未配置）：提取值与历史用例一致（回归钉）', async () => {
  const secret = '5.7.40';
  const ctx = buildCtx(makeOracle(secret), 'MySQL');
  assert.equal(await extractWithDeadline(() => ex.extractBoolean(ctx, 'version()')), secret);
});

test('布尔通道 between：同一 secret 提取结果与 gt 一致', async () => {
  const secret = '5.7.40';
  const ctx = buildCtx(makeOracle(secret), { fetchUsing: 'between' });
  assert.equal(await extractWithDeadline(() => ex.extractBoolean(ctx, 'version()')), secret);
});

test('布尔通道 between：多字节/全区间字节也收敛（含非字母数字字符）', async () => {
  const secret = 'aZ0_~ 9'; // 覆盖 cls 两类都不命中的回退路径 + 边界字节
  const ctx = buildCtx(makeOracle(secret), { fetchUsing: 'between' });
  assert.equal(await extractWithDeadline(() => ex.extractBoolean(ctx, 'version()')), secret);
});

// ── ③ 探针算子审计（结构性不变量：between 模式比较位不得含 `>`） ─────────

test('布尔通道 between：二分/长度探针全部 BETWEEN 形态且不含 `>`（采集面下限断言）', async () => {
  const secret = '5.7.40';
  const oracle = makeOracle(secret);
  const ctx = buildCtx(oracle, { fetchUsing: 'between' });
  await extractWithDeadline(() => ex.extractBoolean(ctx, 'version()'));
  // 豁免：false 基准（1=2）与等值验证（=C）——`=` 被过滤时整条通道本就不要命，非本开关可救
  const probes = oracle.seen.filter((q) => !q.includes('1=2') && !/SUBSTR(?:ING)?\(\(.*?,\s*\d+,\s*1\)+\s*=/.test(q));
  const betweenProbes = probes.filter((q) => /\sBETWEEN\s\d+\sAND\s\d+/.test(q));
  // 采集面下限：between 探针必须真出现过（长度 + 字符两类都要有），否则判据空转
  assert.ok(betweenProbes.length >= 10, `between 探针数量异常：${betweenProbes.length}`);
  assert.ok(probes.some((q) => /LENGTH\(\(.*?\)+\s+BETWEEN/.test(q)), '长度探针未走 BETWEEN');
  assert.ok(probes.some((q) => /SUBSTR(?:ING)?\(\(.*?,\s*\d+,\s*1\)+\s+BETWEEN/.test(q)), '字符探针未走 BETWEEN');
  for (const q of betweenProbes) {
    assert.ok(!q.includes('>'), `between 探针比较位混入 >：${q}`);
  }
});

// ── ④ 能力判据：WAF 过滤 `>` 时 gt 失败（诚实 null）、between 成功 ──────

test('WAF 过滤 `>`：gt 模式返回 null（不造值），between 模式照常提取', async () => {
  const secret = '5.7.40';
  const gtCtx = buildCtx(makeOracle(secret, { blockGt: true }));
  assert.equal(await ex.extractBoolean(gtCtx, 'version()'), null,
    'gt 模式在 `>` 被过滤时必须诚实失败，不得输出垃圾值');
  const btCtx = buildCtx(makeOracle(secret, { blockGt: true }), { fetchUsing: 'between' });
  assert.equal(await extractWithDeadline(() => ex.extractBoolean(btCtx, 'version()')), secret);
});

// ── ⑤ 长值延伸段 between（>255 走 [256, blindMaxLen] 续段） ────────────

test('长值延伸：between 模式在 [256,blindMaxLen] 续段提取与 gt 一致', async () => {
  const secret = 'x'.repeat(260);
  const cfg = { blindMaxLen: 280 };
  const gt = await ex.extractBoolean(buildCtx(makeOracle(secret), cfg), 'version()');
  assert.equal(gt.length, 260, 'gt 延伸段基线：260 字符长值');
  const bt = await extractWithDeadline(() => ex.extractBoolean(buildCtx(makeOracle(secret), { ...cfg, fetchUsing: 'between' }), 'version()'));
  assert.equal(bt, secret);
});

// ── ⑥ 时间通道三连 ────────────────────────────────────────────────────

// [D165 2026-10-25] 平台时钟预算：共享 CI runner（实测 macOS）的 setTimeout 抖动可达
// ±100ms，吃掉固定余量 ⇒ 两种病征交替出现：判别余量（FALSE≈BASE vs 阈值 BASE+20，仅
// 20ms）被吃 → 错提取；累计时长（between 上百探针）被推过 30s 死循环检测线。三档常数
// **等比**放大 = 时钟变慢、判别比例 40:80:20 不变 ⇒ 引擎判定语义零变化（不是放宽校准，
// 是把「时钟预算」随平台显式化）；30s 截止是死循环探测器，同倍放大。本地默认 1x。
const SCALE = process.env.TIME_TEST_SCALE
  ? Number(process.env.TIME_TEST_SCALE)
  : process.env.CI && process.platform === 'darwin' ? 3 : 1;
const BASE_MS = 40 * SCALE;
const TRUE_EXTRA_MS = 80 * SCALE;
const ABS_THRESHOLD_MS = 20 * SCALE;
const DEADLINE_MS = 30000 * SCALE;

// 时间预言机：从 payload 解出条件（gt/between/= 全形态）判定真假；
// blockGt=true 模拟「`>` 被 WAF 过滤」——含 `>` 的 payload 不执行、不延迟。
function makeTimeOracle(secret, { blockGt = false } = {}) {
  const bytes = Array.from(new TextEncoder().encode(secret));
  const evalCond = (q) => {
    if (blockGt && q.includes('>')) return false;
    const lenBt = q.match(/LENGTH\(\(.*?\)+\s+BETWEEN\s+(\d+)\s+AND\s+(\d+)/);
    if (lenBt) return bytes.length >= Number(lenBt[1]) && bytes.length <= Number(lenBt[2]);
    const lenGt = q.match(/LENGTH\(\(.*?\)+\s*>\s*(\d+)/);
    if (lenGt) return Number(lenGt[1]) < bytes.length;
    const charBt = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s+BETWEEN\s+(\d+)\s+AND\s+(\d+)/i);
    if (charBt) {
      const code = bytes[Number(charBt[1]) - 1];
      return code >= Number(charBt[2]) && code <= Number(charBt[3]);
    }
    const charGt = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
    if (charGt) return Number(charGt[2]) < bytes[Number(charGt[1]) - 1];
    const eqM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*=\s*(\d+)/);
    if (eqM) return Number(eqM[2]) === bytes[Number(eqM[1]) - 1];
    const wholeM = q.match(/\(version\(\)\)='([^']*)'/);
    if (wholeM) return wholeM[1] === secret;
    return false;
  };
  return {
    async request(opts) {
      const q = extractQuery(opts);
      const extra = evalCond(q) ? TRUE_EXTRA_MS : 0;
      await new Promise((r) => setTimeout(r, BASE_MS + extra));
      return { data: 'OK', status: 200 };
    },
  };
}

function buildTimeCtx(oracle, extra = {}) {
  return {
    ...buildCtx(oracle, extra),
    config: {
      timeoutMs: 5000, retry: 0, timeThresholdMs: ABS_THRESHOLD_MS,
      extractConcurrency: 1, ...extra,
    },
  };
}

// ── [D287] 时间通道「错值」形态的批内三抽归因（D280 A2 语义移植） ──────────
// 背景（D283 实测，reports/外部靶场复跑-2026-11-10.md）：五靶场 JVM 预热噪声下，
// 单抽硬钉的 :233/:245 各翻面一次（提取出 `5.7/40` / 越过终止符拖乱码），
// 单文件 ×3 复跑 33/33 ⇒ 非确定性缺陷，不是产品代码回归。D283 边界明说
// 「加批内重抽属 [D280] 已知取舍，另立批次再做不迟」——本批即该批次。
// 语义**照抄** D280 在 extractor.timeDrift.test.js 定下的三抽归因，不许另写宽口径：
//   · 请求数预算内：错值先重抽，任一抽真值 ⇒ 环境归因通过，但 console.warn 大声登记疑似翻面；
//   · 三抽全错且请求数稳定 ⇒ 确定性污染，带全部错值红；
//   · 请求数发散（max > min×3）⇒ 环境本身不稳，不归因、原样红；
//   · DEADLINE 截止（死循环探测器）触发 ⇒ 不是「错值」是挂死，不重抽、当场红（保住原语义）。
// 绿抽零开销：命中即断，只有翻面时才付重抽成本（正常套件耗时不变）。
function countingClient(oracle) {
  const state = { requests: 0 };
  return {
    state,
    async request(opts) {
      state.requests++;
      return oracle.request(opts);
    },
  };
}

/**
 * 三抽提取 + 归因判定（提取值必须等于 secret；详见上方 D287 注释）。
 * @param {object} ctx buildTimeCtx 产物
 * @param {string} secret 期望真值
 * @param {{requests:number}} clientState countingClient 的计数器
 * @returns {Promise<{ok: boolean, attempts: Array<{value: string|null, requests: number}>, reason?: string, flipped?: boolean}>}
 */
async function extractTimeAttributed(ctx, secret, clientState) {
  const attempts = [];
  for (let i = 0; i < 3; i++) {
    const before = clientState.requests;
    let value;
    try {
      value = await extractWithDeadline(() => ex.extractTime(ctx, 'version()'), DEADLINE_MS);
    } catch (e) {
      attempts.push({ value: `<<deadline>>`, requests: clientState.requests - before });
      return {
        ok: false,
        attempts,
        reason: `第 ${i + 1}/3 抽超 ${DEADLINE_MS}ms 截止（死循环探测器触发，挂死不是错值，不归因）：${e.message}`,
      };
    }
    attempts.push({ value, requests: clientState.requests - before });
    if (value === secret) {
      if (i > 0) {
        console.warn(
          `⚠️ [D287] 疑似环境翻面：第 ${i + 1}/3 抽才出真值，此前错值 ` +
            `${attempts.slice(0, i).map((a) => JSON.stringify(a.value)).join('、')}，请求数 ` +
            `${attempts.map((a) => a.requests).join('/')}——按 D280 A2 环境归因放行并大声登记`
        );
      }
      return { ok: true, attempts, flipped: i > 0 };
    }
  }
  const reqs = attempts.map((a) => a.requests);
  const diverged = Math.max(...reqs) > Math.min(...reqs) * 3;
  return {
    ok: false,
    attempts,
    reason: diverged
      ? `三抽全错且请求数发散（${reqs.join('/')}）——不归因，按确定性异常处理`
      : `三抽全错且请求数稳定（${reqs.join('/')}）——确定性污染`,
  };
}

test('时间通道 gt（默认）：慢目标上正确提取（回归钉；D287 三抽归因）', async () => {
  const secret = '5.7.40';
  const client = countingClient(makeTimeOracle(secret));
  const ctx = buildTimeCtx(client);
  const r = await extractTimeAttributed(ctx, secret, client.state);
  assert.equal(r.ok, true, `时间通道 gt 错值未归因：${r.reason}；各抽=${JSON.stringify(r.attempts)}`);
});

test('时间通道 between：同一 secret 提取结果与 gt 一致（D287 三抽归因）', async () => {
  const secret = '5.7.40';
  const client = countingClient(makeTimeOracle(secret));
  const ctx = buildTimeCtx(client, { fetchUsing: 'between' });
  const r = await extractTimeAttributed(ctx, secret, client.state);
  assert.equal(r.ok, true, `时间通道 between 错值未归因：${r.reason}；各抽=${JSON.stringify(r.attempts)}`);
});

test('时间通道 WAF 过滤 `>`：between 模式仍可提取（gt 恒假失败；D287 三抽归因）', async () => {
  const secret = '5.7.40';
  const client = countingClient(makeTimeOracle(secret, { blockGt: true }));
  const ctx = buildTimeCtx(client, { fetchUsing: 'between' });
  const r = await extractTimeAttributed(ctx, secret, client.state);
  assert.equal(r.ok, true, `时间通道 blockGt 错值未归因：${r.reason}；各抽=${JSON.stringify(r.attempts)}`);
});

// [D287] 归因判据有牙的自钉：确定性污染形态（预言机恒答空 ⇒ 永远提不出真值）
// 必须在三抽后判红并给出「确定性污染」归因，不许被三抽重抽洗成绿。
test('[D287] 归因判据有牙：三抽全错且请求数稳定 ⇒ 确定性污染，必须红', async () => {
  const secret = '5.7.40';
  const deadOracle = {
    async request() {
      return { data: '', status: 200 }; // 恒空、恒瞬时：时间通道没有任何真值可提
    },
  };
  const client = countingClient(deadOracle);
  const ctx = buildTimeCtx(client);
  const r = await extractTimeAttributed(ctx, secret, client.state);
  assert.equal(r.ok, false, '恒空预言机在三抽重抽后仍被判绿 ⇒ 归因判据没牙（把污染洗成环境噪声）');
  assert.match(r.reason, /三抽全错且请求数稳定（.*）——确定性污染/, `归因口径不符：${r.reason}`);
  assert.equal(r.attempts.length, 3, `应恰三次抽取，实际 ${r.attempts.length}`);
  assert.ok(
    r.attempts.every((a) => a.value !== secret),
    `三抽里出现了真值却没判 ok，判定自相矛盾：${JSON.stringify(r.attempts)}`
  );
});
