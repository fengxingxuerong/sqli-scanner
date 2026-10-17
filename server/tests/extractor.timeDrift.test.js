// ============================================================================
// tests/extractor.timeDrift.test.js —— 时间提取的基线不能「开头测一次、用到尾」
// ============================================================================
// 判据本体（blindExtractor.js extractTime，[D53]）：
//
// 阈值 = 目标自身耗时 + timeThresholdMs。D47 补上了「基线」这一项，但**只在提取开头
// 采 3 个样本取中位数，之后整条链共用一个固定阈值**。而一条时间提取链动辄几十个探针
// （长度二分 ~8 + 逐字节 8 轮 × N + 等值验证 + 整值复验），目标自身耗时在这期间会漂：
// 应用预热、下游负载爬升、同机其他扫描并发、缓存过期后回源……
//
// 漂移一旦吃掉 timeThresholdMs 那点余量，「耗时 ≥ 阈值」对**任何**条件都成立 ⇒ 恒判真。
// 这不是「值偏一点」，而是两种形态：
//   ① 撞长度上界 ⇒ 逐位置循环失控（挂死，反倒容易发现）；
//   ② ★ 长度先收敛、逐字节再全判真 ⇒ 产出 "5:::::" 这种**看着像数据的错值** ——
//      而 extractVerify 的整值复验失败**只标 low 置信、不重测**（见 extractTime 尾部
//      注释），错值不会被自动纠正，一路进报告。② 比 ① 危险得多。
//
// 修法（[D53]）：判假探针的耗时就是干净的 RTT（条件为假 ⇒ 服务端没执行 SLEEP），
// 一次正常二分约半数探针判假 ⇒ **免费、连续**的基线样本流，阈值随之实时重算；
// 只有连续 timeBaselineEvery 个探针都没拿到干净样本（已经恒判真 / 请求失败）时，
// 才补发一次「不注入条件」的原值请求 ⇒ 健康提取零额外请求。
// ⚠ 请求失败的探针绝不入样：异常几乎瞬时返回，elapsed≈0 会把基线拽下去 ⇒
//   阈值被压低 ⇒ 反过来制造恒判真（与要修的故障同形，最讽刺的一种自伤）。
//
// ── 两档标定（都实测过，别随手改常数）────────────────────────────────────
//  · TIGHT（余量 25ms / 真侧 90ms）：沿用 extractor.timeBaseline.test.js 的口径，
//    探针便宜，用来跑「多种漂移速率」的矩阵；代价是余量极小，跟踪器的容限也极小。
//  · REALISTIC（余量 300ms / 真侧 320ms）：贴近 timeThresholdMs 的默认量级，
//    用 1 字节 secret 把探针压到 ~18 个，证明**不是只在极端小余量下才有效**。
//
// ⚠ 如实标注的能力上限：跟踪器能扛住的漂移速率 ≈ 余量 / 滞后（滞后 ≈ 2 个探针）。
//    TIGHT 档余量 25ms ⇒ 约 2ms/探针；实测 drift=8ms/探针 @ 余量 25ms **仍会失控**
//    （下方用例只钉「关掉跟踪会失控」，没钉「开着一定救得回来」——救不回来就不许吹）。
//    默认 timeThresholdMs=1500ms 时容限约 150ms/探针，远超真实业务的漂移速率。
//
// ── 墙钟预算与截止时间（2026-10-14 D64，CI windows 实测后重标）────────────────
// 事故：同一份代码，CI windows #228 故障② 6.7s 通过、#229 同一条用例 30s 截止没跑完
// （超时时已发 142 个请求还在发）。算一笔账就明白为什么「本机 6.2s / 截止 30s」的
// 4.8 倍余量是假的：oracle 的单请求延迟 = 60 + 2×请求数（累计漂移）随计数线性增长，
//    Σ(60+2i), i=1..142 ≈ 28.8s + 真侧附加 ≈ 30s+ —— **零通胀下二次项本身就吃满 30s**。
// 请求数一发散，墙钟随即爆管。发散机制（本机噪声模型复现 + 算账双重确认）：
//   TIGHT 档 25ms 余量在**长度二分阶段只剩 5-9ms 净空**（漂移在请求 10-12 时已吃掉
//   大半余量，而长度探针就在那几个请求上）⇒ runner 噪声（windows 2 vCPU 共享 +
//   Defender 实时扫描 + 定时器粒度，本机实测各模型 ±10~40ms）翻面长度探针 ⇒
//   长度收敛虚高（L≈30）⇒ 位置数翻 5 倍 ⇒ 请求数 47 → 200+。请求数呈**重尾分布**
//   （本机/ubuntu 47~54，windows 观测到 142+，合成最坏 212），截止必须按尾部定。
// 修法（只重定截止时间；不碰断言、不碰标定、不碰 oracle 模型）：
//  故障② 30s→90s（覆盖 ~300 请求 ≈ 85s，即观测尾部的 2 倍）；2026-10-17 D95 再于
//   macos 实测（269 请求仍顶爆 90s）后重标 90s→150s；同日 D96 macos 二连实锤
//   （356 请求仍在发）后，故障② 由墙钟截止**改为请求预算制**（见 extractWithBudget：
//   墙钟 = Σ(60+2i) 随 N 二次增长，按墙钟定预算等于赌 runner 噪声尾部）；故障③ 20s→60s
//   （REALISTIC 档单请求 ~1s，正常 17 请求就要 ~17s，原 20s 截止余量近零，
//    本机 stall 模型实测一次停顿就双杀）；修复③ 20s→45s（同档预防）。
//  [D96 补] 故障③ 再加抽样化：macos #263 单抽未复现（原因见该用例内注释：首采样停顿
//   抬高阈值 ⇒ 腐蚀点出搜索窗口）。∃抽样判定，4 抽上限；修复③ 保持单抽 ∀-正确。
//  修复① 保持 30s：跟踪开启后 CI 三平台实测 8.4~8.7s 零通胀，3.4 倍余量足够——
//  故意不放宽，跟踪器回归要能快速红。失控形态的快速探测由故障① 的 6s hangs
//  负责，故障侧的 90s/60s 截止只是防挂死 suite，不是失控判据。
//
// ⚠ 试过并**驳回**的方案（记录在此免得后人再走一遍）：
//  ① 给累计漂移封顶（driftMs × min(N, CAP)）：CAP=25 时初始基线采样被噪声抬高
//     +30ms ⇒ 阈值（119ms）高于平台期延迟（110ms）⇒ 永不交叉 ⇒ 提取正确 ⇒
//     「没打到故障」。**不封顶的无界增长是「故障必然复现」的承重墙**，封顶把它拆了。
//     且按请求数封顶对 REALISTIC 档（drift=30ms/探针）给出 +3000ms 的荒谬上限。
//  ② 故障侧关 per-byte 等值验证（去重试乘数）：本机实测对尾部无效（长度通胀与
//     验证无关，seed 99 仍 212 请求），还把修复① 的自愈承重墙拆了（它开始产出错值）。
//  ③ 放大 TIGHT 余量抗噪声：长度阶段是稳健了，但真/假侧间隔从 65ms 压到 30ms，
//     字节阶段开始翻面——把一个脆弱换成另一个脆弱，且要连带改两个标定常数，证据不足。
//   结论：二次项与长度通胀是 oracle 模型+标定的固有属性，靠截止时间兜底。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';
import { resolveTimeBaselineEvery } from '../src/engine/blindExtractor.js';

const BASE_MS = 60; // 目标自身基线耗时

// 两档标定（见文件头「两档标定」）
const TIGHT = { absMs: 25, trueExtraMs: 90 };
const REALISTIC = { absMs: 300, trueExtraMs: 320 };

function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  return '';
}

/**
 * MySQL 时间预言机（可选漂移 / 可选注入失败）。
 * @param {string} secret
 * @param {{driftMs?: number, trueExtraMs?: number, throwWhen?: (q: string) => boolean,
 *          failAfterMs?: number}} [opts] failAfterMs>0 = 先耗掉这么多毫秒再抛（模拟超时）
 */
function makeDriftOracle(secret, { driftMs = 0, trueExtraMs = 90, throwWhen = null, failAfterMs = 0 } = {}) {
  const bytes = Array.from(new TextEncoder().encode(secret));
  const evalCond = (q) => {
    const lenM = q.match(/(?:LENGTH|LEN)\(\(.*?\)+\s*>\s*(\d+)/);
    if (lenM) return Number(lenM[1]) < bytes.length;
    const btwM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)\)?\s*BETWEEN\s+(\d+)\s+AND\s+(\d+)/i);
    if (btwM) {
      const code = bytes[Number(btwM[1]) - 1];
      return code >= Number(btwM[2]) && code <= Number(btwM[3]);
    }
    const charM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
    if (charM) return Number(charM[2]) < bytes[Number(charM[1]) - 1];
    const eqM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*=\s*(\d+)/);
    if (eqM) return Number(eqM[2]) === bytes[Number(eqM[1]) - 1];
    const wholeM = q.match(/\(version\(\)\)='([^']*)'/);
    if (wholeM) return wholeM[1] === secret;
    return false;
  };
  const stats = { total: 0, withSleep: 0, baselineLike: 0, thrown: 0, dead: false };
  return {
    stats,
    async request(opts) {
      // 断言已出结论后把在途循环掐掉：否则失控的那一轮会在测试结束后继续发请求。
      if (stats.dead) throw new Error('测试已结束，停止本次提取');
      const q = extractQuery(opts);
      stats.total++;
      if (/SLEEP\(/.test(q)) stats.withSleep++;
      else stats.baselineLike++; // 开头基线采样与后续补采都不含 SLEEP
      if (throwWhen && throwWhen(q)) {
        stats.thrown++;
        if (failAfterMs > 0) await new Promise((r) => setTimeout(r, failAfterMs));
        throw new Error('模拟网络失败');
      }
      const extra = evalCond(q) ? trueExtraMs : 0;
      await new Promise((r) => setTimeout(r, BASE_MS + driftMs * stats.total + extra));
      return { data: 'OK', status: 200 };
    },
  };
}

function buildCtx(oracle, scanId, { absMs = TIGHT.absMs, ...rest } = {}) {
  return {
    httpClient: oracle,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: true },
    dbms: 'MySQL',
    scanId,
    config: { timeoutMs: 30000, retry: 0, timeThresholdMs: absMs, extractConcurrency: 4, ...rest },
  };
}

/** 带截止时间的提取：超时即判红（失控形态），并在收尾掐掉在途请求。 */
async function extractWithDeadline(ex, ctx, oracle, expr, deadlineMs = 30000) {
  let timer;
  const kill = new Promise((_, rej) => {
    timer = setTimeout(() => rej(Object.assign(new Error('DEADLINE'), { deadline: true })), deadlineMs);
  });
  try {
    return await Promise.race([ex.extractTime(ctx, expr), kill]);
  } catch (e) {
    if (e && e.deadline) {
      assert.fail(
        `提取在 ${deadlineMs}ms 内没跑完：基线未随漂移重算 ⇒ 恒判真 ⇒ 长度顶到上界 ⇒ ` +
          `逐位置循环失控（已发请求 ${oracle.stats.total} 个）。`
      );
    }
    throw e;
  } finally {
    clearTimeout(timer);
    oracle.stats.dead = true;
  }
}

/**
 * 带**请求预算**的提取（[D96] 故障② 专用）：完成 → 返回提取值；请求数越过 cap
 * 仍未完成 → 抛 `RUNAWAY`（失控，与故障① 同族）。另设挂死外闸（hangMs）：既没完成、
 * 请求数也不增长 ⇒ 真挂死，判红。
 *
 * 为什么从墙钟截止改成请求预算：故障② 的失控形态在慢 runner 上是**重尾**的 ——
 * linux 收敛只需 47~54 个请求；windows 观测 142+；macos 两次实测在 90s/150s 墙钟
 * 截止下已发 269/356 个请求仍在发（D64 重标 → D95 再重标 → 同日被二连击穿）。
 * 每请求延迟 = 60+2i(ms) 由 oracle 模型决定 ⇒ 墙钟 = Σover N 随 N 二次增长，
 * 按墙钟定预算等于在赌 runner 的噪声尾部；请求数才是判定「有没有失控」的稳定量。
 */
async function extractWithBudget(ex, ctx, oracle, expr, { cap = 256, hangMs = 300000 } = {}) {
  let hangTimer;
  const poll = (async () => {
    for (;;) {
      if (oracle.stats.dead) return; // 提取已收尾
      if (oracle.stats.total > cap) throw Object.assign(new Error('RUNAWAY'), { runaway: true });
      await new Promise((r) => setTimeout(r, 50));
    }
  })();
  const hang = new Promise((_, rej) => {
    hangTimer = setTimeout(() => rej(Object.assign(new Error('HANG'), { hang: true })), hangMs);
  });
  try {
    return await Promise.race([ex.extractTime(ctx, expr), poll, hang]);
  } catch (e) {
    if (e && e.hang) {
      assert.fail(
        `提取在 ${hangMs}ms 内既没完成、请求数也没越过预算 ${cap}（已发 ${oracle.stats.total} 个）` +
          '—— 真挂死，不是重尾（这是防挂死外闸，不是失控判据）。'
      );
    }
    throw e;
  } finally {
    clearTimeout(hangTimer);
    oracle.stats.dead = true;
  }
}

/** 跑一次并在 deadlineMs 内没完成时为 true（用于钉「关闭跟踪 ⇒ 失控」） */
async function hangs(oracle, ctx, deadlineMs) {
  let timer;
  const kill = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('DEADLINE')), deadlineMs); });
  try {
    await Promise.race([new Extractor().extractTime(ctx, 'version()'), kill]);
    return false;
  } catch (e) {
    return e?.message === 'DEADLINE';
  } finally {
    clearTimeout(timer);
    oracle.stats.dead = true;
  }
}

// ── 故障侧：timeBaselineEvery=0 即退化成 D47 的「开头采一次用到尾」 ──────────────
// 三条故障断言是**修复断言的前提**：如果它们绿不了（说明故障在这些参数下不复现），
// 后面的修复断言就是在证明一个不存在的问题（自证陷阱）。

test('★故障①★ 关闭跟踪、快速漂移 ⇒ 恒判真 ⇒ 长度顶上界 ⇒ 失控挂死', async () => {
  const oracle = makeDriftOracle('5.7.40', { driftMs: 8 });
  const ctx = buildCtx(oracle, 'drift-off-fast', { absMs: TIGHT.absMs, timeBaselineEvery: 0 });
  assert.ok(
    await hangs(oracle, ctx, 6000),
    `关闭跟踪时应复现失控（6s 内跑不完）：实际已完成，请求 ${oracle.stats.total} 个 —— ` +
      '说明本用例没打到故障，后面的修复断言将失去意义（请调 driftMs，不要改断言）'
  );
});

test('★故障②★ 关闭跟踪、慢漂移 ⇒ 产出「看着像数据的错值」（比挂死更危险）', async () => {
  const secret = '5.7.40';
  const oracle = makeDriftOracle(secret, { driftMs: 2 });
  const ctx = buildCtx(oracle, 'drift-off-slow', { absMs: TIGHT.absMs, timeBaselineEvery: 0 });
  // [D64] 截止 30s→90s；[D95] 90s→150s（macos 269 请求顶爆）——同日 [D96] 150s 又被击穿
  // （356 请求仍在发），至此两次墙钟重标都被 runner 噪声尾部反杀，改为**请求预算**：
  //   判定 = 完成得错值（常规形态）OR 请求数越过预算（失控 = 故障复现，和故障① 同族 ——
  //   慢 runner 上慢漂移故障的退化解）。预算 256 = D64 合成最坏 212 × 1.2；健康路径
  //   （修复① 同组参数）只需 ~17 个请求，预算不会误触。断言内核不变：**不许提取正确**。
  let out = null;
  let runaway = false;
  try {
    out = await extractWithBudget(new Extractor(), ctx, oracle, 'version()');
  } catch (e) {
    if (e && e.runaway) runaway = true;
    else throw e;
  }
  if (runaway) {
    console.log(
      `[故障②] 以失控形态复现：请求 ${oracle.stats.total} 个越过预算仍未收敛` +
        '（慢 runner 上的退化解——故障确已打到，静默错值的"完成态"由快 runner 的 test-server 见证）'
    );
  } else {
    assert.notEqual(
      out,
      secret,
      `关闭跟踪时应复现静默错值（实测形态 "5\\u0000::::"）：实际却提取正确 —— ` +
        '说明本用例没打到故障（请调 driftMs，不要改断言）'
    );
  }
});

test('★故障②机制自证★ 请求预算不是装饰：失控路径必须在越过预算时抛 RUNAWAY', async () => {
  // 用故障① 的同组参数（快速漂移 ⇒ 必然失控）走预算路径、cap 压到 40：
  // 短墙钟内必须以 RUNAWAY 收场。否则 cap 分支就是**永不触发的死代码**，
  // 故障② 的「慢 runner 退化解」判定会静默失效（预算形同虚设）。
  const oracle = makeDriftOracle('5.7.40', { driftMs: 8 });
  const ctx = buildCtx(oracle, 'budget-probe', { absMs: TIGHT.absMs, timeBaselineEvery: 0 });
  let runaway = false;
  try {
    await extractWithBudget(new Extractor(), ctx, oracle, 'version()', { cap: 40 });
  } catch (e) {
    runaway = !!(e && e.runaway);
  }
  assert.ok(runaway, `失控路径必须在请求数越过预算时抛 RUNAWAY（实际请求 ${oracle.stats.total} 个）`);
});

test('★故障③★ 真实余量档（300ms）下同样出错：不是只在极端小余量下才坏', async () => {
  const secret = '8';
  // [D64] 截止 20s→60s（REALISTIC 档单请求 ~1s，正常 17 请求 ~17s，原 20s 截止余量近零）。
  // [D96 补] 抽样化：macos #263 单抽拿到正确值（#260 同参数同 runner 却复现）——机制是
  //   **首个基线采样吃到大停顿**（冷启动/GC stall ⊇ 300ms+）⇒ 阈值被同步抬高
  //   （threshold = tracker.ms + 300 ⇒ stall 直接抬高 onset）⇒ 腐蚀点（30ms×N ≥ stall+300）
  //   推迟出搜索窗口（~18 请求）⇒ 这一抽看不到故障。故障是**配置级**断言：跟踪关闭
  //   ⇒ 漂移最终必然腐蚀（不封顶增长是承重墙，见头部驳回方案①），但**何时**腐蚀受环境
  //   停顿调制。抽样无状态（每抽新 oracle）：stall 只推迟复现、不取消复现。
  //   判定 = ∃抽样出错（红 = 4 抽全对：该环境不可复现故障 ⇒ 修复断言前提失效，必须暴露）；
  //   修复侧相反 —— 跟踪开启必须**零抽样**泄漏（见修复③ 单抽恒正确）。
  const draws = 4;
  for (let draw = 1; draw <= draws; draw++) {
    const oracle = makeDriftOracle(secret, { driftMs: 30, trueExtraMs: REALISTIC.trueExtraMs });
    const ctx = buildCtx(oracle, `real-off-${draw}`, { absMs: REALISTIC.absMs, timeBaselineEvery: 0 });
    const out = await extractWithDeadline(new Extractor(), ctx, oracle, 'version()', 60000);
    if (out !== secret) {
      if (draw > 1) console.log(`[故障③] 第 ${draw} 抽样才复现错值（该抽请求 ${oracle.stats.total} 个；前 ${draw - 1} 抽被环境停顿遮蔽）`);
      return;
    }
  }
  assert.fail(
    `真实余量档关闭跟踪时应出错：连续 ${draws} 抽都拿到正确值 ${JSON.stringify(secret)} —— ` +
      '故障在该环境不可复现，后续修复断言失去前提（自证陷阱），不许静默放过。'
  );
});

// ── 修复侧 ──────────────────────────────────────────────────────────────────

test('★修复①★ 慢漂移 + 极小余量：跟踪后提取正确（故障② 的同一组参数）', async () => {
  const secret = '5.7.40';
  const oracle = makeDriftOracle(secret, { driftMs: 2 });
  const ctx = buildCtx(oracle, 'drift-on-slow', { absMs: TIGHT.absMs, timeBaselineEvery: 16 });
  const out = await extractWithDeadline(new Extractor(), ctx, oracle, 'version()');
  assert.equal(out, secret, `慢漂移目标上应正确提取，实际 ${JSON.stringify(out)}`);
});

test('★修复②★ 中等漂移 + 中等余量（4ms/探针 @ 60ms）：跟踪后提取正确', async () => {
  const secret = '5.7.40';
  const oracle = makeDriftOracle(secret, { driftMs: 4 });
  const ctx = buildCtx(oracle, 'drift-on-mid', { absMs: 60, timeBaselineEvery: 16 });
  const out = await extractWithDeadline(new Extractor(), ctx, oracle, 'version()');
  assert.equal(out, secret, `中等漂移目标上应正确提取，实际 ${JSON.stringify(out)}`);
});

test('★修复③★ 真实余量档（300ms @ 30ms/探针）：跟踪后提取正确（故障③ 同参数）', async () => {
  const secret = '8';
  const oracle = makeDriftOracle(secret, { driftMs: 30, trueExtraMs: REALISTIC.trueExtraMs });
  const ctx = buildCtx(oracle, 'real-on', { absMs: REALISTIC.absMs, timeBaselineEvery: 16 });
  // [D64] 截止 20s→45s：同故障③——REALISTIC 档单请求 ~1s，原截止余量近零
  const out = await extractWithDeadline(new Extractor(), ctx, oracle, 'version()', 45000);
  assert.equal(out, secret, `真实余量档应正确提取，实际 ${JSON.stringify(out)}`);
});

// ── 回归与护栏 ──────────────────────────────────────────────────────────────

test('稳定目标零回归：值正确，且不产生任何额外基线请求', async () => {
  // 健康提取中约半数探针判假 ⇒ 免费样本不断 ⇒ 欠采计数永远到不了阈值 ⇒
  // 补采请求数必须为 0（只保留开头那 3 个基线样本）。这条同时是请求预算护栏：
  // 防「为了跟踪漂移把基线改成每探针一采」把请求预算翻倍。
  const secret = '8036';
  const oracle = makeDriftOracle(secret, { driftMs: 0 });
  const ctx = buildCtx(oracle, 'stable', { absMs: TIGHT.absMs, timeBaselineEvery: 16 });
  const out = await extractWithDeadline(new Extractor(), ctx, oracle, 'version()');
  assert.equal(out, secret);
  assert.equal(
    oracle.stats.baselineLike,
    3,
    `稳定目标上基线类请求应恰为开头 3 个（判假探针的免费样本不花钱）：` +
      `实际 ${oracle.stats.baselineLike} 个 / 总请求 ${oracle.stats.total}`
  );
  assert.ok(oracle.stats.withSleep > 0, '预言机未收到任何 SLEEP 探针，本用例等于空断言');
});

test('欠采补采有界：额外基线请求 ≤ ceil(探针数 / every) + 1', async () => {
  const oracle = makeDriftOracle('5.7.40', { driftMs: 8 });
  const ctx = buildCtx(oracle, 'bounded', { absMs: TIGHT.absMs, timeBaselineEvery: 16 });
  // 本组参数超出跟踪容限（见文件头「能力上限」）⇒ 判定长期偏向真 ⇒ 拿不到免费样本
  // ⇒ 走补采路径。这里不断言结果，只断言**补采次数有界**：防「补采写成每探针一次」。
  try {
    await extractWithDeadline(new Extractor(), ctx, oracle, 'version()', 6000);
  } catch {
    /* 本组允许超时（已知容限外），只关心请求数 */
  }
  const extra = oracle.stats.baselineLike - 3;
  assert.ok(
    extra <= Math.ceil(oracle.stats.total / 16) + 1,
    `补采请求应有界（≤ ceil(${oracle.stats.total}/16)+1）：实际额外 ${extra} 个`
  );
});

test('请求失败的探针既不得入样、也不得参与判定（首次超时+重试成功的混合 elapsed 会被直接判真）', async () => {
  // 为什么用「超时」而不是「瞬时抛错」来测这条：
  // 跟踪器的下行方向由中位数兜底，瞬时抛错（elapsed≈0）根本打不动它 —— 拿 0 值测这条
  // 会得到一条**永远绿**的假判据（实测注入「失败也入样」后它照样绿）。真实且打得住的
  // 形态是**超时**。
  //
  // ⚠ 本用例真正钉住的根因不是「入样抬阈值」，而是**计时没随重试重置**（2026-10-13 实测）：
  //   _send 首次超时返回 null ⇒ 重试成功 ⇒ 但 elapsed 从首次起算 ≈ timeoutMs + 真实 RTT。
  //   这个混合值既不是 RTT 也不是失败，却必然 ≥ 阈值 ⇒ **这一次探针被直接判成「条件为真」**，
  //   连样本都不用入。表现：长度二分会在真值之上多收敛几位 ⇒ 提出 "8036\u0000\u0000\u0000\u0000"
  //   （尾部 NUL 是越界位置 ASCII('') 的产物）——一个看着像数据的错值，正是文件头说的危险形态 ②。
  //   摘掉 `t0 = Date.now()` 那行本用例即红（A/B 验过：对照 11/11 绿、变异 10/11 红）。
  //   同一处还须「失败绝不入样」：两个方向都会坏，缺一半都留红。
  const secret = '8036';
  let n = 0;
  const oracle = makeDriftOracle(secret, {
    driftMs: 0,
    failAfterMs: 1200, // 明显大于「真侧延迟 90ms + 余量 25ms」
    throwWhen: (q) => {
      if (!/SLEEP\(/.test(q)) return false;
      n += 1;
      return n === 5;
    },
  });
  const ctx = buildCtx(oracle, 'fail-probe', { absMs: TIGHT.absMs, timeBaselineEvery: 16 });
  const out = await extractWithDeadline(new Extractor(), ctx, oracle, 'version()');
  assert.equal(out, secret, `失败探针污染判定/基线时会提取出错值，实际 ${JSON.stringify(out)}`);
  assert.ok(oracle.stats.thrown >= 1, '模拟失败未命中，本用例等于空断言');
});

test('resolveTimeBaselineEvery：非法值硬拒，不静默回落（「传了没生效」红线）', () => {
  assert.equal(resolveTimeBaselineEvery({}), 16, '未配置取默认 16');
  assert.equal(resolveTimeBaselineEvery({ timeBaselineEvery: 0 }), 0, '0 = 关闭跟踪');
  assert.equal(resolveTimeBaselineEvery({ timeBaselineEvery: '32' }), 32, '数字串合法');
  for (const bad of [-1, 1.5, NaN, 'abc', '', '  ', true, false, {}, []]) {
    assert.throws(
      () => resolveTimeBaselineEvery({ timeBaselineEvery: bad }),
      /timeBaselineEvery/,
      `非法值 ${JSON.stringify(bad)} 应抛错而不是静默回落`
    );
  }
});

test('CLI 侧非法 --time-baseline-every 拒启动（入口同口径，不静默回落）', async () => {
  const { buildConfig, parseArgs } = await import('../bin/cli.js');
  for (const bad of ['-1', '1.5', 'abc', '']) {
    assert.throws(
      () => buildConfig(parseArgs(['--time-baseline-every', bad])),
      /--time-baseline-every/,
      `CLI 收到 ${JSON.stringify(bad)} 应拒启动`
    );
  }
  // buildConfig 在「无 -u 目标」分支直接返回配置对象本身（带 url 时才是 {config, targets}），
  // 两种形状都接住，免得这条断言变成对返回结构的隐式耦合。
  const ok = buildConfig(parseArgs(['--time-baseline-every', '8']));
  assert.equal((ok.config ?? ok).timeBaselineEvery, 8, '合法值应落到 config');
});
