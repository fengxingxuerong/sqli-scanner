// ============================================================================
// tests/extractor.timeBaseline.test.js —— 时间提取的判定阈值必须含目标基线
//
// 判据本体（blindExtractor.js extractTime）：注释写「以基线耗时 + timeThresholdMs 为准，
// 避免目标本身慢造成误判」，代码却是 thresholdMs = config.timeThresholdMs —— **基线没加**。
// 于是自身响应就慢于阈值的目标（内网大页面、跨地域、带渲染开销的业务页）上，
// 「耗时 ≥ 阈值」对**任何**条件都成立 → 逐字节恒判真。
//
// 后果不是「返回一个错值」而是**失控**：长度二分恒判真 → 顶到 blindMaxLen 上界（默认 65535）
// → 逐位置提取循环 65535 次。所以本文件三条断言都带截止时间：修复后秒级完成，
// 未修复则根本跑不完（现场即证据）。
//
// 本仓另外三条时间路径都已补基线，唯独提取通道漏了 —— 而它正是拖库时输出
// 「看起来像数据」的那一段：
//   · detectors/TimeBlindDetector.js  threshold = max(μ + z·σ, μ + floor)
//   · detectors/StackedDetector.js    effectiveThreshold = max(阈值, baselineMs + sleep/2)
//   · DBFingerprinter.js              effThreshold = baselineRtt + thresholdMs
//
// 两个方向都要锁：
//   ① 慢目标 + 从不延迟 → 必须判「取不出」（不得凭空造值）；
//   ② 慢目标 + 真条件确有额外延迟 → 必须还原出正确值（修复不能退化成「一律判假」）。
// 单次基线对抖动敏感 ⇒ 与 StackedDetector 同取 3 样本中位数，全失败才回落 0。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';

// 目标自身耗时 60ms；「条件为真」额外 90ms；配置阈值 25ms —— **低于基线**，
// 故不补基线的实现会把每次请求都读成「条件为真」。余量各 ≥25ms，Windows 定时器抖动可容忍。
const BASE_MS = 60;
const TRUE_EXTRA_MS = 90;
const ABS_THRESHOLD_MS = 25;
// 修复后本文件的提取在 ~3s 内完成；未修复要跑数十分钟。取 15s 是两侧都远离的判定点。
const DEADLINE_MS = 15000;

function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  return '';
}

// MySQL 时间预言机：从 payload 解出条件、按真实值判定，真条件多延迟 TRUE_EXTRA_MS。
// 条件形状与 extractor.timeCharset.test.js 同源（LEN> / BETWEEN / > / = / 整值复验）。
function makeSlowOracle(secret, { neverTrue = false } = {}) {
  const bytes = Array.from(new TextEncoder().encode(secret));
  const evalCond = (q) => {
    if (neverTrue) return false;
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
  const stats = { total: 0, withSleep: 0, dead: false };
  return {
    stats,
    async request(opts) {
      // 断言已出结论/已超时后把在途循环掐掉：否则失控的那一轮会在测试结束后继续发请求。
      if (stats.dead) throw new Error('测试已结束，停止本次提取');
      const q = extractQuery(opts);
      stats.total++;
      if (/SLEEP\(/.test(q)) stats.withSleep++;
      const extra = evalCond(q) ? TRUE_EXTRA_MS : 0;
      await new Promise((r) => setTimeout(r, BASE_MS + extra));
      return { data: 'OK', status: 200 };
    },
  };
}

function buildCtx(oracle, scanId) {
  return {
    httpClient: oracle,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: true },
    dbms: 'MySQL',
    scanId,
    config: {
      timeoutMs: 5000,
      retry: 0,
      timeThresholdMs: ABS_THRESHOLD_MS,
      extractConcurrency: 4,
    },
  };
}

/** 带截止时间的提取：超时即判红（未修复时的失控形态），并在收尾掐掉在途请求。 */
async function extractWithDeadline(ex, ctx, oracle, expr) {
  let timer;
  const kill = new Promise((_, rej) => {
    timer = setTimeout(() => rej(Object.assign(new Error('DEADLINE'), { deadline: true })), DEADLINE_MS);
  });
  try {
    return await Promise.race([ex.extractTime(ctx, expr), kill]);
  } catch (e) {
    if (e && e.deadline) {
      assert.fail(
        `提取在 ${DEADLINE_MS}ms 内没跑完：阈值未含基线 ⇒ 长度二分恒判真顶到 65535 上界 ⇒ ` +
          `逐位置循环失控（已发请求 ${oracle.stats.total} 个）。这就是慢目标上「恒判真」的真实后果。`
      );
    }
    throw e;
  } finally {
    clearTimeout(timer);
    oracle.stats.dead = true;
  }
}

test('★假数据★ 慢目标上从不延迟的注入点：必须判「取不出」而非凭空造值', async () => {
  const oracle = makeSlowOracle('8.0.36', { neverTrue: true });
  const out = await extractWithDeadline(new Extractor(), buildCtx(oracle, 'tb-null'), oracle, 'version()');
  assert.equal(
    out,
    null,
    `阈值未含基线时「耗时 ≥ ${ABS_THRESHOLD_MS}ms」对每次请求都成立 ⇒ 恒判真。实际返回 ${JSON.stringify(out)}`
  );
});

test('慢目标 + 真条件确有额外延迟：补基线后仍要还原出正确值（不得退化成一律判假）', async () => {
  const secret = '8036';
  const oracle = makeSlowOracle(secret);
  const out = await extractWithDeadline(new Extractor(), buildCtx(oracle, 'tb-ok'), oracle, 'version()');
  assert.equal(out, secret, `慢站上应仍能正确提取，实际 ${JSON.stringify(out)}`);
});

test('基线采样不得失控：只允许 3 个不含 SLEEP 的请求', async () => {
  // 提取通道每个判定探针都带 SLEEP(...)，只有基线采样不带 ⇒ total - withSleep 即基线成本。
  // 这条是护栏：防「为降噪把基线改成几十次采样」把请求预算吃掉（本仓有 request-budget 探针）。
  const oracle = makeSlowOracle('8036');
  await extractWithDeadline(new Extractor(), buildCtx(oracle, 'tb-cost'), oracle, 'version()');
  const nonSleep = oracle.stats.total - oracle.stats.withSleep;
  assert.ok(nonSleep <= 3, `基线请求应 ≤3 个（3 样本取中位数），实际 ${nonSleep} 个 / 总请求 ${oracle.stats.total}`);
  assert.ok(oracle.stats.withSleep > 0, '预言机未收到任何 SLEEP 探针，本用例等于空断言');
});
