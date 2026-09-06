// [B-perf 收尾] 时间盲注通道数字字符集收窄测试（与布尔通道 extractor.charset.test.js 同构）
// 覆盖：
//   1) 纯数字场景：每字符 1 次类探测 + ≤4 轮 [48,57] 二分 + 1 次等值验证（8 → ~6 探测），
//      每探测真实 sleep，数字密集值（ID/计数/价格）拖库墙钟显著下降
//   2) 混合场景（数字+点）：类外字符回退全区间，最坏 +1 探测但收敛值不变
//   3) 类探测被污染（恒真谎言）：等值验证失败 → 回退全区间重测 → 收敛正确
//   4) extractVerify 关闭：不启用收窄（零类探测/零等值探测），全区间二分收敛不变
//   5) 多字节字符（UTF-8）：类外回退全区间，还原正确
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';

// 时间预言机：条件为真才真实延迟（≥ timeThresholdMs），与真实目标「IF(cond, SLEEP(n), 0)」同构。
// 延迟取 30ms / 阈值 15ms：真条件稳定超阈、假条件立即返回，测试墙钟 <1s/用例。
const DELAY_MS = 30;

function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  return '';
}

function makeTimeOracle(secret, { lieDigitsAt = [] } = {}) {
  const bytes = Array.from(new TextEncoder().encode(secret));
  const stats = { lenProbes: 0, betweenProbes: 0, gtProbes: 0, eqProbes: 0, wholeProbes: 0 };
  const liars = new Set(lieDigitsAt);
  const evalCond = (q) => {
    const lenM = q.match(/(?:LENGTH|LEN)\(\(.*?\)+\s*>\s*(\d+)/);
    if (lenM) {
      stats.lenProbes++;
      return Number(lenM[1]) < bytes.length;
    }
    const btwM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)\)?\s*BETWEEN\s+(\d+)\s+AND\s+(\d+)/i);
    if (btwM) {
      stats.betweenProbes++;
      const pos = Number(btwM[1]);
      if (liars.has(pos)) return true; // 污染：恒报数字类命中
      const code = bytes[pos - 1];
      return code >= Number(btwM[2]) && code <= Number(btwM[3]);
    }
    const charM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
    if (charM) {
      stats.gtProbes++;
      return Number(charM[2]) < bytes[Number(charM[1]) - 1];
    }
    const eqM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*=\s*(\d+)/);
    if (eqM) {
      stats.eqProbes++;
      return Number(eqM[2]) === bytes[Number(eqM[1]) - 1];
    }
    const wholeM = q.match(/\(version\(\)\)='([^']*)'/);
    if (wholeM) {
      stats.wholeProbes++;
      return wholeM[1] === secret;
    }
    return false;
  };
  return {
    stats,
    async request(opts) {
      const cond = evalCond(extractQuery(opts));
      if (cond) await new Promise((r) => setTimeout(r, DELAY_MS));
      return { data: 'OK', status: 200 };
    },
  };
}

function buildCtx(oracle, config = {}) {
  return {
    httpClient: oracle,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: true },
    dbms: 'MySQL',
    scanId: 'time-charset-test',
    config: {
      timeoutMs: 5000,
      retry: 0,
      timeThresholdMs: 15,
      extractConcurrency: 4,
      ...config,
    },
  };
}

test('时间通道收窄：纯数字场景每字符 ~6 探测（原 8），收敛值一致', async () => {
  const secret = '8036';
  const oracle = makeTimeOracle(secret);
  const out = await new Extractor().extractTime(buildCtx(oracle), 'version()');
  assert.equal(out, secret);
  assert.equal(oracle.stats.betweenProbes, secret.length, '每个数字字符应命中 1 次类探测');
  assert.equal(oracle.stats.eqProbes, secret.length, '每个收窄字符应有 1 次等值验证');
  assert.ok(
    oracle.stats.gtProbes <= secret.length * 4,
    `[48,57] 二分应 ≤4 轮/字符，实际 gt 总数 ${oracle.stats.gtProbes}`
  );
  const total = oracle.stats.betweenProbes + oracle.stats.gtProbes + oracle.stats.eqProbes;
  assert.ok(total < secret.length * 8, `总探测应少于全区间 8/字符（${secret.length * 8}），实际 ${total}`);
});

test('时间通道收窄：版本串（数字+点）混合场景类外字符回退全区间，收敛值不变', async () => {
  const secret = '5.7.40';
  const oracle = makeTimeOracle(secret);
  const out = await new Extractor().extractTime(buildCtx(oracle), 'version()');
  assert.equal(out, secret);
  // 4 个数字（1 类探测 + ≤4 二分 + 1 验证）+ 2 个 '.'（1 类探测未命中 + 8 轮全区间）
  assert.equal(oracle.stats.betweenProbes, 4 * 1 + 2 * 1);
  assert.equal(oracle.stats.eqProbes, 4, '仅收窄命中的位置发等值验证');
  assert.equal(oracle.stats.wholeProbes, 1, '完整值复验仍发 1 次');
});

test('时间通道收窄：类探测被污染（恒报数字命中）→ 等值验证失败回退全区间，收敛正确', async () => {
  const secret = 'xyz'; // 'x'=120 非数字，但预言机对 pos1 谎报数字命中
  const oracle = makeTimeOracle(secret, { lieDigitsAt: [1] });
  const out = await new Extractor().extractTime(buildCtx(oracle), 'version()');
  assert.equal(out, secret, '污染的类探测应被等值验证发现并回退全区间重测');
});

test('时间通道收窄：extractVerify 关闭时不启用收窄（零类/零等值探测），收敛不变', async () => {
  const secret = '8.0.36';
  const oracle = makeTimeOracle(secret);
  const out = await new Extractor().extractTime(
    buildCtx(oracle, { blindRobust: { extractVerify: false } }),
    'version()'
  );
  assert.equal(out, secret);
  assert.equal(oracle.stats.betweenProbes, 0, 'extractVerify 关闭时不应发类探测');
  assert.equal(oracle.stats.eqProbes, 0, 'extractVerify 关闭时不应发等值验证');
});

test('时间通道收窄：多字节字符（UTF-8）与收窄共存，还原正确', async () => {
  const secret = '版本8.0';
  const oracle = makeTimeOracle(secret);
  const out = await new Extractor().extractTime(buildCtx(oracle), 'version()');
  assert.equal(out, secret);
});
