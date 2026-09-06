// [B-perf] 盲注二分字符集收窄（对标 sqlmap --charset 思路）测试
// 覆盖：
//   1) 数字场景：每字符 1 次类探测 + 3-4 轮二分（8 → ~5 请求），收敛值与全区间完全一致
//   2) 小写字母场景：2 次类探测 + ~5 轮二分（8 → ~7 请求）
//   3) 类外字符（大写/符号）：回退全区间，最坏 +2 请求但收敛值不变（无回归）
//   4) 类探测被污染（恒真谎言）：等值验证失败 → 回退全区间重测 → 收敛正确
//   5) extractVerify 关闭时收敛不变；多字节字符（UTF-8）不受影响
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';

function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  return '';
}

// 完整布尔预言机：识别长度二分 / 字符类探测（BETWEEN）/ 字符二分（>）/ 字符等值（=）/ 完整值等值，
// 并按类别计数（用于验证收窄的请求节省）。字符级判定按 UTF-8 字节（与引擎 ASCII(SUBSTRING(...,1))
// 逐字节提取同构），完整值等值按解码后的字符串。
function makeCharsetOracle(secret, { lieDigitsAt = [] } = {}) {
  const bytes = Array.from(new TextEncoder().encode(secret));
  const stats = { lenProbes: 0, betweenProbes: 0, gtProbes: 0, eqProbes: 0, wholeProbes: 0 };
  const ret = (cond) => ({ data: cond ? 'OK' : '', status: 200 });
  const liars = new Set(lieDigitsAt);
  return {
    stats,
    async request(opts) {
      const q = extractQuery(opts);
      if (q.includes('1=2')) return ret(false);
      const lenM = q.match(/(?:LENGTH|LEN)\(\(.*?\)+\s*>\s*(\d+)/);
      if (lenM) {
        stats.lenProbes++;
        return ret(Number(lenM[1]) < bytes.length);
      }
      const btwM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)\)?\s*BETWEEN\s+(\d+)\s+AND\s+(\d+)/i);
      if (btwM) {
        stats.betweenProbes++;
        const pos = Number(btwM[1]);
        if (liars.has(pos)) return ret(true); // 污染：恒报数字类命中
        const code = bytes[pos - 1];
        return ret(code >= Number(btwM[2]) && code <= Number(btwM[3]));
      }
      const charM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
      if (charM) {
        stats.gtProbes++;
        return ret(Number(charM[2]) < bytes[Number(charM[1]) - 1]);
      }
      const eqM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*=\s*(\d+)/);
      if (eqM) {
        stats.eqProbes++;
        return ret(Number(eqM[2]) === bytes[Number(eqM[1]) - 1]);
      }
      const wholeM = q.match(/\(version\(\)\)='([^']*)'/);
      if (wholeM) {
        stats.wholeProbes++;
        return ret(wholeM[1] === secret);
      }
      return ret(false);
    },
  };
}

function buildCtx(oracle, config = {}) {
  // 每个用例独立 target 对象：predictOutput 值缓存按 target 身份隔离，避免跨用例串缓存
  return {
    httpClient: oracle,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: true },
    dbms: 'MySQL',
    scanId: 'charset-test',
    config: { timeoutMs: 5000, retry: 0, extractConcurrency: 4, ...config },
  };
}

test('字符集收窄：纯数字场景每字符 ~5 请求（原 8），收敛值与全区间一致', async () => {
  const secret = '1834567290'; // 10 个数字字符
  const oracle = makeCharsetOracle(secret);
  const out = await new Extractor().extractBoolean(buildCtx(oracle), 'version()');
  assert.equal(out, secret);
  // 每字符：1 次 BETWEEN 命中 + ≤4 轮 [48,57] 二分 = ≤5 请求（原固定 8）
  assert.equal(oracle.stats.betweenProbes, secret.length, '每个数字字符应命中 1 次类探测');
  assert.ok(
    oracle.stats.gtProbes <= secret.length * 4,
    `[48,57] 二分应 ≤4 轮/字符，实际 gt 总数 ${oracle.stats.gtProbes}`
  );
  const total = oracle.stats.betweenProbes + oracle.stats.gtProbes;
  assert.ok(total <= 50, `数字场景每字符 ≤5 请求，实际总计 ${total}`);
  assert.ok(total < secret.length * 8, `应少于全区间 8 轮/字符（${secret.length * 8}），实际 ${total}`);
});

test('字符集收窄：版本串（数字+点）混合场景总请求数下降，收敛值一致', async () => {
  const secret = '5.7.40';
  const oracle = makeCharsetOracle(secret);
  const out = await new Extractor().extractBoolean(buildCtx(oracle), 'version()');
  assert.equal(out, secret);
  // 数字 4 个（1 次类探测 + 3-4 轮）；'.'(46) 2 个（2 次类探测未命中 + 8 轮全区间）
  assert.equal(oracle.stats.betweenProbes, 8);
  const total = oracle.stats.betweenProbes + oracle.stats.gtProbes;
  assert.ok(total < secret.length * 8, `总字符请求数应低于旧实现 48，实际 ${total}`);
  assert.equal(oracle.stats.wholeProbes, 1, '完整值复验仍发 1 次');
});

test('字符集收窄：小写字母场景 2 次类探测 + ~5 轮二分（8 → ~7），收敛值一致', async () => {
  const secret = 'mysql80';
  const oracle = makeCharsetOracle(secret);
  const out = await new Extractor().extractBoolean(buildCtx(oracle), 'version()');
  assert.equal(out, secret);
  // 5 个小写字母（2 次类探测 + ≤5 轮 [97,122]）+ 2 个数字（1+≤4）
  assert.equal(oracle.stats.betweenProbes, 5 * 2 + 2 * 1);
  const total = oracle.stats.betweenProbes + oracle.stats.gtProbes;
  assert.ok(total < secret.length * 8, `字母场景总请求数应低于 8/字符，实际 ${total}`);
});

test('字符集收窄：类外字符（大写/符号）回退全区间，收敛值不变（无回归）', async () => {
  const secret = 'AWS-2024';
  const oracle = makeCharsetOracle(secret);
  const out = await new Extractor().extractBoolean(buildCtx(oracle), 'version()');
  assert.equal(out, secret, '类外字符回退全区间后收敛值必须与原实现一致');
  // 'A','W','S','-' 各 +2 请求（两次类探测未命中），仍保证正确性
  assert.equal(oracle.stats.betweenProbes, 4 * 2 + 4 * 1);
});

test('字符集收窄：类探测被污染（恒报数字命中）→ 等值验证失败回退全区间，收敛正确', async () => {
  const secret = 'xyz'; // 'x'=120 不在数字区间，但预言机对 pos1 谎报数字命中
  const oracle = makeCharsetOracle(secret, { lieDigitsAt: [1] });
  const out = await new Extractor().extractBoolean(buildCtx(oracle), 'version()');
  assert.equal(out, secret, '污染的类探测应被等值验证发现并回退全区间重测');
});

test('字符集收窄：extractVerify 关闭时（可信预言机）收敛值不变', async () => {
  const secret = '8.0.36';
  const oracle = makeCharsetOracle(secret);
  const out = await new Extractor().extractBoolean(
    buildCtx(oracle, { blindRobust: { extractVerify: false } }),
    'version()'
  );
  assert.equal(out, secret);
  assert.equal(oracle.stats.eqProbes, 0, 'extractVerify 关闭时不应发等值验证请求');
});

test('字符集收窄：多字节字符（UTF-8）与收窄共存，还原正确', async () => {
  const secret = '版本8.0';
  const oracle = makeCharsetOracle(secret);
  const out = await new Extractor().extractBoolean(buildCtx(oracle), 'version()');
  assert.equal(out, secret);
});
