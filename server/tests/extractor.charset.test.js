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
// 并按类别计数（用于验证收窄的请求节省）。字符级判定按 UTF-8 字节（与引擎ASCII(SUBSTRING(...,1))
// 逐字节提取同构），完整值等值按解码后的字符串。
//
// ⚠️ [2026-10-05] 四条正则全部补**前后**词边界（`(?<![A-Za-z0-9_])` / `(?![A-Za-z0-9_])`）。
//   起因见文件末尾「活性守卫」：不带边界的 `/LEN/i` 会匹配 `OCTET_LENGTH` 的**尾部**，
//   把"失配"伪装成"命中"。过宽与过窄同样危险——前者让活性守卫失明。
//   另外 BETWEEN 那条此前**没加 i 标志却写了 \s+BETWEEN**，与其他三条不一致，已统一。
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
      const lenM = q.match(/(?<![A-Za-z0-9_])(?:LENGTH|LEN)(?![A-Za-z0-9_])\(\(.*?\)+\s*>\s*(\d+)/);
      if (lenM) {
        stats.lenProbes++;
        return ret(Number(lenM[1]) < bytes.length);
      }
      const btwM = q.match(/(?<![A-Za-z0-9_])SUBSTR(?:ING)?(?![A-Za-z0-9_])\(\(.*?,\s*(\d+),\s*1\)\)?\s*BETWEEN\s+(\d+)\s+AND\s+(\d+)/i);
      if (btwM) {
        stats.betweenProbes++;
        const pos = Number(btwM[1]);
        if (liars.has(pos)) return ret(true); // 污染：恒报数字类命中
        const code = bytes[pos - 1];
        return ret(code >= Number(btwM[2]) && code <= Number(btwM[3]));
      }
      const charM = q.match(/(?<![A-Za-z0-9_])SUBSTR(?:ING)?(?![A-Za-z0-9_])\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
      if (charM) {
        stats.gtProbes++;
        return ret(Number(charM[2]) < bytes[Number(charM[1]) - 1]);
      }
      const eqM = q.match(/(?<![A-Za-z0-9_])SUBSTR(?:ING)?(?![A-Za-z0-9_])\(\(.*?,\s*(\d+),\s*1\)+\s*=\s*(\d+)/);
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

// ============================================================================
// 活性守卫（2026-10-05）
//
// ── 要防的具体失效形态 ───────────────────────────────────────────────────────
// 本文件上面那些请求数断言，形式是：
//     assert.ok(oracle.stats.gtProbes <= secret.length * 4);
//     assert.ok(total <= 50);
//     assert.ok(total < secret.length * 8);
//
// 若预言机的**全部正则同时失配**（构造器改函数名 / 改括号层数 / 改方言分支），
// 则每个分支都不命中、计数恒为 **0**：
//     0 <= len*4   ✓ 通过
//     0 <= 50      ✓ 通过
//     0 < len*8    ✓ 通过
//
// ⇒ 三条断言**全部恒真**，而提取结果早已是空串。
// 这是「比无断言更危险」的形态：断言存在、看起来在管性能，实际什么都没验证。
//
// 唯一能识破它的办法是断言**下界**：探针数必须够提取出每个字符。
// 二分提取一个字符至少要 1 次类探测或 1 次字符比较，故下界 = 字符数（保守取一半，
// 因为类探测一次命中可覆盖一个字符，而回退全区间的路径更多）。
// ============================================================================

/** 断言预言机确实识别了探针——即它没有静默失配。 */
function assertOracleAlive(oracle, { min } = {}) {
  const total = oracle.stats.betweenProbes + oracle.stats.gtProbes + oracle.stats.eqProbes;
  assert.ok(
    total > (min ?? 0),
    `预言机未识别任何字符探针（len=${oracle.stats.lenProbes} between=${oracle.stats.betweenProbes} ` +
    `gt=${oracle.stats.gtProbes} eq=${oracle.stats.eqProbes}）—— ` +
    '所有正则均已失配，上面的请求数断言会恒真通过。需同步更新本文件的反解正则。'
  );
  return total;
}

test('活性-1) 数字场景：预言机必须识别到探针（下界 = 字符数）', async () => {
  const secret = '1834567290';
  const oracle = makeCharsetOracle(secret);
  const out = await new Extractor().extractBoolean(buildCtx(oracle), 'version()');
  assert.equal(out, secret);
  const total = assertOracleAlive(oracle, { min: secret.length });
  assert.ok(total >= secret.length,
    `每字符至少 1 次探测，实际 ${total} 次（secret 长度 ${secret.length}）`);
});

test('活性-2) 字母+数字场景：预言机必须识别到探针', async () => {
  const secret = 'mysql80';
  const oracle = makeCharsetOracle(secret);
  const out = await new Extractor().extractBoolean(buildCtx(oracle), 'version()');
  assert.equal(out, secret);
  const total = assertOracleAlive(oracle, { min: secret.length });
  assert.ok(total >= secret.length, `每字符至少 1 次探测，实际 ${total}`);
});

test('活性-3) 类外字符场景：预言机必须识别到探针', async () => {
  const secret = 'AWS-2024';
  const oracle = makeCharsetOracle(secret);
  const out = await new Extractor().extractBoolean(buildCtx(oracle), 'version()');
  assert.equal(out, secret);
  assertOracleAlive(oracle, { min: secret.length });
});

test('活性-4) UTF-8 多字节场景：预言机必须识别到探针', async () => {
  const secret = '版本8.0';
  const oracle = makeCharsetOracle(secret);
  const out = await new Extractor().extractBoolean(buildCtx(oracle), 'version()');
  assert.equal(out, secret);
  // 多字节：secret.length 是**字符**数，而预言机按 UTF-8 **字节**判定，
  // 字节数 ≥ 字符数，故下界取字符数（不取字节数，留出余量）。
  assertOracleAlive(oracle, { min: secret.length });
});

test('活性-5) 噪声不得被误判为探针（正则过宽同样是无声失效）', () => {
  // 反向自证：活性守卫不能"什么都算命中"。恒真的守卫等于没有守卫。
  const garbage = ['1 AND 1=1', '1', '', 'SELECT 1', '1 AND OCTET_LENGTH((version()))>3'];
  const lenRe = /(?<![A-Za-z0-9_])(?:LENGTH|LEN)(?![A-Za-z0-9_])\(\(.*?\)+\s*>\s*(\d+)/;
  const subRe = /(?<![A-Za-z0-9_])SUBSTR(?:ING)?(?![A-Za-z0-9_])\(\(.*?,\s*(\d+),\s*1\)/;
  const hits = garbage.filter((p) => lenRe.test(p) || subRe.test(p));
  assert.equal(hits.length, 0,
    `噪声被误判为探针：${JSON.stringify(hits)}（OCTET_LENGTH 那条正是词边界要挡的误命中）`);
});
