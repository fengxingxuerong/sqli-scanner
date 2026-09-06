// P2-P2 盲注提取二次确认（extractVerify）测试（node --test）
// 验证：1) 二次确认开启（默认 true）时每字节收敛后发等值验证请求，结果正确；
//       2) 验证判定与主判定一致（响应≠false 基准即真）：不识别等值探测的 mock oracle
//          验证失败 → 回退重测最多 2 次 → 结果仍正确（幂等，兼容既有 mock oracle 测试）；
//       3) extractVerify:false 时零验证请求，行为与旧版一致。
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

// 布尔预言机：长度/字符二分谓词 + 可选等值谓词（= 探测识别开关）
function makeOracle(secret, { supportEquality = true } = {}) {
  const stats = { equalityProbes: 0 };
  return {
    stats,
    async request(opts) {
      const q = extractQuery(opts);
      if (q.includes('1=2')) return { data: '', status: 200 };
      const lenM = q.match(/(?:LENGTH|LEN)\(\(.*?\)+\s*>\s*(\d+)/);
      if (lenM) {
        return { data: Number(lenM[1]) < secret.length ? 'OK' : '', status: 200 };
      }
      const charM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
      if (charM) {
        const i = Number(charM[1]);
        const c = Number(charM[2]);
        return { data: c < secret.charCodeAt(i - 1) ? 'OK' : '', status: 200 };
      }
      const eqM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*=\s*(\d+)/);
      if (eqM) {
        stats.equalityProbes++;
        if (!supportEquality) return { data: '', status: 200 }; // 不识别等值 → 恒 false（模拟旧 mock）
        const i = Number(eqM[1]);
        const c = Number(eqM[2]);
        return { data: c === secret.charCodeAt(i - 1) ? 'OK' : '', status: 200 };
      }
      return { data: '', status: 200 };
    },
  };
}

function buildCtx(httpClient, overrides = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: true },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, retry: 0, extractConcurrency: 2 },
    ...overrides,
  };
}

test('extractBoolean 二次确认：等值验证请求已发且结果正确（默认开启）', async () => {
  const secret = '5.7.40';
  const oracle = makeOracle(secret, { supportEquality: true });
  const ctx = buildCtx(oracle, { config: { timeoutMs: 5000, retry: 0, extractConcurrency: 2, blindRobust: { extractVerify: true } } });
  const ex = new Extractor();
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, secret);
  assert.ok(oracle.stats.equalityProbes >= secret.length, `每字节应有验证请求，实际 ${oracle.stats.equalityProbes}`);
});

test('extractBoolean 二次确认：不识别等值探测的 mock 也幂等（回退重测后结果正确）', async () => {
  const secret = '8.0.33';
  // 旧 mock oracle 语义：等值探测返回 false（与主判定同一比较），验证失败 → 回退重测 → 收敛回同一值
  const oracle = makeOracle(secret, { supportEquality: false });
  const ctx = buildCtx(oracle, { config: { timeoutMs: 5000, retry: 0, extractConcurrency: 2, blindRobust: { extractVerify: true } } });
  const ex = new Extractor();
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, secret, '验证失败回退重测后结果仍应正确（幂等）');
  assert.ok(oracle.stats.equalityProbes >= secret.length, '应确实尝试了等值验证');
});

test('extractBoolean：extractVerify:false 零验证请求（与旧行为一致）', async () => {
  const secret = '8.0.33';
  const oracle = makeOracle(secret, { supportEquality: true });
  const ctx = buildCtx(oracle, { config: { timeoutMs: 5000, retry: 0, extractConcurrency: 2, blindRobust: { extractVerify: false } } });
  const ex = new Extractor();
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, secret);
  assert.equal(oracle.stats.equalityProbes, 0, '关闭二次确认后不应发等值验证请求');
});
