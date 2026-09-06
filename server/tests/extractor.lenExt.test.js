// [P2-FIX 长度上界] 长度二分撞 255 上界时的延伸提取测试：
// 300 字节长值 → 探测 >255 为真 → 在 [256, blindMaxLen] 续段二分拿到真实长度 300 →
// 完整还原 300 字节值（原实现静默截断为 255 字节）。短值回归由 extractorNonAscii.test.js 覆盖。
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

// 字节级布尔预言机（同 extractorNonAscii 模式），支持任意长度（含 >255 字节）
function makeByteOracle(secret) {
  const bytes = Buffer.from(secret, 'utf-8');
  return {
    async request(opts) {
      const q = extractQuery(opts);
      if (q.includes('1=2')) return { data: '', status: 200 };
      // 长度（字节数）：LENGTH((X))>N
      const lenM = q.match(/(?:LENGTH|LEN)\(\(.*?\)+\s*>\s*(\d+)/);
      if (lenM) return { data: Number(lenM[1]) < bytes.length ? 'OK' : '', status: 200 };
      // 字节：ASCII(SUBSTRING((X),i,1))>C
      const charM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
      if (charM) {
        const i = Number(charM[1]);
        const c = Number(charM[2]);
        const code = bytes[i - 1];
        return { data: c < code ? 'OK' : '', status: 200 };
      }
      return { data: '', status: 200 };
    },
  };
}

function buildCtx(httpClient, dbms = 'MySQL') {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms,
    config: { timeoutMs: 5000, retry: 0, maxColumnsGuess: 10 },
  };
}

const ex = new Extractor();

test('extractBoolean 长值（300 字节 > 255 上界）经延伸二分完整还原', async () => {
  const secret = 'A'.repeat(300);
  const ctx = buildCtx(makeByteOracle(secret), 'MySQL');
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, secret);
  assert.equal(out.length, 300);
});

test('extractBoolean 盲注长度上界可配（blindMaxLen 生效）', async () => {
  const secret = 'B'.repeat(300);
  const ctx = buildCtx(makeByteOracle(secret), 'MySQL');
  ctx.config.blindMaxLen = 280; // 上限收窄到 280 → 提取应截断为 280 字节
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out.length, 280);
});
