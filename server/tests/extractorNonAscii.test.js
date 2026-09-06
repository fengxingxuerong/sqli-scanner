// 验证本轮优化点：
// 1) extractBoolean 字节级提取（0–255）后可经 TextDecoder('utf-8') 还原中文等多字节字符（原 code>=32&&<=126 会截断）
// 2) dumpData 用控制字符 0x1F/0x1E 分隔，业务数据含 '|' 不再错位
// 3) binaryGuessColumns 二分列数探测正确且请求数 ~log2(maxCols)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';
import { binaryGuessColumns } from '../src/engine/columnGuess.js';

function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  if (opts.data && typeof opts.data.q !== 'undefined') return String(opts.data.q);
  return '';
}

// 字节级布尔预言机：按 UTF-8 字节逐位比较，支持中文
function makeByteOracle(secret) {
  const bytes = Buffer.from(secret, 'utf-8'); // 明文按 utf-8 编码为字节数组
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

test('extractBoolean 字节级提取中文（多字节字符不被截断）', async () => {
  const secret = '版本8.0.33-数据库';
  const ctx = buildCtx(makeByteOracle(secret), 'MySQL');
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, secret);
});

test('extractBoolean 提取纯 ASCII 仍正确（向后兼容）', async () => {
  const secret = '5.7.40-log';
  const ctx = buildCtx(makeByteOracle(secret), 'MySQL');
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, secret);
});

test('extractBoolean 提取含 emoji 的字符串', async () => {
  const secret = 'ok🚀';
  const ctx = buildCtx(makeByteOracle(secret), 'MySQL');
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, secret);
});

// 控制字符分隔：业务数据含 '|' 不冲突
function makeCtrlPager(rows) {
  return {
    async request(opts) {
      const q = extractQuery(opts);
      if (/__S__/.test(q)) {
        const offM = q.match(/OFFSET (\d+)/);
        const offset = offM ? Number(offM[1]) : 0;
        const limM = q.match(/LIMIT (\d+)/);
        const lim = limM ? Number(limM[1]) : 100;
        const page = rows.slice(offset, offset + lim).map(
          (r) => r.join(String.fromCharCode(0x1f))
        );
        return { data: `__S__${page.join(String.fromCharCode(0x1e))}__E__`, status: 200 };
      }
      return { data: 'baseline', status: 200 };
    },
  };
}

test('dumpData 控制字符分隔：字段值含 | 不错位', async () => {
  const rows = [
    ['1', '合肥市|包河区'],
    ['2', '备注|a|b|c'],
  ];
  const ctx = buildCtx(makeCtrlPager(rows), 'MySQL');
  ctx.point.echoCols = [0];
  const out = await ex.dumpData(ctx, 'db', 't', ['id', 'addr'], 100);
  assert.equal(out.length, 2);
  assert.deepEqual(out[0], { id: '1', addr: '合肥市|包河区' });
  assert.deepEqual(out[1], { id: '2', addr: '备注|a|b|c' });
});

test('binaryGuessColumns 二分返回正确列数', async () => {
  // ORDER BY 超过 3 列时返回短响应
  let calls = 0;
  const probe = async (n) => {
    calls++;
    return { status: n > 3 ? 500 : 200, data: n > 3 ? 'ERR' : 'okresult' };
  };
  const cols = await binaryGuessColumns(probe, { baseLen: 8, maxCols: 50 });
  assert.equal(cols, 3);
  assert.ok(calls <= 6, `二分请求数应≈log2(50)，实际=${calls}`);
});
