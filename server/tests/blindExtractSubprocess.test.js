// ============================================================================
// blindExtractSubprocess.test.js —— D54 §2.4 定点单测：extractBoolean 拆分后的子过程等价性
//
// 拆分（D54 §2.1）：extractBoolean → _resolveExtractPlan / _extractLength /
// _extractBytesBitwise / _extractBytesBisect / _finalizeExtract。
// 本测试钉住：① 正常提取流程端到端正确 ② 缓存命中跳过全流程 ③ 结构性不支持方言返回 null
// ④ 位平面 opt-in（默认关）⑤ 空值不缓存。变异任一子过程的判定/请求序列/缓存逻辑即红。
// ============================================================================
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

// 字节级预言机：模拟 MySQL 盲注响应（真条件返回有内容页，假条件返回空页）
function makeByteOracle(secret) {
  const bytes = Buffer.from(secret, 'utf-8');
  return {
    async request(opts) {
      const q = extractQuery(opts);
      if (q.includes('1=2')) return { data: '', status: 200 };
      const lenM = q.match(/(?:LENGTH|LEN)\(\(.*?\)+\s*>\s*(\d+)/);
      if (lenM) return { data: Number(lenM[1]) < bytes.length ? 'OK' : '', status: 200 };
      const betweenLenM = q.match(/(?:LENGTH|LEN)\(\(.*?\)+\s*BETWEEN\s+(\d+)\s+AND\s+(\d+)/);
      if (betweenLenM) {
        const lo = Number(betweenLenM[1]), hi = Number(betweenLenM[2]);
        return { data: bytes.length >= lo && bytes.length <= hi ? 'OK' : '', status: 200 };
      }
      const charBetweenM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*BETWEEN\s+(\d+)\s+AND\s+(\d+)/);
      if (charBetweenM) {
        const i = Number(charBetweenM[1]), lo = Number(charBetweenM[2]), hi = Number(charBetweenM[3]);
        const code = bytes[i - 1] ?? 0;
        return { data: code >= lo && code <= hi ? 'OK' : '', status: 200 };
      }
      const charM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
      if (charM) {
        const i = Number(charM[1]), c = Number(charM[2]);
        const code = bytes[i - 1] ?? 0;
        return { data: c < code ? 'OK' : '', status: 200 };
      }
      const eqM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*=\s*(\d+)/);
      if (eqM) {
        const i = Number(eqM[1]), c = Number(eqM[2]);
        const code = bytes[i - 1] ?? 0;
        return { data: code === c ? 'OK' : '', status: 200 };
      }
      return { data: '', status: 200 };
    },
  };
}

function buildCtx(httpClient, overrides = {}) {
  return {
    httpClient,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, retry: 0, maxColumnsGuess: 10, ...overrides },
  };
}

test('子过程-1) 正常提取：extractBoolean 端到端正确提取秘密值', async () => {
  const ex = new Extractor();
  const ctx = buildCtx(makeByteOracle('s3cr3t'));
  const result = await ex.extractBoolean(ctx, 'version()');
  assert.equal(result, 's3cr3t', '应正确提取秘密值');
});

test('子过程-2) 缓存命中：第二次调用跳过全流程（_resolveExtractPlan 返回 cached）', async () => {
  const ex = new Extractor();
  let reqCount = 0;
  const oracle = makeByteOracle('cached!');
  const countingOracle = {
    async request(opts) { reqCount++; return oracle.request(opts); },
  };
  const ctx = buildCtx(countingOracle, { predictOutput: true });
  ctx.scanId = 'scan-cache-test';
  const r1 = await ex.extractBoolean(ctx, 'version()');
  assert.equal(r1, 'cached!', '首次提取应正确');
  const firstReqs = reqCount;
  const r2 = await ex.extractBoolean(ctx, 'version()');
  assert.equal(r2, 'cached!', '第二次应返回缓存值');
  assert.equal(reqCount, firstReqs, '第二次调用应零请求（缓存命中）');
});

test('子过程-3) 结构性不支持：方言函数缺失时 _resolveExtractPlan 返回 null', async () => {
  const ex = new Extractor();
  const ctx = buildCtx(makeByteOracle('test'), {});
  ctx.dbms = 'Derby'; // Derby 的 ASCII_FN 显式 null（无字符→码点函数）
  const result = await ex.extractBoolean(ctx, 'version()');
  assert.equal(result, null, 'Derby 码点提取结构性不支持应诚实返回 null（不投无效 SQL）');
});

test('子过程-4) 位平面 opt-in：默认关闭时走原二分路径', async () => {
  const ex = new Extractor();
  const ctx = buildCtx(makeByteOracle('hello'));
  assert.ok(!ctx.config.blindBitwise, 'blindBitwise 默认应未设置（关闭）');
  const result = await ex.extractBoolean(ctx, 'version()');
  assert.equal(result, 'hello', '默认路径（二分）应正确提取');
});

test('子过程-5) 空值不缓存：提取失败不固化（null/空串不进缓存）', async () => {
  const ex = new Extractor();
  const emptyOracle = {
    async request(opts) { return { data: '', status: 200 }; },
  };
  const ctx = buildCtx(emptyOracle, { predictOutput: true });
  ctx.scanId = 'scan-empty-test';
  const result = await ex.extractBoolean(ctx, 'version()');
  assert.equal(result, null, '全空响应应返回 null');
  const cache = ex._extractCache.get(ctx.target);
  assert.ok(!cache || !cache.has(`${ctx.scanId}:MySQL:version()`),
    'null 结果不应被缓存（避免固化「提取失败」）');
});