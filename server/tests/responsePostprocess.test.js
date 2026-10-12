// ============================================================================
// tests/responsePostprocess.test.js —— D52 响应解密扩展点（--postprocess）
//
// 三层判据（与 requestTransform 同构）：
//   ① 单元：路径白名单/导出形态/只换 data/fail-closed/未登记零拷贝；
//   ② 提取链端到端（killer）：加密响应体的 oracle 上，不配脚本 ⇒ extractBoolean
//      诚实返回 null（密文差异被判据失效吞掉），配脚本 ⇒ 正确提取 secret；
//   ③ 接线：经 ScanManager.getScanClient 出来的响应真的是解密后的（防「函数对、
//      调用链断」，本仓反复出现的那一族）。
// ============================================================================

import { test, after, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';

import { Extractor } from '../src/engine/Extractor.js';
import { ScanManager } from '../src/engine/ScanManager.js';
import {
  assertResponseScriptPath,
  loadResponseScript,
  ensureResponseTransform,
  applyResponseTransform,
  registerResponseTransform,
  releaseResponseTransform,
  responseTransformCount,
  responseTransformActiveForScan,
  RESPONSE_TRANSFORMABLE_KEYS,
} from '../src/core/responseTransform.js';
import { ErrorCode } from '../src/core/errors.js';

const DIR = mkdtempSync(path.join(tmpdir(), 'sqli-pp-'));
process.env.RESPONSE_SCRIPT_DIR = DIR;
let seq = 0;
function script(body, ext = 'mjs') {
  const f = path.join(DIR, `p${++seq}.${ext}`);
  writeFileSync(f, body, 'utf8');
  return f;
}

after(() => {
  releaseResponseTransform('pp-any');
  delete process.env.RESPONSE_SCRIPT_DIR;
  try { rmSync(DIR, { recursive: true, force: true }); } catch { /* 清理失败不影响结论 */ }
});

// ── ① 路径白名单与导出形态 ─────────────────────────────────────────────

describe('路径白名单（RESPONSE_SCRIPT_DIR）', () => {
  test('未设置白名单根 ⇒ 拒绝加载并点名环境变量', () => {
    const saved = process.env.RESPONSE_SCRIPT_DIR;
    delete process.env.RESPONSE_SCRIPT_DIR;
    try {
      assert.throws(
        () => assertResponseScriptPath('/anywhere/dec.mjs'),
        (e) => e.code === ErrorCode.RESPONSE_SCRIPT_INVALID && /RESPONSE_SCRIPT_DIR/.test(e.message),
      );
    } finally {
      process.env.RESPONSE_SCRIPT_DIR = saved;
    }
  });

  test('目录外脚本 ⇒ 拒绝（白名单根外一律不加载）', () => {
    const outside = path.join(tmpdir(), `sqli-pp-outside-${seq}.mjs`);
    writeFileSync(outside, 'export function transform(r){ return r }\n', 'utf8');
    try {
      assert.throws(
        () => assertResponseScriptPath(outside),
        (e) => e.code === ErrorCode.RESPONSE_SCRIPT_INVALID && /不在 RESPONSE_SCRIPT_DIR/.test(e.message),
      );
    } finally {
      rmSync(outside, { force: true });
    }
  });

  test('非 js 后缀 / 不存在 / 无 transform 导出 ⇒ 拒绝', async () => {
    assert.throws(() => assertResponseScriptPath(path.join(DIR, 'x.py')),
      (e) => e.code === ErrorCode.RESPONSE_SCRIPT_INVALID);
    assert.throws(() => assertResponseScriptPath(path.join(DIR, 'nope.mjs')),
      (e) => e.code === ErrorCode.RESPONSE_SCRIPT_INVALID);
    const noExport = script('export const x = 1;\n');
    await assert.rejects(
      () => loadResponseScript(noExport),
      (e) => e.code === ErrorCode.RESPONSE_SCRIPT_INVALID && /必须导出 transform 函数/.test(e.message),
    );
  });

  test('合法脚本加载成功并给出 sha256', async () => {
    const f = script('export function transform(r){ return { ...r, data: "x" } }\n');
    const entry = await loadResponseScript(f);
    assert.equal(typeof entry.fn, 'function');
    assert.match(entry.sha256, /^[0-9a-f]{64}$/);
    // entry.source 是 **realpath 后**的路径：assertResponseScriptPath 的白名单判据含 realpath
    // （防 symlink 绕过目录白名单），语义正确。macOS 的 /tmp → /private/tmp 是 symlink，
    // 直接拿原始 tmpdir 路径比较会多出 /private 前缀 ⇒ test-matrix(macos) 红（#220 实测）。
    // 两边都 realpath 后比较：无 symlink 的平台（Linux/Windows）恒等，零行为变化。
    assert.equal(entry.source, realpathSync(f));
  });
});

// ── ② applyResponseTransform 行为契约 ──────────────────────────────────

// 模拟 AES-CBC 随机 IV 的加密器：相同明文也产出不同密文（8 位 nonce + base64(明文)）。
// 密钥点：不解密时真/假响应「看起来都像随机串」⇒ 比对判据失效 ⇒ 提取必须诚实失败。
const enc = (s) => Math.random().toString(16).slice(2, 10).padEnd(8, '0') + Buffer.from(s, 'utf8').toString('base64');
const DECRYPTOR = script(
  'export function transform(res){ return { ...res, data: Buffer.from(String(res.data).slice(8), "base64").toString("utf8") } }\n',
);

test('未登记时原样返回（同一引用，零拷贝）', async () => {
  const res = { status: 200, data: 'anything', headers: {} };
  const out = await applyResponseTransform('pp-none', res);
  assert.equal(out, res);
});

test('只替换 data；status/headers 改动被忽略（可信度判账的输入不可改）', async () => {
  registerResponseTransform('pp-data', { fn: async (r) => ({ ...r, data: 'PLAIN', status: 500, headers: { x: 'evil' } }), source: 'mem', sha256: '0'.repeat(64) });
  try {
    const res = { status: 200, data: 'Y2lwaGVy', headers: { ct: 'text/html' } };
    const out = await applyResponseTransform('pp-data', res);
    assert.equal(out.data, 'PLAIN');
    assert.equal(out.status, 200, '脚本不得把 200 洗成 500（反之亦然）');
    assert.deepEqual(out.headers, { ct: 'text/html' });
    assert.equal(res.data, 'Y2lwaGVy', '调用方响应对象不得被原地改写');
  } finally {
    releaseResponseTransform('pp-data');
  }
});

test('fail-closed：脚本抛错 ⇒ RESPONSE_SCRIPT_FAILED（该响应按失败处理）', async () => {
  registerResponseTransform('pp-throw', { fn: async () => { throw new Error('key lost'); }, source: 'mem', sha256: '0'.repeat(64) });
  try {
    await assert.rejects(
      () => applyResponseTransform('pp-throw', { status: 200, data: 'x' }),
      (e) => e.code === ErrorCode.RESPONSE_SCRIPT_FAILED && /key lost/.test(e.message),
    );
  } finally {
    releaseResponseTransform('pp-throw');
  }
});

test('fail-closed：data 非字符串 ⇒ RESPONSE_SCRIPT_FAILED', async () => {
  registerResponseTransform('pp-badtype', { fn: async () => ({ data: 42 }), source: 'mem', sha256: '0'.repeat(64) });
  try {
    await assert.rejects(
      () => applyResponseTransform('pp-badtype', { status: 200, data: 'x' }),
      (e) => e.code === ErrorCode.RESPONSE_SCRIPT_FAILED,
    );
  } finally {
    releaseResponseTransform('pp-badtype');
  }
});

test('RESPONSE_TRANSFORMABLE_KEYS 只有 data', () => {
  assert.deepEqual([...RESPONSE_TRANSFORMABLE_KEYS], ['data']);
});

test('登记生命周期：ensure/count/active/release', async () => {
  const n0 = responseTransformCount();
  const info = await ensureResponseTransform('pp-life', { postprocess: DECRYPTOR });
  assert.ok(info && /p\d+\.mjs$/.test(info.file), 'file 只嵌 basename，不嵌操作者绝对路径');
  assert.equal(responseTransformActiveForScan('pp-life'), true);
  assert.equal(responseTransformCount(), n0 + 1);
  releaseResponseTransform('pp-life');
  assert.equal(responseTransformActiveForScan('pp-life'), false);
  assert.equal(responseTransformCount(), n0);
});

// ── ③ 提取链端到端（killer） ───────────────────────────────────────────

function extractQuery(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  return '';
}

// 加密 oracle：响应体恒为 base64(明文)。'OK'/'' 加密后可区分（与真实加密器
// 「相同明文→不同密文」不同，这里刻意可逆，才能验证解密后的比对语义）。
function makeEncryptedOracle(secret) {
  return {
    async request(opts) {
      const q = extractQuery(opts);
      if (q.includes('1=2')) return { data: enc(''), status: 200 };
      const lenM = q.match(/LENGTH\(\(.*?\)+\s*>\s*(\d+)/);
      if (lenM) return { data: enc(Number(lenM[1]) < secret.length ? 'OK' : ''), status: 200 };
      const charM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*>\s*(\d+)/);
      if (charM) {
        return { data: enc(Number(charM[2]) < secret.charCodeAt(Number(charM[1]) - 1) ? 'OK' : ''), status: 200 };
      }
      const eqM = q.match(/SUBSTR(?:ING)?\(\(.*?,\s*(\d+),\s*1\)+\s*=\s*(\d+)/);
      if (eqM) return { data: enc(Number(eqM[2]) === secret.charCodeAt(Number(eqM[1]) - 1) ? 'OK' : ''), status: 200 };
      return { data: enc(''), status: 200 };
    },
  };
}

// 把 oracle 包进 applyResponseTransform —— 与 scanClient 视图对响应做的事逐字一致
// （视图接线由下方两条 wiring 用例单独钉住，这里组合的是「解密层 + 提取链」）。
function buildCtx(oracle, scanId) {
  const wrapped = scanId
    ? { request: async (opts) => applyResponseTransform(scanId, await oracle.request(opts)) }
    : oracle;
  return {
    httpClient: wrapped,
    target: { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {} },
    point: { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, retry: 0, maxColumnsGuess: 10 },
  };
}

const ex = new Extractor();

test('加密响应体：不配解密脚本 ⇒ 诚实返回 null（不拿密文差异造值）', async () => {
  const secret = '5.7.40';
  const ctx = buildCtx(makeEncryptedOracle(secret));
  const out = await ex.extractBoolean(ctx, 'version()');
  assert.equal(out, null, '密文上跑二分只会得到判据失效的产物，必须判失败而不是吐错值');
});

test('加密响应体：配解密脚本 ⇒ 正确提取（--postprocess 的存在理由）', async () => {
  const secret = '5.7.40';
  await ensureResponseTransform('pp-extract', { postprocess: DECRYPTOR });
  try {
    const ctx = buildCtx(makeEncryptedOracle(secret), 'pp-extract');
    assert.equal(await ex.extractBoolean(ctx, 'version()'), secret);
  } finally {
    releaseResponseTransform('pp-extract');
  }
});

test('解密脚本执行失败时按失败处理：宁漏不误，不用密文继续比对', async () => {
  const boom = script('export function transform(res){ throw new Error("bad key") }\n');
  const secret = '5.7.40';
  await ensureResponseTransform('pp-boom', { postprocess: boom });
  try {
    const ctx = buildCtx(makeEncryptedOracle(secret), 'pp-boom');
    // 每条响应都解密失败 ⇒ _send 记 null ⇒ 长度探测全不可判定 ⇒ null（不是错值）
    assert.equal(await ex.extractBoolean(ctx, 'version()'), null);
  } finally {
    releaseResponseTransform('pp-boom');
  }
});

// ── ④ 接线层：getScanClient 出来的响应真的是解密后的 ───────────────────

function stubClient(responder) {
  const sent = [];
  return {
    sent,
    forScan() {
      return {
        request: async (opts) => {
          sent.push({ kind: 'request', opts });
          return responder(opts, sent.length);
        },
        headRequest: async (url, opts) => {
          sent.push({ kind: 'head', url, opts });
          return responder(url, sent.length);
        },
      };
    },
    removeBucket() {}, releaseGroupBucket() {}, removeRequestCount() {}, clearJar() {},
  };
}

test('接线：经 getScanClient 的响应体是解密后的（防「函数对、调用链断」）', async () => {
  const raw = { status: 200, data: enc('PLAIN-BODY'), headers: {} };
  const original = raw.data; // nonce 每次随机：原地改写判据必须锚定原始值
  const sm = new ScanManager();
  sm.httpClient = stubClient(() => raw);
  await ensureResponseTransform('pp-wire', { postprocess: DECRYPTOR });
  try {
    const view = sm.getScanClient('pp-wire', { url: 'http://t.test/p?id=1', mode: 'http', config: {} });
    const res = await view.request({ url: 'http://t.test/p?id=1', method: 'GET', headers: {} });
    assert.equal(res.data, 'PLAIN-BODY');
    assert.equal(res.status, 200, '响应对象的其余字段原样保留');
    assert.equal(raw.data, original, '内层客户端的原始响应不得被原地改写');
  } finally {
    releaseResponseTransform('pp-wire');
  }
});

test('接线：HEAD（--null-connection）也走同一层解密', async () => {
  const sm = new ScanManager();
  sm.httpClient = stubClient(() => ({ status: 200, data: enc('HEAD-PLAIN'), headers: {} }));
  await ensureResponseTransform('pp-wire-head', { postprocess: DECRYPTOR });
  try {
    const view = sm.getScanClient('pp-wire-head', { url: 'http://t.test/p?id=1', mode: 'http', config: {} });
    const res = await view.headRequest('http://t.test/p?id=1', {});
    assert.equal(res.data, 'HEAD-PLAIN');
  } finally {
    releaseResponseTransform('pp-wire-head');
  }
});
