// ============================================================================
// booleanBlind.orTruth.d282.test.js —— [D282] 「OR 恒真」第三档判据
//
// 外部裁判真机证据（OWASP Juice Shop `/rest/products/search?q=test`，SQLite）：
//   查询 `WHERE (name LIKE '%q%' OR description LIKE '%q%')`，基线命中只来自第二支
//   （O-Saft 的 description 含 "tests"）⇒ 任何正确闭合都会注释掉那一支
//   ⇒ AND 对永远无差分（30B vs 30B），而 OR 对是 34245B（全表）vs 30B。
//   旧判据硬要求 `similarToBaseline(tBody)`（真侧≈基线 744B）⇒ 该点 4/4 确定性漏检。
//
// 本文件钉三件事：
//   ① 该形态必须被检出（修复的正面判据）；
//   ② 分页类「真大假小但不近空」不得放行（假阳第一道）；
//   ③ 参数被忽略（所有请求同页，含基线）不得放行（假阳第二道）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';

const ORIG = 'test';
const EMPTY = '{"status":"success","data":[]}'; // 30B
const BASE = `{"status":"success","data":[{"id":9,"name":"O-Salt","description":"${'o'.repeat(600)}"}]}`;
const FULL = `{"status":"success","data":[${Array.from({ length: 40 }, (_, i) => `{"id":${i},"name":"row-${i}","description":"${'d'.repeat(60)}"}`).join(',')}]}`;

function qOf(url) {
  const m = String(url || '').match(/[?&]q=([^&]*)/);
  return m ? decodeURIComponent(m[1].replace(/\+/g, ' ')) : '';
}

/**
 * Juice 形态：AND 对双空；OR 1=1 全表；OR 1=2 空；基线 1 条。
 * @returns {object} 假 httpClient
 */
function juiceLikeClient() {
  return {
    calls: [],
    async request(opts) {
      this.calls.push(opts);
      const q = qOf(opts.url);
      if (q === ORIG) return { status: 200, headers: {}, data: BASE };
      if (/OR\s+1=1/i.test(q)) return { status: 200, headers: {}, data: FULL };
      if (/OR\s+1=2/i.test(q)) return { status: 200, headers: {}, data: EMPTY };
      if (/AND\s+1=1|AND\s+1=2/i.test(q)) return { status: 200, headers: {}, data: EMPTY };
      return { status: 200, headers: {}, data: BASE };
    },
  };
}

/** 分页形态：OR 真侧大、假侧也大（不近空）——不得放行 */
function pagedClient() {
  return {
    calls: [],
    async request(opts) {
      const q = qOf(opts.url);
      if (q === ORIG) return { status: 200, headers: {}, data: BASE };
      if (/OR\s+1=1/i.test(q)) return { status: 200, headers: {}, data: FULL };
      if (/OR\s+1=2/i.test(q)) return { status: 200, headers: {}, data: `{"data":[${'y'.repeat(900)}]}` };
      return { status: 200, headers: {}, data: BASE };
    },
  };
}

/** 小响应形态：真侧 800B（< 1000B 下界）——不得放行（fail-closed，回退旧行为） */
function smallTableClient() {
  const SMALL_BASE = `{"data":[{"id":1,"name":"${'s'.repeat(200)}"}]}`;
  const SMALL_FULL = `{"data":[${Array.from({ length: 10 }, (_, i) => `{"id":${i},"n":"${'z'.repeat(50)}"}`).join(',')}]}`;
  return {
    calls: [],
    async request(opts) {
      const q = qOf(opts.url);
      if (q === ORIG) return { status: 200, headers: {}, data: SMALL_BASE };
      if (/OR\s+1=1/i.test(q)) return { status: 200, headers: {}, data: SMALL_FULL };
      if (/OR\s+1=2/i.test(q)) return { status: 200, headers: {}, data: EMPTY };
      return { status: 200, headers: {}, data: SMALL_BASE };
    },
  };
}

function buildCtx(client) {
  return {
    httpClient: client,
    target: { method: 'GET', baseUrl: `http://mock/?q=${ORIG}`, headerParams: {}, cookieParams: {} },
    point: {
      id: 'p1',
      location: 'url',
      param: 'q',
      originalValue: ORIG,
      confirmed: false,
      boundary: "'))",
    },
    dbms: 'MySQL',
    config: { timeoutMs: 5000, retry: 0, level: 2, risk: 1 },
  };
}

const det = new BooleanBlindDetector();

test('★[D282] OR 恒真形态：真侧不≈基线（全表 3000B+ vs 假侧空）也必须判布尔注入', async () => {
  const r = await det.detect(buildCtx(juiceLikeClient()));
  assert.equal(r.vulnerable, true, '基线命中来自 OR 另一支时，旧判据（真侧≈基线）会整点漏判');
  assert.match(String(r.evidence || ''), /OR 恒真/, `证据应标明第三档判据，实际：${r.evidence}`);
});

test('[D282] 反例：分页目标（假侧 900B 不近空）不得被 OR 恒真判据放行', async () => {
  const r = await det.detect(buildCtx(pagedClient()));
  assert.equal(r.vulnerable, false, '假侧不近空 ⇒ 仍可能只是结果集大小的正常变化，必须 fail-closed');
});

test('[D282] 反例：真/假差值不足 1000B（小表）不得被 OR 恒真判据放行', async () => {
  const r = await det.detect(buildCtx(smallTableClient()));
  assert.equal(r.vulnerable, false, '低于差值下界时必须 fail-closed，回退旧行为（不劣化）');
});

// ── 鲁棒分支（CLI / REST 默认 rb=true 走这条）──
// 实测：CLI 的 detect 入口打印 `rb= true`，只改 legacy 分支等于没修。
const ROBUST = { blindRobust: { enabled: true, baselineSamples: 3, booleanSamples: 3, concurrency: 2 } };

test('★[D282] 鲁棒分支：OR 恒真形态同样必须检出（真≈基线比例恒 0）', async () => {
  const r = await det.detect(buildCtx(juiceLikeClient(), ROBUST));
  assert.equal(r.vulnerable, true, 'rb=true 时统计判据的 trueRatio 恒 0，必须由第三档接管');
  assert.match(String(r.evidence || ''), /OR 恒真/, `证据应标明第三档判据，实际：${r.evidence}`);
});

test('[D282] 鲁棒分支反例：分页目标不得放行', async () => {
  const r = await det.detect(buildCtx(pagedClient(), ROBUST));
  assert.equal(r.vulnerable, false, '假侧不近空 ⇒ 仍可能只是结果集正常变化');
});
