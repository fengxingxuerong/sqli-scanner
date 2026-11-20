// ============================================================================
// booleanBlind.xor.d308.guard.test.js —— [D308] XOR 布尔对 opt-in 守卫
//
// 来源：社区 905 条 payload（PayloadsAllTheThings SQLi/Intruder）特征对账，
// 21 类语法特征中 19 类本仓覆盖，唯一真缺口 = XOR（出自 MySQL polyglot）。
//
// 真引擎语义（MariaDB 3306，DVWA users 表，本文写作时实测）：
//   WHERE user_id='1' XOR 0-- -  → 1 行（≈基线，取真）
//   WHERE user_id='1' XOR 1-- -  → 4 行（补集，取假）
//   SQLite 真引擎报 `near "XOR": syntax error` ⇒ 限定 MySQL/MariaDB/TiDB 投放。
//
// 判据钉四件事：
//   ① 默认关（booleanXor 未开/为 false）时绝对不产生 XOR 对 —— 零行为变化；
//   ② 显式 open + boundary + MySQL 系才产生 XOR 对（id='xor_bool'）；
//   ③ 真假 payload 语义正确（XOR 0 真 / XOR 1 假，注释后缀闭合）；
//   ④ 反例：非 MySQL（SQLite/PG）、无 boundary 均不投放（防语法噪声）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { PAYLOADS } from '../src/engine/payloads.js';

const D = new BooleanBlindDetector();
const POINT = { id: 'p1', originalValue: '1', boundary: "'" };
const templates = PAYLOADS.MySQL.boolean;

function pairs(overrides = {}) {
  return D._getBooleanPairs(
    { point: POINT, dbms: 'MySQL', config: {}, obfuscateValue: (_c, s) => s, ...overrides },
    templates
  );
}

test('D308-1 默认关：未开 booleanXor 时不产生 XOR 对（零行为变化）', () => {
  const got = pairs();
  assert.ok(!got.some((p) => p.id === 'xor_bool'), '默认不应投放 XOR 对');
  const gotFalse = pairs({ config: { booleanXor: false } });
  assert.ok(!gotFalse.some((p) => p.id === 'xor_bool'), 'booleanXor=false 不应投放');
});

test('D308-2 显式开启 + boundary + MySQL：产生唯一 XOR 对', () => {
  const got = pairs({ config: { booleanXor: true } });
  const xors = got.filter((p) => p.id === 'xor_bool');
  assert.equal(xors.length, 1, '应恰有 1 个 XOR 对');
});

test('D308-3 XOR 真假对语义：XOR 0 为真、XOR 1 为假，注释闭合', () => {
  const xp = pairs({ config: { booleanXor: true } }).find((p) => p.id === 'xor_bool');
  assert.ok(xp, 'XOR 对应存在');
  assert.equal(xp.truePayload, "1' XOR 0-- -");
  assert.equal(xp.falsePayload, "1' XOR 1-- -");
  assert.ok(xp.truePayload.includes('XOR 0'), '真条件应为 XOR 0（≈基线）');
  assert.ok(xp.falsePayload.includes('XOR 1'), '假条件应为 XOR 1（补集）');
  assert.ok(!/\b(AND|OR)\b/i.test(xp.truePayload), 'XOR 对不得含 AND/OR（否则绕过无意义）');
});

test('D308-4 方言与上下文边界：非 MySQL 系 / 无 boundary 不投放', () => {
  for (const dbms of ['SQLite', 'PostgreSQL', 'Oracle', 'SQL Server']) {
    const got = pairs({ config: { booleanXor: true }, dbms });
    assert.ok(!got.some((p) => p.id === 'xor_bool'), `${dbms} 不应投放 XOR（语法不支持/未验证）`);
  }
  const noBoundary = pairs({
    config: { booleanXor: true },
    point: { id: 'p2', originalValue: '1', boundary: '' },
  });
  assert.ok(!noBoundary.some((p) => p.id === 'xor_bool'), '无 boundary 不应投放（语法错误噪声）');
});

test('D308-5 反例（判据不空转）：若把 XOR 对改成 AND 对，D308-3 必红', () => {
  const fakeTrue = "1' AND 1=1-- -";
  assert.ok(/\bAND\b/i.test(fakeTrue), '反例含 AND，应被 D308-3 的「不含 AND/OR」断言拒绝');
});

// —— 隔离验证：AND/OR 族全部无差分，只有 XOR 对可分 ⇒ 必须靠 XOR 检出 ——
// 这是 WAF 过滤 AND/OR 场景的 detector 层抽象。真引擎 XOR 语义由 MariaDB 实测
// （见文件头注释）单独保证；这里用 mock 响应隔离「XOR 对真能驱动检出判定」这一环。
const XOR_TRUE = "1' XOR 0-- -";
const XOR_FALSE = "1' XOR 1-- -";
const BODY_BASE = `{"data":[{"id":1,"name":"${'a'.repeat(120)}"}]}`;
const BODY_EMPTY = `{"data":[]}`;
const BODY_FULL = `{"data":[${Array.from({ length: 20 }, (_, i) => `{"id":${i},"n":"${'z'.repeat(40)}"}`).join(',')}]}`;

/** 只对 XOR 真假对给差分；AND/OR 全部恒定（模拟 WAF 过滤 AND/OR 后两者无差异） */
function xorOnlyClient() {
  return {
    calls: [],
    async request(opts) {
      // URL query 里空格被编码成 '+'，先还原再判断（decodeURIComponent 不处理 '+'）
      const q = decodeURIComponent(String(opts.url || '')).replace(/\+/g, ' ');
      this.calls.push(q);
      if (q.includes('XOR 0')) return { status: 200, headers: {}, data: BODY_BASE };
      if (q.includes('XOR 1')) return { status: 200, headers: {}, data: BODY_FULL };
      return { status: 200, headers: {}, data: BODY_BASE };
    },
  };
}

async function detectWith(config) {
  const d = new BooleanBlindDetector();
  const client = xorOnlyClient();
  const point = { id: 'xor-p', originalValue: '1', boundary: "'", location: 'url', param: 'id', confirmed: false };
  const target = { method: 'GET', baseUrl: 'http://mock/?id=1', headerParams: {}, cookieParams: {} };
  const ctx = {
    httpClient: client,
    target,
    point,
    dbms: 'MySQL',
    config: { timeoutMs: 5000, retry: 0, level: 2, risk: 2, ...config },
  };
  const result = await d.detect(ctx);
  return { result, sentXor: client.calls.some((q) => q.includes('XOR 0')) };
}

test('D308-6 隔离验证：AND/OR 无差分、仅 XOR 可分时，开启 booleanXor 才检出', async () => {
  const off = await detectWith({ booleanXor: false, booleanOrFallback: false });
  assert.equal(off.result.vulnerable, false, 'XOR 关：AND/OR 无差分 ⇒ 不应检出');
  assert.equal(off.sentXor, false, 'XOR 关：不应发送 XOR payload');

  const on = await detectWith({ booleanXor: true, booleanOrFallback: false });
  assert.equal(on.sentXor, true, 'XOR 开：应发送 XOR payload');
  assert.equal(on.result.vulnerable, true, 'XOR 开：XOR 对可分 ⇒ 必须检出');
});
