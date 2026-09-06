// OobDetector DNS 轮测试（对标 sqlmap --dns-domain 的 DNS 外带闭环）
// 覆盖：
//   1) dnsOob 开 + DNS 触发 mock → vulnerable=true，evidence 标注 DNS 通道，payload 含 <token>.<domain>
//   2) dnsOob 关 → 不生成任何 DNS payload（零行为变化）
//   3) dnsOob 开 + 静默目标 → vulnerable=false
//   4) 已知 dbms → 仅投放该库 DNS 模板
//   5) DNS_OOB_PAYLOADS 结构：非空模板 {TOKEN}/{DOMAIN} 占位符齐全；PG/SQLite/ClickHouse 留空
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OobDetector } from '../src/engine/detectors/OobDetector.js';
import { DNS_OOB_PAYLOADS } from '../src/engine/payloads.js';
import { oobReceiver } from '../src/core/oobReceiver.js';

const PORT = 19110;
const DOMAIN = 'oobdns.test';
const OOB_CFG = {
  enabled: true,
  callbackBase: `127.0.0.1:${PORT}`,
  httpPort: PORT,
  timeoutMs: 200, // HTTP 轮快速落空，尽快进入 DNS 轮
  dnsOob: true,
  dnsDomain: DOMAIN,
  dnsPort: 15353,
};

// 记录全部请求 + 模拟目标执行 DNS 触发语句：payload 中出现 <token>.oobdns.test 即回连
function makeDnsMock() {
  const seen = [];
  return {
    seen,
    async request(opts) {
      const text = JSON.stringify(opts);
      seen.push(text);
      const m = text.match(/([A-Za-z0-9_-]{16})\.oobdns\.test/);
      if (m) oobReceiver.receive(m[1]); // 目标 DBMS 发起 DNS 查询 → 接收端捕获
      return { data: '', status: 200 };
    },
  };
}

const makeSilentMock = () => ({ async request() { return { data: '', status: 200 }; } });

function makeCtx(httpClient, { dbms = 'MySQL', oob = OOB_CFG } = {}) {
  const config = { timeoutMs: 5000, oob };
  const target = { method: 'GET', baseUrl: 'http://mock/?q=1', headerParams: {}, cookieParams: {}, config };
  const point = { id: 'p1', location: 'url', param: 'q', originalValue: '1', confirmed: false, dbms: null };
  return { httpClient, target, point, dbms, config };
}

test('DNS 轮：dnsOob 开 + 目标触发 DNS 查询 → vulnerable=true 且证据标注 DNS 通道', async () => {
  await oobReceiver.start(OOB_CFG);
  const mock = makeDnsMock();
  const ctx = makeCtx(mock, { dbms: 'Oracle' }); // Oracle 用 UTL_INADDR 纯 DNS 原语
  const res = await new OobDetector().detect(ctx);
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'oob');
  assert.ok(res.evidence.includes('DNS 通道'), `evidence 应标注 DNS 通道：${res.evidence}`);
  assert.ok(res.evidence.includes(DOMAIN));
  assert.ok(res.payloads.some((p) => p.includes(`.${DOMAIN}`)), 'payload 应含 DNS 域名');
  assert.equal(ctx.point.confirmed, true);
  assert.equal(ctx.point.technique, 'oob');
  await oobReceiver.stop();
});

test('DNS 轮：已知 dbms=Oracle 仅投放 Oracle DNS 模板（UTL_INADDR）', async () => {
  await oobReceiver.start({ ...OOB_CFG, timeoutMs: 100 });
  const mock = makeDnsMock();
  // 关闭 mock 的自动回连（静默）以便检查全部已发 payload
  const seen = [];
  const silentRecord = { async request(opts) { seen.push(JSON.stringify(opts)); return { data: '', status: 200 }; } };
  await new OobDetector().detect(makeCtx(silentRecord, { dbms: 'Oracle' }));
  const dnsPayloads = seen.filter((t) => t.includes(DOMAIN));
  assert.ok(dnsPayloads.length > 0, '应发出 DNS 轮 payload');
  assert.ok(dnsPayloads.every((t) => t.toUpperCase().includes('UTL_INADDR')), 'Oracle DNS 轮应仅用 UTL_INADDR 模板');
  await oobReceiver.stop();
  void mock;
});

test('DNS 轮：dnsOob 关（默认）→ 不生成任何 DNS payload（零行为变化）', async () => {
  await oobReceiver.start({ ...OOB_CFG, dnsOob: false, timeoutMs: 150 });
  const seen = [];
  const silentRecord = { async request(opts) { seen.push(JSON.stringify(opts)); return { data: '', status: 200 }; } };
  const res = await new OobDetector().detect(makeCtx(silentRecord, { oob: { ...OOB_CFG, dnsOob: false } }));
  assert.equal(res.vulnerable, false);
  assert.equal(seen.filter((t) => t.includes(DOMAIN)).length, 0, 'dnsOob 关时不应出现 DNS 域名 payload');
  await oobReceiver.stop();
});

test('DNS 轮：dnsOob 开但目标静默 → vulnerable=false', async () => {
  await oobReceiver.start({ ...OOB_CFG, timeoutMs: 100 });
  const res = await new OobDetector().detect(makeCtx(makeSilentMock(), { dbms: 'Oracle' }));
  assert.equal(res.vulnerable, false);
  await oobReceiver.stop();
});

test('DNS_OOB_PAYLOADS 结构：非空模板占位符齐全，无域名泄漏到模板层', () => {
  for (const [db, tpls] of Object.entries(DNS_OOB_PAYLOADS)) {
    for (const tpl of tpls) {
      assert.ok(tpl.includes('{TOKEN}'), `${db} 模板缺 {TOKEN}：${tpl}`);
      assert.ok(tpl.includes('{DOMAIN}'), `${db} 模板缺 {DOMAIN}：${tpl}`);
      assert.ok(tpl.includes('{ORIG}'), `${db} 模板缺 {ORIG}：${tpl}`);
    }
  }
  // 无纯 DNS 原语的库留空（与 sqlmap 对 PG DNS 外带受限一致）
  assert.deepEqual(DNS_OOB_PAYLOADS.PostgreSQL, []);
  assert.deepEqual(DNS_OOB_PAYLOADS.SQLite, []);
  assert.deepEqual(DNS_OOB_PAYLOADS.ClickHouse, []);
  // 有能力的库至少 1 条
  for (const db of ['MySQL', 'MariaDB', 'TiDB', 'SQL Server', 'Oracle', 'DM8']) {
    assert.ok(DNS_OOB_PAYLOADS[db].length >= 1, `${db} 应至少 1 条 DNS 模板`);
  }
});
