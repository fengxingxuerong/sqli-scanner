// Phase 2 检测召回优化（T1-T4）单元测试
// 覆盖：报错签名分库 / 时间向量定库 / 锚点判定 / WAF 自动重跑节流 / URI 路径注入点解析
// 用 node:test + 轻量 mock（参考 detectors.test.js / fingerprint.mariadb.test.js 写法）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ERROR_SIG_BY_DBMS,
  dbmsFromError,
  TIME_VECTORS,
  fillPayload,
} from '../src/engine/payloads.js';
import { DBFingerprinter } from '../src/engine/DBFingerprinter.js';
import { Detector } from '../src/engine/Detector.js';
import { WafIdentifier, WAF_HIGH_CONFIDENCE } from '../src/core/waf/WafIdentifier.js';
import { TargetParser } from '../src/engine/TargetParser.js';
import { createTarget } from '../src/engine/models.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 从请求中取注入值（url query 注入点 q）
function extractInjected(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  return '';
}

// ===== T1a：报错签名分库（per-dbms 签名表） =====
test('T1：ERROR_SIG_BY_DBMS 含 6 大主流库独立签名子表', () => {
  const names = ERROR_SIG_BY_DBMS.map((e) => e.dbms);
  for (const db of ['MySQL', 'MariaDB', 'PostgreSQL', 'Oracle', 'SQL Server', 'SQLite']) {
    assert.ok(names.includes(db), `缺少 ${db} 报错签名`);
  }
  for (const e of ERROR_SIG_BY_DBMS) {
    assert.ok(e.sig instanceof RegExp, `${e.dbms} sig 应为正则`);
  }
});

test('T1：dbmsFromError 按报错文本精确定库（不再死回退 MySQL）', () => {
  assert.equal(dbmsFromError('ORA-00933: SQL command not properly ended'), 'Oracle');
  assert.equal(dbmsFromError('You have an error in your SQL syntax near ...'), 'MySQL');
  assert.equal(dbmsFromError('PostgreSQL: ERROR: syntax error at or near "1"'), 'PostgreSQL');
  assert.equal(dbmsFromError('Unclosed quotation mark after the character string ... Microsoft SQL Server'), 'SQL Server');
  assert.equal(dbmsFromError('SQLite3::SQLException: no such column: foo'), 'SQLite');
  assert.equal(dbmsFromError('SQLSTATE[42000]: [Microsoft][ODBC] SQL Server'), 'SQL Server');
  assert.equal(dbmsFromError('10.6.0-MariaDB: syntax error'), 'MariaDB');
  assert.equal(dbmsFromError('plain normal page'), null);
});

test('T1：TIME_VECTORS 各库独有延时原语 + 可填充', () => {
  const fns = TIME_VECTORS.map((v) => v.dbms);
  for (const db of ['MySQL', 'PostgreSQL', 'SQL Server', 'Oracle', 'SQLite']) {
    assert.ok(fns.includes(db), `缺少 ${db} 时间向量`);
  }
  const byDb = Object.fromEntries(TIME_VECTORS.map((v) => [v.dbms, v.payload]));
  assert.ok(byDb.MySQL.includes('SLEEP'));
  assert.ok(byDb.PostgreSQL.includes('pg_sleep'));
  assert.ok(byDb['SQL Server'].includes('WAITFOR DELAY'));
  assert.ok(byDb.Oracle.includes('DBMS_PIPE'));
  assert.ok(byDb.SQLite.includes('LIKE'));
  // 可填充 {ORIG}/{SLEEP}
  const filled = fillPayload(TIME_VECTORS[0].payload, { orig: '1', sleep: 2 });
  assert.equal(filled, '1 AND SLEEP(2)-- -');
});

// ===== T1b：DBFingerprinter 报错签名定库（无回显时不再返回 null） =====
function fpCtx(httpClient, config = {}) {
  const target = createTarget({ url: 'http://mock/?q=1' });
  const point = { id: 'p1', location: 'url', param: 'q', originalValue: '1', dbms: null };
  return { httpClient, target, point, config };
}

test('T1：DBFingerprinter 无回显时经报错签名定库（Oracle）', async () => {
  const calls = [];
  const mock = {
    calls,
    async request(opts) {
      const q = extractInjected(opts);
      calls.push(q);
      if (/ORDER BY/i.test(q)) return { status: 500, data: '' };
      if (/SQLISCANNER/.test(q)) return { data: 'no echo here', status: 200 };
      // 注入报错 payload 后目标回显 Oracle 报错
      if (/extractvalue|updatexml|CAST|CONVERT|CTXSYS|badfunc|db2_sqli|non_existent/i.test(q)) {
        return { data: 'ORA-00933: SQL command not properly ended', status: 200 };
      }
      return { data: 'normal', status: 200 };
    },
  };
  const fp = new DBFingerprinter();
  const res = await fp.fingerprint(fpCtx(mock));
  assert.equal(res.dbms, 'Oracle');
  assert.ok(res.baseline && typeof res.baseline.status === 'number');
});

test('T1：DBFingerprinter 时间向量定库（PostgreSQL pg_sleep 延迟命中即停）', async () => {
  const calls = [];
  const mock = {
    calls,
    async request(opts) {
      const q = extractInjected(opts);
      calls.push(q);
      if (/ORDER BY/i.test(q)) return { status: 500, data: '' };
      if (/SQLISCANNER/.test(q)) return { data: 'no echo', status: 200 };
      if (/pg_sleep/.test(q)) { await sleep(80); return { data: 'ok', status: 200 }; }
      return { data: 'normal', status: 200 };
    },
  };
  const fp = new DBFingerprinter();
  const res = await fp.fingerprint(fpCtx(mock, { fingerprintTimeThresholdMs: 40, fingerprintSleepSec: 1 }));
  assert.equal(res.dbms, 'PostgreSQL');
  // 命中即停：时间向量只应探测到 pg_sleep（MySQL SLEEP 在前，未延迟即跳过）
  const timeCalls = calls.filter((c) => /pg_sleep|SLEEP|WAITFOR|DBMS_PIPE|LIKE/.test(c));
  assert.deepEqual(timeCalls.filter((c) => /pg_sleep/.test(c)).length, 1);
  assert.ok(!calls.some((c) => /WAITFOR|DBMS_PIPE|LIKE/.test(c)), '命中后不应继续探测后续库');
});

test('T1：DBFingerprinter 无信号时返回 dbms=null（结构不变）', async () => {
  const mock = {
    async request(opts) {
      const q = extractInjected(opts);
      if (/ORDER BY/i.test(q)) return { status: 500, data: '' };
      if (/SQLISCANNER/.test(q)) return { data: 'no echo', status: 200 };
      return { data: 'normal', status: 200 };
    },
  };
  const fp = new DBFingerprinter();
  const res = await fp.fingerprint(fpCtx(mock));
  assert.equal(res.dbms, null);
  assert.ok(res.baseline && typeof res.baseline.body === 'string');
});

// ===== T2：锚点判定 + 分块比对（Detector 基类） =====
test('T2：matchAnchors 无锚点返回 null（回落分块比对）', () => {
  const d = new Detector('boolean');
  assert.equal(d.matchAnchors('any body', {}), null);
  assert.equal(d.matchAnchors('any body', { matchString: null, notString: null }), null);
});

test('T2：matchAnchors --string 真页面必含文本', () => {
  const d = new Detector('boolean');
  assert.equal(d.matchAnchors('page with SUCCESS marker', { matchString: 'SUCCESS' }), true);
  assert.equal(d.matchAnchors('page without marker', { matchString: 'SUCCESS' }), false);
});

test('T2：matchAnchors --not-string 假页面必含文本', () => {
  const d = new Detector('boolean');
  assert.equal(d.matchAnchors('normal page', { notString: 'ERROR_BLOCK' }), true);
  assert.equal(d.matchAnchors('page with ERROR_BLOCK', { notString: 'ERROR_BLOCK' }), false);
});

test('T2：chunkedSimilar 首部动态内容（时间戳/CSRF）仍判相似（分块兜底）', () => {
  const d = new Detector('boolean');
  const common = 'X'.repeat(64 * 8); // 8 个公共块
  const a = 'A'.repeat(64) + common; // 首块不同（动态）
  const b = 'B'.repeat(64) + common;
  assert.equal(d.chunkedSimilar(a, b), true, '首块不同但其余相同应判相似');
});

test('T2：chunkedSimilar 完全无关内容判不相似', () => {
  const d = new Detector('boolean');
  assert.equal(d.chunkedSimilar('a'.repeat(500), 'b'.repeat(500)), false);
});

test('T2：_boundarySimilar 有锚点时优先锚点判定（忽略状态码/长度）', () => {
  const d = new Detector('boolean');
  const r = d._boundarySimilar('base', 200, 'page has TARGET', 500, { matchString: 'TARGET' });
  assert.equal(r, true, '锚点命中应判相似，即使状态码不同');
  const r2 = d._boundarySimilar('base', 200, 'page lacks', 200, { matchString: 'TARGET' });
  assert.equal(r2, false);
});

// ===== T3：WAF 自动重跑门控 + 节流 =====
test('T3：WAF_HIGH_CONFIDENCE 阈值为 0.8', () => {
  assert.equal(WAF_HIGH_CONFIDENCE, 0.8);
});

test('T3：shouldAutoRetry 高置信 + autoRetry 开启 → true', () => {
  const id = new WafIdentifier();
  const cfg = { wafEvasion: { autoRetry: true, tamper: { enabled: false, plugins: [] } } };
  assert.equal(id.shouldAutoRetry([{ vendor: 'Cloudflare', confidence: 0.9 }], cfg), true);
});

test('T3：shouldAutoRetry 默认 autoRetry=false → false（保持现状）', () => {
  const id = new WafIdentifier();
  const cfg = { wafEvasion: { autoRetry: false, tamper: { enabled: false, plugins: [] } } };
  assert.equal(id.shouldAutoRetry([{ vendor: 'Cloudflare', confidence: 0.9 }], cfg), false);
  // 未配置 wafEvasion 也返回 false
  assert.equal(id.shouldAutoRetry([{ vendor: 'Cloudflare', confidence: 0.9 }], {}), false);
});

test('T3：shouldAutoRetry 低置信 WAF → false（节流：仅高置信）', () => {
  const id = new WafIdentifier();
  const cfg = { wafEvasion: { autoRetry: true, tamper: { enabled: false, plugins: [] } } };
  assert.equal(id.shouldAutoRetry([{ vendor: 'Cloudflare', confidence: 0.7 }], cfg), false);
});

test('T3：shouldAutoRetry 用户显式配置 tamper → false（不覆盖用户选择）', () => {
  const id = new WafIdentifier();
  const cfgEnabled = { wafEvasion: { autoRetry: true, tamper: { enabled: true, plugins: [] } } };
  assert.equal(id.shouldAutoRetry([{ vendor: 'Cloudflare', confidence: 0.9 }], cfgEnabled), false);
  const cfgPlugins = { wafEvasion: { autoRetry: true, tamper: { enabled: false, plugins: ['space2comment'] } } };
  assert.equal(id.shouldAutoRetry([{ vendor: 'Cloudflare', confidence: 0.9 }], cfgPlugins), false);
});

// ===== T4：URI 路径注入点解析 =====
test('T4：TargetParser 识别 URL 路径段 * 注入点', async () => {
  const parser = new TargetParser();
  const target = createTarget({ url: 'http://host/api/v1/users/1*/profile' });
  const points = await parser.discover(target);
  assert.equal(points.length, 1);
  assert.equal(points[0].location, 'path');
  assert.equal(points[0].originalValue, '1');
  assert.equal(points[0].pathSegment, 4);
  assert.equal(points[0].precisionMarked, true);
});

test('T4：无 * 时行为不变（仅查询参数注入点）', async () => {
  const parser = new TargetParser();
  const target = createTarget({ url: 'http://host/api/users/1?id=5&name=x' });
  const points = await parser.discover(target);
  assert.equal(points.length, 2);
  assert.ok(points.every((p) => p.location === 'url'));
  assert.deepEqual(points.map((p) => p.param).sort(), ['id', 'name']);
});

test('T4：多个路径 * 段全部保留为注入点', async () => {
  const parser = new TargetParser();
  const target = createTarget({ url: 'http://host/a*/b*/c' });
  const points = await parser.discover(target);
  assert.equal(points.length, 2);
  assert.deepEqual(points.map((p) => p.pathSegment).sort(), [1, 2]);
  assert.ok(points.every((p) => p.location === 'path'));
});
