// MariaDB 指纹区分 + 版本特征单元测试（数据层 + DBFingerprinter 集成）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  FINGERPRINT,
  DB_VERSION,
  PAYLOADS,
  DBMS_LIST,
  SUPPORTED,
  TECHNIQUE_TYPES,
  OOB_PAYLOADS,
} from '../src/engine/payloads.js';
import { DBFingerprinter } from '../src/engine/DBFingerprinter.js';
import { createTarget } from '../src/engine/models.js';

// ===== 数据层：MariaDB 与 MySQL 区别 =====
test('FINGERPRINT.MariaDB 存在且形状正确', () => {
  assert.ok(Array.isArray(FINGERPRINT.MariaDB) && FINGERPRINT.MariaDB.length > 0);
  assert.ok(FINGERPRINT.MariaDB[0].header && FINGERPRINT.MariaDB[0].match instanceof RegExp);
});

test('DB_VERSION.MariaDB.sig 匹配 MariaDB 版本串', () => {
  assert.ok(DB_VERSION.MariaDB.sig.test('10.6.0-MariaDB-1~focal'));
  assert.ok(DB_VERSION.MariaDB.sig.test('5.5.5-MariaDB'));
});

test('DB_VERSION.MySQL.sig 负向约束：不匹配 MariaDB（让 MariaDB 优先命中）', () => {
  assert.equal(DB_VERSION.MySQL.sig.test('10.6.0-MariaDB-1~focal'), false);
  assert.equal(DB_VERSION.MySQL.sig.test('5.5.5-MariaDB'), false);
});

test('DB_VERSION.MySQL.sig 仍匹配纯 MySQL 版本', () => {
  assert.ok(DB_VERSION.MySQL.sig.test('5.7.40'));
  assert.ok(DB_VERSION.MySQL.sig.test('8.0.32-log'));
});

test('PAYLOADS.MariaDB 镜像 MySQL 全部模板', () => {
  assert.deepEqual(PAYLOADS.MariaDB, PAYLOADS.MySQL);
  for (const tech of ['union', 'error', 'boolean', 'time', 'stacked']) {
    assert.ok(Array.isArray(PAYLOADS.MariaDB[tech]) && PAYLOADS.MariaDB[tech].length > 0);
  }
});

test('DBMS_LIST 含 MariaDB；SUPPORTED.MariaDB 各技术为真、SQLite oob 为假', () => {
  assert.ok(DBMS_LIST.includes('MariaDB'));
  assert.equal(SUPPORTED.MariaDB.union, true);
  assert.equal(SUPPORTED.MariaDB.error, true);
  assert.equal(SUPPORTED.MariaDB.boolean, true);
  assert.equal(SUPPORTED.MariaDB.time, true);
  assert.equal(SUPPORTED.MariaDB.oob, true);
  assert.equal(SUPPORTED.SQLite.oob, false);
});

test('TECHNIQUE_TYPES 含 oob 与 second_order 且共 7 项', () => {
  assert.ok(TECHNIQUE_TYPES.includes('oob'));
  assert.ok(TECHNIQUE_TYPES.includes('second_order'));
  assert.equal(TECHNIQUE_TYPES.length, 7);
});

test('OOB_PAYLOADS 各支持库非空、SQLite 为空', () => {
  for (const db of ['MySQL', 'MariaDB', 'PostgreSQL', 'SQL Server', 'Oracle']) {
    assert.ok(Array.isArray(OOB_PAYLOADS[db]) && OOB_PAYLOADS[db].length > 0, `${db} OOB 应为非空`);
  }
  assert.deepEqual(OOB_PAYLOADS.SQLite, []);
  // 触发语句应含 {CALLBACK} 占位（OobDetector 会替换）
  assert.ok(OOB_PAYLOADS.MySQL[0].includes('{CALLBACK}'));
});

// ===== 集成：DBFingerprinter 优先区分 MariaDB =====
function extractInjected(opts) {
  if (typeof opts.url === 'string') {
    const m = opts.url.match(/[?&]q=([^&]*)/);
    if (m) return decodeURIComponent(m[1]).replace(/\+/g, ' ');
  }
  return '';
}

// 模拟目标：ORDER BY 返回 500（列数=1）；UNION 回显版本串（含 SQLISCANNER 标记用于定位回显列）
function makeFpMock(versionStr) {
  return {
    async request(opts) {
      const q = extractInjected(opts);
      if (/ORDER BY/i.test(q)) return { status: 500, data: '' };
      if (/SQLISCANNER/.test(q)) return { data: 'x SQLISCANNER0 y', status: 200 };
      if (/UNION SELECT/i.test(q)) return { data: `__S__${versionStr}__E__`, status: 200 };
      return { data: 'normal', status: 200 };
    },
  };
}

function fpCtx(versionStr) {
  const target = createTarget({ url: 'http://mock/?q=1' });
  const point = { id: 'p1', location: 'url', param: 'q', originalValue: '1', dbms: null };
  return { httpClient: makeFpMock(versionStr), target, point, config: {} };
}

test('DBFingerprinter：MariaDB 版本串 → 优先判 MariaDB（非 MySQL）', async () => {
  const fp = new DBFingerprinter();
  const res = await fp.fingerprint(fpCtx('10.6.0-MariaDB-1~focal'));
  // F-20 起 fingerprint 返回 { dbms, baseline }（baseline 供 WAF 识别复用）
  assert.equal(res.dbms, 'MariaDB');
  assert.ok(res.baseline && typeof res.baseline.status === 'number' && typeof res.baseline.body === 'string' && res.baseline.headers);
});

test('DBFingerprinter：纯 MySQL 版本串 → 判 MySQL', async () => {
  const fp = new DBFingerprinter();
  const res = await fp.fingerprint(fpCtx('5.7.40'));
  assert.equal(res.dbms, 'MySQL');
  assert.ok(res.baseline && typeof res.baseline.status === 'number');
});
