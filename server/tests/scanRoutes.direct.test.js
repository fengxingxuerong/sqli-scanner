// 直连模式（对标 sqlmap -d）sanitizeStart 放行测试
// 原实现 sanitizeStart 只认 http/https 目标，mode/db/connectionString 全被丢弃 →
// DirectConnector/getDriver 在 API 层不可达（死代码）。修复后：
//   mode='direct'（或携带 db/connectionString）→ 放行并校验 db + sqlTemplate，
//   返回带 mode/db/sqlTemplate 的对象（不再要求 url / 不再走 http scheme 校验）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeStart } from '../src/api/scanRoutes.js';
import { ErrorCode } from '../src/core/errors.js';

test('direct: 提供 connectionString + sqlTemplate 时放行', () => {
  const out = sanitizeStart({
    mode: 'direct',
    connectionString: 'sqlite://:memory:',
    sqlTemplate: 'SELECT * FROM users WHERE id={INJECT}',
    config: { level: 2, risk: 2 },
  });
  assert.equal(out.mode, 'direct');
  assert.equal(out.db.connectionString, 'sqlite://:memory:');
  assert.equal(out.db.driverType, 'memory');
  assert.equal(out.sqlTemplate, 'SELECT * FROM users WHERE id={INJECT}');
  assert.equal(out.config.level, 2);
});

test('direct: 提供 db 对象（含 driverType）时优先透传', () => {
  const out = sanitizeStart({
    mode: 'direct',
    db: { connectionString: 'mysql://u:p@h/db', driverType: 'sqljs' },
    sqlTemplate: 'SELECT * FROM t WHERE id={INJECT}',
  });
  assert.equal(out.mode, 'direct');
  assert.equal(out.db.driverType, 'sqljs');
  assert.equal(out.db.connectionString, 'mysql://u:p@h/db');
});

test('direct: 缺 sqlTemplate 抛 INVALID_TARGET', () => {
  assert.throws(
    () => sanitizeStart({ mode: 'direct', connectionString: 'sqlite://:memory:' }),
    (e) => e.code === ErrorCode.INVALID_TARGET && /sqlTemplate/i.test(e.message)
  );
});

test('direct: sqlTemplate 缺 {INJECT} 标记抛 INVALID_TARGET', () => {
  assert.throws(
    () => sanitizeStart({ mode: 'direct', connectionString: 'sqlite://:memory:', sqlTemplate: 'SELECT 1' }),
    (e) => e.code === ErrorCode.INVALID_TARGET && /INJECT/i.test(e.message)
  );
});

test('direct: 未提供连接信息（无 db/connectionString）抛 INVALID_TARGET', () => {
  assert.throws(
    () => sanitizeStart({ mode: 'direct', sqlTemplate: 'SELECT 1 WHERE id={INJECT}' }),
    (e) => e.code === ErrorCode.INVALID_TARGET
  );
});

test('http 模式不受影响：正常 url 仍走 http 校验（回归）', () => {
  const out = sanitizeStart({ url: 'http://x.test/?id=1', config: { ratePerSec: 30 } });
  assert.equal(out.url, 'http://x.test/?id=1');
  assert.equal(out.mode, undefined); // 未指定 mode → http 语义（createTarget 默认 http）
});