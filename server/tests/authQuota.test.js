// ============================================================================
// tests/authQuota.test.js —— 授权声明 + 配额 + 审计 测试（spec 5.2.1）
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateDeclaration, extractDeclaration } from '../src/core/authDeclaration.js';
import { checkQuota, release, getQuotaState, credentialKeyOf, _resetForTest } from '../src/api/quotaMiddleware.js';
import { recordAuthEvent, readAuthEvents, _clearForTest } from '../src/services/authAudit.js';
import { tokenKeyOf } from '../src/api/rateLimit.js';

// ── authDeclaration ──────────────────────────────────────────────────────
test('授权声明缺失 → AUTH_DECLARATION_MISSING', () => {
  const r = validateDeclaration(null);
  assert.equal(r.valid, false);
  assert.equal(r.code, 'AUTH_DECLARATION_MISSING');
});

test('仅布尔 authorized=true 无声明 → 拒绝（spec 5.2.1 规则 7）', () => {
  // 模拟仅传 authorized=true 而无声明结构
  const r = validateDeclaration(undefined);
  assert.equal(r.valid, false);
  assert.equal(r.code, 'AUTH_DECLARATION_MISSING');
  assert.match(r.message, /不构成充分条件/);
});

test('授权声明字段非法 → AUTH_DECLARATION_INVALID', () => {
  assert.equal(validateDeclaration({ operator: '', timestamp: Date.now() }).code, 'AUTH_DECLARATION_INVALID');
  assert.equal(validateDeclaration({ operator: 'op', timestamp: 'bad' }).code, 'AUTH_DECLARATION_INVALID');
  assert.equal(validateDeclaration({ operator: 'op', timestamp: Date.now(), scope: 'not-object' }).code, 'AUTH_DECLARATION_INVALID');
});

test('授权声明过期 → AUTH_DECLARATION_EXPIRED', () => {
  const r = validateDeclaration({ operator: 'op', timestamp: Date.now() - 2 * 60 * 60 * 1000, validWindowMs: 3600000 });
  assert.equal(r.code, 'AUTH_DECLARATION_EXPIRED');
});

test('有效授权声明 → valid', () => {
  const r = validateDeclaration({ operator: 'pentester', timestamp: Date.now(), validWindowMs: 3600000 });
  assert.equal(r.valid, true);
  assert.equal(r.declaration.operator, 'pentester');
});

test('scope 不覆盖目标 → AUTH_SCOPE_MISMATCH', () => {
  const r = validateDeclaration(
    { operator: 'op', timestamp: Date.now(), scope: { hosts: ['authorized.target.com'] } },
    'http://unauthorized.target.com/',
  );
  assert.equal(r.code, 'AUTH_SCOPE_MISMATCH');
});

test('scope 覆盖目标 → valid', () => {
  const r = validateDeclaration(
    { operator: 'op', timestamp: Date.now(), scope: { hosts: ['authorized.target.com'] } },
    'http://authorized.target.com/',
  );
  assert.equal(r.valid, true);
});

test('scope domains 后缀匹配', () => {
  const r = validateDeclaration(
    { operator: 'op', timestamp: Date.now(), scope: { domains: ['example.com'] } },
    'http://sub.example.com/',
  );
  assert.equal(r.valid, true);
});

test('extractDeclaration 从请求体提取', () => {
  assert.ok(extractDeclaration({ authDeclaration: { operator: 'op', timestamp: 1 } }));
  assert.ok(extractDeclaration({ declaration: { operator: 'op', timestamp: 1 } }));
  assert.equal(extractDeclaration({ authorized: true }), null);
});

// ── quotaMiddleware ──────────────────────────────────────────────────────
test('配额：目标数超限 → QUOTA_TARGET_EXCEEDED', () => {
  _resetForTest();
  const key = 'test-key-1';
  // QUOTA_TARGET_MAX 默认 20，用 21 个不同目标触发
  // 每次 checkQuota 后 release 释放扇出（目标数 Map 不被 release 清空，仍累加）
  for (let i = 0; i < 20; i++) {
    const r = checkQuota({ credentialKey: key, target: `http://t${i}.com/` });
    assert.equal(r.allowed, true, `目标 ${i} 应通过`);
    release({ credentialKey: key });
  }
  const r = checkQuota({ credentialKey: key, target: 'http://t20.com/' });
  assert.equal(r.allowed, false);
  assert.equal(r.code, 'QUOTA_TARGET_EXCEEDED');
});

test('配额：扇出超限 → QUOTA_FANOUT_EXCEEDED', () => {
  _resetForTest();
  const key = 'test-key-2';
  // QUOTA_FANOUT_MAX 默认 5，同一目标不触发目标数限制
  for (let i = 0; i < 5; i++) {
    const r = checkQuota({ credentialKey: key, target: 'http://same.com/' });
    assert.equal(r.allowed, true, `扇出 ${i} 应通过`);
  }
  const r = checkQuota({ credentialKey: key, target: 'http://same.com/' });
  assert.equal(r.allowed, false);
  assert.equal(r.code, 'QUOTA_FANOUT_EXCEEDED');
});

test('配额：release 释放扇出', () => {
  _resetForTest();
  const key = 'test-key-3';
  checkQuota({ credentialKey: key, target: 'http://t.com/' });
  checkQuota({ credentialKey: key, target: 'http://t.com/' });
  checkQuota({ credentialKey: key, target: 'http://t.com/' });
  checkQuota({ credentialKey: key, target: 'http://t.com/' });
  checkQuota({ credentialKey: key, target: 'http://t.com/' });
  assert.equal(checkQuota({ credentialKey: key, target: 'http://t.com/' }).allowed, false, '扇出满');
  release({ credentialKey: key });
  assert.equal(checkQuota({ credentialKey: key, target: 'http://t.com/' }).allowed, true, 'release 后可继续');
});

test('配额：不同凭据独立计额（spec 5.2.1 规则 5/6）', () => {
  _resetForTest();
  const r1 = checkQuota({ credentialKey: 'key-a', target: 'http://a.com/' });
  const r2 = checkQuota({ credentialKey: 'key-b', target: 'http://b.com/' });
  assert.equal(r1.allowed, true);
  assert.equal(r2.allowed, true);
  assert.equal(getQuotaState('key-a').fanout, 1);
  assert.equal(getQuotaState('key-b').fanout, 1);
});

test('credentialKeyOf：不同 token 不同键', () => {
  assert.notEqual(credentialKeyOf('token-aaa'), credentialKeyOf('token-bbb'));
  assert.equal(credentialKeyOf('token-aaa'), credentialKeyOf('token-aaa'), '同 token 同键');
  assert.equal(credentialKeyOf(''), 'anonymous');
});

// ── rateLimit tokenKeyOf SHA-256 ─────────────────────────────────────────
test('tokenKeyOf：SHA-256 摘要无前缀碰撞（spec 5.2.1 规则 5）', () => {
  // 两个不同 token 前 8 位相同
  const reqA = { headers: { 'x-api-token': 'sharedPrefix123456' }, ip: '127.0.0.1' };
  const reqB = { headers: { 'x-api-token': 'sharedPrefix789012' }, ip: '127.0.0.1' };
  const keyA = tokenKeyOf(reqA);
  const keyB = tokenKeyOf(reqB);
  assert.notEqual(keyA, keyB, '前 12 位相同的不同 token 必须有不同计额键');
  assert.ok(keyA.startsWith('h:'), '键以 h: 前缀标识哈希');
});

test('tokenKeyOf：无 token 回落 req.ip', () => {
  const req = { headers: {}, ip: '192.168.1.1' };
  assert.equal(tokenKeyOf(req), '192.168.1.1');
});

// ── authAudit ────────────────────────────────────────────────────────────
test('authAudit：记录并读取审计事件（spec 5.2.1 规则 2）', () => {
  _clearForTest();
  const r = recordAuthEvent({
    declaration: { operator: 'pentester', scope: { hosts: ['target.com'] }, timestamp: Date.now() },
    operation: 'exploit:sql',
    target: 'http://target.com/page?id=1',
    result: 'allowed',
  });
  assert.equal(r.ok, true);
  const events = readAuthEvents();
  assert.ok(events.length >= 1, '至少 1 条记录');
  const last = events[events.length - 1];
  assert.equal(last.operator, 'pentester');
  assert.equal(last.operation, 'exploit:sql');
  assert.equal(last.result, 'allowed');
  assert.ok(last.eventId, '有 eventId');
  assert.ok(last.recordedAt, '有 recordedAt');
});

test('authAudit：拒绝事件也记录', () => {
  _clearForTest();
  recordAuthEvent({
    operation: 'exploit:os-shell',
    target: 'http://target.com/',
    result: 'denied',
    reason: 'AUTH_DECLARATION_MISSING',
  });
  const events = readAuthEvents();
  const last = events[events.length - 1];
  assert.equal(last.result, 'denied');
  assert.equal(last.reason, 'AUTH_DECLARATION_MISSING');
});