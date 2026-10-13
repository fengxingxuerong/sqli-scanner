// ============================================================================
// tests/reportRedaction.test.js —— 统一脱敏管道测试（spec 5.3.1）
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactReport, parseRedactOpts } from '../src/services/reportRedaction.js';

test('opts 缺省时零行为变化（向后兼容，spec 5.3.1 规则 1）', () => {
  const report = { data: { passwords: ['root:abc123'] }, target: { config: { auth: { user: 'admin' } } } };
  const out = redactReport(report);
  assert.equal(out, report, '无 opts 时返回原对象引用（零拷贝、零行为变化）');
});

test('redactPasswords：哈希原文打码，保留 identity（spec 5.3.1 规则 2）', () => {
  const report = { data: { passwords: ['root@localhost:abc123hash', 'admin:5f4dcc3b5aa765d61d8327deb882cf99'] } };
  const out = redactReport(report, { redactPasswords: true });
  assert.equal(out.data.passwords[0], 'root@localhost:[REDACTED]');
  assert.equal(out.data.passwords[1], 'admin:[REDACTED]');
  // 原对象不被污染
  assert.equal(report.data.passwords[0], 'root@localhost:abc123hash', '原 report 不被污染');
});

test('redactAuth：PoC 凭据头打码', () => {
  const report = {
    vulns: [
      { id: 'v1', poc: { curl: 'curl -H "Authorization: Bearer sk-secret123" http://target/' } },
      { id: 'v2', poc: 'curl -H "Cookie: session=abc" http://target/' },
    ],
  };
  const out = redactReport(report, { redactAuth: true });
  assert.doesNotMatch(out.vulns[0].poc.curl, /sk-secret123/, 'Bearer token 被打码');
  assert.match(out.vulns[0].poc.curl, /\[REDACTED\]/, '含 [REDACTED] 标记');
  assert.doesNotMatch(out.vulns[1].poc, /session=abc/, 'Cookie 被打码');
});

test('redactTarget：target.config.auth/proxy 置 null', () => {
  const report = { target: { config: { auth: { user: 'admin', pass: 'secret' }, proxy: 'http://proxy:8080', baseUrl: 'http://target/' } } };
  const out = redactReport(report, { redactTarget: true });
  assert.equal(out.target.config.auth, null, 'auth 置 null');
  assert.equal(out.target.config.proxy, null, 'proxy 置 null');
  assert.equal(out.target.config.baseUrl, 'http://target/', '非敏感字段保留');
});

test('三层脱敏可组合', () => {
  const report = {
    data: { passwords: ['root:hash'] },
    vulns: [{ poc: { curl: 'curl -H "Authorization: Bearer secret" http://t/' } }],
    target: { config: { auth: { user: 'a' } } },
  };
  const out = redactReport(report, { redactPasswords: true, redactAuth: true, redactTarget: true });
  assert.equal(out.data.passwords[0], 'root:[REDACTED]');
  assert.doesNotMatch(out.vulns[0].poc.curl, /secret/);
  assert.equal(out.target.config.auth, null);
});

test('parseRedactOpts：非法值按默认 false 处理并告警（异常场景 1）', () => {
  const { opts, warn } = parseRedactOpts({ redactPasswords: 'yes', redactAuth: null, redactTarget: 42 });
  assert.equal(opts.redactPasswords, false, '非法值 "yes" 按默认 false');
  assert.equal(opts.redactAuth, false, 'null 按默认 false');
  assert.equal(opts.redactTarget, false, '42 按默认 false');
  assert.ok(warn.length >= 2, '至少 2 条告警（redactPasswords 和 redactTarget 非法）');
});

test('parseRedactOpts：合法值正确解析', () => {
  const { opts, warn } = parseRedactOpts({ redactPasswords: true, redactAuth: 'true', redactTarget: 1 });
  assert.equal(opts.redactPasswords, true);
  assert.equal(opts.redactAuth, true);
  assert.equal(opts.redactTarget, true);
  assert.equal(warn.length, 0, '无告警');
});

test('passwordAnalysis 不受脱敏影响（风险标注仍可读，spec 5.3.1 规则 4）', () => {
  const report = {
    data: { passwords: ['root:abc123'] },
    passwordAnalysis: { total: 1, weak: 1, entries: [{ identity: 'root', algo: 'mysql_old', strength: 'weak' }] },
  };
  const out = redactReport(report, { redactPasswords: true });
  assert.deepEqual(out.passwordAnalysis, report.passwordAnalysis, 'passwordAnalysis 原样保留（可读且不可反推原文）');
});