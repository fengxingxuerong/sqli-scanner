// 测试 server/src/core/logger.js 的敏感信息打码能力
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, redactHeaders, sanitizeLog } from '../src/core/logger.js';

test('redact: URL 内嵌凭据打码', () => {
  const out = redact('curl https://user:secret@host/path');
  assert.ok(!out.includes('user:secret'), '凭据应被打码');
  assert.ok(out.includes('***:***@'));
});

test('redact: Authorization Bearer 头值打码', () => {
  const out = redact('Authorization: Bearer abc123XYZ');
  assert.ok(!out.includes('abc123XYZ'), 'Bearer token 应被打码');
  assert.ok(out.includes('***'));
});

test('redact: Cookie 头值打码', () => {
  const out = redact('Cookie: session=abcdef; sid=987');
  assert.ok(!out.includes('abcdef'));
  assert.ok(out.includes('***'));
});

test('redact: 通用敏感键值打码（password/token/api_key）', () => {
  const out = redact('password=secret123 token=tok456 api_key=key789');
  assert.ok(!out.includes('secret123'));
  assert.ok(!out.includes('tok456'));
  assert.ok(!out.includes('key789'));
  assert.equal((out.match(/\*\*\*/g) || []).length, 3);
});

test('redact: 超长截断（maxLength）', () => {
  const long = 'A'.repeat(200);
  const out = redact(long, { maxLength: 10 });
  assert.ok(out.startsWith('AAAAAAAAAA'));
  assert.ok(out.includes('截断'));
  assert.ok(out.length < long.length);
});

test('redactHeaders: authorization/cookie/set-cookie/x-api-token 整体替换为 ***', () => {
  const out = redactHeaders({
    authorization: 'Bearer xyz',
    cookie: 'a=b',
    'set-cookie': 'c=d',
    'x-api-token': 'tok',
    'x-scan-token': 'st',
    accept: 'text/html',
  });
  assert.equal(out.authorization, '***');
  assert.equal(out.cookie, '***');
  assert.equal(out['set-cookie'], '***');
  assert.equal(out['x-api-token'], '***');
  assert.equal(out['x-scan-token'], '***');
  assert.equal(out.accept, 'text/html');
});

test('redactHeaders: 非对象安全返回', () => {
  assert.equal(redactHeaders(null), null);
});

test('sanitizeLog: 向后兼容（委托 redact）', () => {
  const msg = 'https://u:p@h password=secret';
  assert.equal(sanitizeLog(msg), redact(msg));
  assert.ok(!sanitizeLog(msg).includes('secret'));
});
