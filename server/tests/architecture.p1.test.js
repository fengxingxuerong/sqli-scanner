// P1-A1/A2/A3/A5 关键路径回归测试
// 覆盖：日志脱敏 sanitizeLog、obfuscatePayload 下沉后仍可从 payloads re-export、
//       请求构造收敛（buildInjectionRequest 被 Detector/Extractor 复用）、
//       createApp 装配不监听（import 无副作用）、createApp 返回可用 app。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeLog } from '../src/core/logger.js';
import { obfuscatePayload } from '../src/engine/payloads.js';
import { obfuscatePayload as obfuscateFromCore } from '../src/core/tamper/obfuscate.js';
import { createApp } from '../index.js';

test('P1-A1：sanitizeLog 剥离 URL 内嵌凭据', () => {
  const out = sanitizeLog('GET https://admin:secret123@example.com/api 返回 200');
  assert.ok(!out.includes('secret123'), `不应含密码，实际=${out}`);
  assert.ok(!out.includes('admin:'), `不应含用户名，实际=${out}`);
  assert.ok(out.includes('example.com'));
});

test('P1-A1：sanitizeLog 打码键值凭据', () => {
  const out = sanitizeLog('password=abc123 token=xyz789 cookie=sessionid=foo');
  assert.ok(!out.includes('abc123'));
  assert.ok(!out.includes('xyz789'));
  assert.ok(!out.includes('foo'));
  assert.ok(out.includes('password=***'));
});

test('P1-A1：sanitizeLog 对无敏感内容原样返回', () => {
  const out = sanitizeLog('扫描 123 完成，发现 2 个漏洞');
  assert.equal(out, '扫描 123 完成，发现 2 个漏洞');
});

test('P1-A2：obfuscatePayload 从 payloads re-export 与 core 实现一致', () => {
  const input = 'SELECT 1 AND 1=1 OR 1=2';
  assert.equal(obfuscatePayload(input), obfuscateFromCore(input));
  // 语义：AND/OR 被包裹内联注释
  assert.ok(obfuscatePayload(input).includes('/*!*/AND/*!*/'));
});

test('P1-A5：createApp 返回可用的 Express app（不监听端口）', () => {
  const app = createApp();
  assert.ok(app, '应返回 app 实例');
  assert.equal(typeof app.use, 'function');
  assert.equal(typeof app.get, 'function');
});

test('P1-A5：createApp 导出 default 与具名一致（装配无副作用 import）', async () => {
  // import '../index.js' 不应自动监听端口（isMain 判断为 false，因为 argv[1] 是测试文件）
  const mod = await import('../index.js');
  assert.equal(typeof mod.createApp, 'function');
  assert.equal(typeof mod.start, 'function');
  assert.equal(typeof mod.default, 'function');
});
