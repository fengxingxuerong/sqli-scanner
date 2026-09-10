// [P0-SEC 2026-09-08] 日志脱敏补口测试（node:test）
// 背景：redact 的敏感键正则只覆盖 `key=value` / `key: value` 形态，JSON 序列化后的
// `"token": "<value>"` 因为 key 与冒号之间隔着闭合引号而完全不匹配 → 启动失败日志
// （打印 e.stack，栈里带调用方 config）与 AI 报告请求体回显会把引擎 token / 目标凭据
// 原文写进 logs/engine.log（0644，任何本机用户可读）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, redactHeaders, sanitizeLog } from '../src/core/logger.js';

test('JSON 形态的敏感键值被打码（回归本缺陷）', () => {
  const out = redact('启动扫描失败：{"config":{"token":"3f2a9c8b7e6d5c4b","auth":{"password":"p@ss"}}}');
  assert.ok(!out.includes('3f2a9c8b7e6d5c4b'), `token 值应被打码，实际：${out}`);
  assert.ok(!out.includes('p@ss'), `password 值应被打码，实际：${out}`);
  assert.ok(out.includes('"config"'), '非敏感键结构应保留（日志可读性）');
});

test('JSON 形态覆盖常见键名：api_key / authorization / cookie / secret', () => {
  const out = redact(
    '{"api_key":"sk-live-123","Authorization":"Bearer aaa","cookie":"sid=9","client_secret":"cs-1","access_token":"at-1"}'
  );
  for (const secret of ['sk-live-123', 'aaa', 'sid=9', 'cs-1', 'at-1']) {
    assert.ok(!out.includes(secret), `应打码 ${secret}，实际：${out}`);
  }
});

test('非敏感 JSON 不被误伤（值保留）', () => {
  const out = redact('{"url":"http://t.example.com/?id=1","risk":2}');
  assert.ok(out.includes('http://t.example.com/?id=1'), 'url 值应保留');
  assert.ok(out.includes('"risk":2'));
});

test('既有 k=v 形态与头对象打码行为不变（回归护栏）', () => {
  assert.ok(!redact('target=http://u:p@h/?token=abc').includes('abc'));
  const h = redactHeaders({ Authorization: 'Bearer x', 'X-Api-Token': 'y', Accept: 'text/html' });
  assert.equal(h.Authorization, '***');
  assert.equal(h['X-Api-Token'], '***');
  assert.equal(h.Accept, 'text/html');
  assert.equal(typeof sanitizeLog('plain'), 'string');
});
