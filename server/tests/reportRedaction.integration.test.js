// ============================================================================
// tests/reportRedaction.integration.test.js —— redactPasswords 开关接入测试（模块 3.3）
//
// 验证：
//   ① 默认（redactPasswords=false）→ data.passwords 原文保留（向后兼容，spec 5.3.1 规则 1）
//   ② redactPasswords=true → data.passwords 哈希原文打码（规则 2）
//   ③ ?redactPasswords=1 运行时覆盖 → 导出脱敏
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanManager } from '../src/engine/ScanManager.js';

function makeReport() {
  return {
    scanId: 'test-scan',
    summary: { verdict: 'no_vulnerability_detected' },
    data: {
      passwords: ['admin:5f4dcc3b5aa765d61d8327deb882cf99', 'root:21232f297a57a5a743894a0e4a801fc3'],
    },
    vulns: [],
    target: { url: 'http://example.com/page?id=1', config: { auth: { user: 'bob', pass: 'secret' }, proxy: 'http://proxy:8080' } },
    points: [],
  };
}

function makeScanEntry(redactPasswords) {
  return {
    target: { url: 'http://example.com/', config: {} },
    report: makeReport(),
    status: 'completed',
    cancelled: false,
    createdAt: Date.now(),
    abortController: new AbortController(),
    redactPasswords,
  };
}

test('默认（redactPasswords=false）→ passwords 原文保留（向后兼容）', () => {
  const sm = new ScanManager();
  sm.scans.set('s1', makeScanEntry(false));
  const json = sm.exportReport('s1', 'json');
  assert.ok(json.includes('5f4dcc3b5aa765d61d8327deb882cf99'), '默认应保留哈希原文');
  assert.ok(json.includes('21232f297a57a5a743894a0e4a801fc3'), '默认应保留第二个哈希原文');
});

test('redactPasswords=true → passwords 哈希原文打码', () => {
  const sm = new ScanManager();
  sm.scans.set('s2', makeScanEntry(true));
  const json = sm.exportReport('s2', 'json');
  assert.ok(!json.includes('5f4dcc3b5aa765d61d8327deb882cf99'), '开启脱敏后不应含哈希原文');
  assert.ok(json.includes('[REDACTED]'), '应含 [REDACTED] 标记');
  assert.ok(json.includes('admin:'), '应保留 identity（admin:）');
});

test('opts.redactPasswords 运行时覆盖 → 导出脱敏（即使 scan 上下文未设）', () => {
  const sm = new ScanManager();
  sm.scans.set('s3', makeScanEntry(false));
  const json = sm.exportReport('s3', 'json', undefined, { redactPasswords: true });
  assert.ok(!json.includes('5f4dcc3b5aa765d61d8327deb882cf99'), '运行时覆盖应脱敏');
  assert.ok(json.includes('[REDACTED]'), '应含 [REDACTED] 标记');
});

test('redactTarget=true → target.config.auth/proxy 置 null', () => {
  const sm = new ScanManager();
  sm.scans.set('s4', makeScanEntry(true));
  const json = sm.exportReport('s4', 'json');
  const parsed = JSON.parse(json);
  assert.equal(parsed.target.config.auth, null, 'auth 应置 null');
  assert.equal(parsed.target.config.proxy, null, 'proxy 应置 null');
});