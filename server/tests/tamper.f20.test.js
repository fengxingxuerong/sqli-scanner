// F-20 增量测试：tamper 链式契约（obfuscateWithConfig）+ tamper 只读端点 + ScanManager 报告标注
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import { obfuscateWithConfig } from '../src/core/tamper/applyTampers.js'; // 触发插件注册（副作用）
import { obfuscatePayload } from '../src/engine/payloads.js';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
import { tamperRoutes } from '../src/api/tamperRoutes.js';
import { ScanManager } from '../src/engine/ScanManager.js';
import { TECHNIQUE_TYPES } from '../src/engine/payloads.js';
import { create as createEmitter } from '../src/core/eventBus.js';

// 等待扫描完成（监听 scan_completed / scan_error 事件；report 本身无 status 字段，status 在扫描态上）
async function runScanUntilDone(sm, scanId, timeoutMs = 8000) {
  const em = createEmitter(scanId);
  await new Promise((resolve, reject) => {
    const onEvent = (evt) => {
      if (evt.type === 'scan_completed') {
        cleanup();
        resolve();
      } else if (evt.type === 'scan_error') {
        cleanup();
        reject(new Error(`scan error: ${evt.payload && evt.payload.message}`));
      }
    };
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('scan did not finish in time'));
    }, timeoutMs);
    const cleanup = () => {
      clearTimeout(timer);
      em.off('event', onEvent);
    };
    em.on('event', onEvent);
  });
  return sm.getReport(scanId);
}

// 构造可控 ScanManager：检测器均不命中，指纹返回指定 dbms + baseline（避免真实网络）
function makeManager({ dbms = null, wafBaseline } = {}) {
  const sm = new ScanManager();
  sm.detectors = TECHNIQUE_TYPES.map((t) => ({
    technique: t,
    async detect() {
      return { pointId: 'p1', technique: t, vulnerable: false, dbms: null, evidence: '', payloads: [] };
    },
  }));
  sm.fp = {
    async fingerprint() {
      return { dbms: dbms || null, baseline: wafBaseline || { status: 200, headers: {}, body: '' } };
    },
  };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  sm.parser = {
    async discover() {
      return [{ id: 'p1', location: 'url', param: 'v', originalValue: '1', confirmed: false }];
    },
  };
  return sm;
}

function getJson(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(data) }));
      })
      .on('error', reject);
  });
}

// ── 1) obfuscateWithConfig 契约 ─────────────────────────────────────────────
test('tamper 关闭 + obfuscate 关闭 → 原样返回', () => {
  assert.equal(obfuscateWithConfig('SELECT 1', { config: {} }), 'SELECT 1');
  assert.equal(obfuscateWithConfig('SELECT 1', { config: { wafEvasion: {} } }), 'SELECT 1');
});

test('tamper 开启 + 指定 plugins → 按序链式变换', () => {
  // space2comment 将空格转 /**/，lowercase 确定性小写（避免 randomcase 随机大小写不可断言）
  const ctx = { config: { wafEvasion: { tamper: { enabled: true, plugins: ['space2comment', 'lowercase'], intensity: 'medium' } } } };
  assert.equal(obfuscateWithConfig('SELECT 1', ctx), 'select/**/1');
});

test('tamper 开启但 plugins 为空 → 原样返回', () => {
  const ctx = { config: { wafEvasion: { tamper: { enabled: true, plugins: [], intensity: 'medium' } } } };
  assert.equal(obfuscateWithConfig('SELECT 1', ctx), 'SELECT 1');
});

test('tamper 优先级高于 legacy obfuscate（两者均开 → 走 tamper）', () => {
  const ctx = {
    config: {
      wafEvasion: { tamper: { enabled: true, plugins: ['space2comment'], intensity: 'medium' }, obfuscate: true },
    },
  };
  assert.equal(obfuscateWithConfig('SELECT 1', ctx), 'SELECT/**/1');
});

test('仅 legacy obfuscate 开启 → 走 obfuscatePayload（向后兼容）', () => {
  const ctx = { config: { wafEvasion: { obfuscate: true } } };
  assert.equal(obfuscateWithConfig('SELECT 1', ctx), obfuscatePayload('SELECT 1'));
});

// ── 2) tamper 只读端点 ──────────────────────────────────────────────────────
test('GET /api/tampers 返回 64 项 tamper 清单（name+description）', async () => {
  const app = express();
  app.use('/api', tamperRoutes);
  const server = app.listen(0);
  const { port } = server.address();
  try {
    const { json } = await getJson(`http://127.0.0.1:${port}/api/tampers`);
    assert.equal(json.code, 0);
    assert.equal(json.data.length, 64);
    assert.ok(json.data.every((t) => typeof t.name === 'string' && typeof t.description === 'string'));
  } finally {
    server.close();
  }
});

test('tamperRegistry 单例与端点数据一致', () => {
  assert.equal(tamperRegistry.list().length, 64);
});

// ── 3) ScanManager 报告标注（tamper + WAF 识别）──────────────────────────────
test('ScanManager：开启 tamper 后 summary.wafEvasion.tamper 正确记录', async () => {
  const sm = makeManager({ wafBaseline: { status: 200, headers: { 'cf-ray': 'abc', server: 'cloudflare' }, body: '' } });
  const scanId = await sm.start({
    url: 'http://test.local/?v=1',
    method: 'GET',
    bodyParams: {},
    cookieParams: {},
    headerParams: {},
    config: {
      techniques: ['union'],
      wafEvasion: { tamper: { enabled: true, plugins: ['space2comment', 'randomcase'], intensity: 'high' } },
    },
  });
  const report = await runScanUntilDone(sm, scanId);
  assert.ok(report.summary.wafEvasion);
  assert.equal(report.summary.wafEvasion.tamper.enabled, true);
  assert.deepEqual(report.summary.wafEvasion.tamper.plugins, ['space2comment', 'randomcase']);
  assert.equal(report.summary.wafEvasion.tamper.intensity, 'high');
});

test('ScanManager：关闭 tamper 时 summary.wafEvasion 不写（向后兼容）', async () => {
  const sm = makeManager();
  const scanId = await sm.start({
    url: 'http://test.local/?v=1',
    method: 'GET',
    bodyParams: {},
    cookieParams: {},
    headerParams: {},
    config: { techniques: ['union'], wafEvasion: { tamper: { enabled: false, plugins: [], intensity: 'medium' } } },
  });
  const report = await runScanUntilDone(sm, scanId);
  assert.equal(report.summary.wafEvasion, undefined);
});

test('ScanManager：识别到 WAF → 发射 waf_detected 且 summary.wafDetected 记录', async () => {
  const sm = makeManager({
    wafBaseline: { status: 200, headers: { 'cf-ray': 'abc123', server: 'cloudflare' }, body: '' },
  });
  const scanId = await sm.start({
    url: 'http://test.local/?v=1',
    method: 'GET',
    bodyParams: {},
    cookieParams: {},
    headerParams: {},
    config: { techniques: ['union'] },
  });
  let wafEvent = null;
  // 同步订阅本次扫描的 waf_detected（在 start 返回后、任何 await 之前订阅，避免竞态）
  const emitter = createEmitter(scanId);
  emitter.on('event', (evt) => {
    if (evt.type === 'waf_detected') wafEvent = evt.payload;
  });
  const report = await runScanUntilDone(sm, scanId);
  assert.ok(wafEvent, '应发射 waf_detected 事件');
  assert.equal(wafEvent.vendors[0].vendor, 'Cloudflare');
  assert.ok(Array.isArray(wafEvent.suggestions) && wafEvent.suggestions.length > 0);
  assert.ok(Array.isArray(report.summary.wafDetected) && report.summary.wafDetected.length === 1);
  assert.equal(report.summary.wafDetected[0].vendor, 'Cloudflare');
});
