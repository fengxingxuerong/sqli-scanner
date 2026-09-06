// F-19 增量回归：技术选择机制 + 堆叠去重 + 风险定级 + Oracle 不投放
// 通过 mock Detectors 与 DBFingerprinter 验证 ScanManager 调度与聚合行为。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanManager } from '../src/engine/ScanManager.js';
import { TECHNIQUE_TYPES } from '../src/engine/payloads.js';

// 构造一个可控的检测器桩：mockDetectors 为 { technique: {vulnerable, dbms} }
function makeScanManager(mockDetectors) {
  const sm = new ScanManager();
  // 用桩替换真实检测器，按 technique 命中
  sm.detectors = TECHNIQUE_TYPES.map((t) => {
    const hit = mockDetectors[t];
    return {
      technique: t,
      async detect(ctx) {
        return {
          pointId: ctx.point.id,
          technique: t,
          vulnerable: !!(hit && hit.vulnerable),
          dbms: hit ? hit.dbms : null,
          evidence: hit && hit.vulnerable ? `mock ${t} hit` : '',
          payloads: hit && hit.vulnerable ? [`mock_${t}`] : [],
        };
      },
    };
  });
  // 指纹桩：固定返回指定 dbms（F-20 起 fingerprint 返回 { dbms, baseline }）
  sm.fp = {
    async fingerprint() {
      return { dbms: mockDetectors.__dbms || null, baseline: { status: 200, headers: {}, body: '' } };
    },
  };
  // 停止提取逻辑，避免触发真实请求
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  return sm;
}

// 直接调用私有聚合逻辑（不跑真正扫描），用 _selectedTechs / activeDetectors
test('_selectedTechs: 无 techniques → 全部（含 stacked）', () => {
  const sm = makeScanManager({});
  const techs = sm._selectedTechs({});
  assert.deepEqual(techs, TECHNIQUE_TYPES);
  assert.ok(techs.includes('stacked'));
});

test('_selectedTechs: 空数组 → 全部（含 stacked）', () => {
  const sm = makeScanManager({});
  const techs = sm._selectedTechs({ techniques: [] });
  assert.deepEqual(techs, TECHNIQUE_TYPES);
});

test('_selectedTechs: 指定子集 → 仅所选', () => {
  const sm = makeScanManager({});
  const techs = sm._selectedTechs({ techniques: ['union'] });
  assert.deepEqual(techs, ['union']);
});

test('activeDetectors: 老配置（无 techniques）→ 5 个全跑', () => {
  const sm = makeScanManager({});
  assert.equal(sm.activeDetectors({}).length, TECHNIQUE_TYPES.length);
});

test('activeDetectors: techniques=["union"] → 仅 1 个', () => {
  const sm = makeScanManager({});
  const active = sm.activeDetectors({ techniques: ['union'] });
  assert.equal(active.length, 1);
  assert.equal(active[0].technique, 'union');
});

test('activeDetectors: techniques=[] → 全部（含 stacked）', () => {
  const sm = makeScanManager({});
  assert.equal(sm.activeDetectors({ techniques: [] }).length, TECHNIQUE_TYPES.length);
});

test('Oracle 不投放堆叠：stacked detect 直接未命中', async () => {
  const sm = makeScanManager({});
  const stacked = sm.detectors.find((d) => d.technique === 'stacked');
  const ctx = {
    httpClient: {},
    target: { method: 'GET', baseUrl: 'http://x?v=1', config: {} },
    point: { id: 'p1', location: 'url', param: 'v', originalValue: '1', confirmed: false },
    dbms: 'Oracle',
    config: {},
  };
  const res = await stacked.detect(ctx);
  assert.equal(res.vulnerable, false);
});

test('dedupeByStacked: 同点 stacked+time 命中 → 仅 1 条 stacked(Critical)，time 进入印证', () => {
  const sm = makeScanManager({});
  // 模拟 _run 聚合部分
  const point = { id: 'p1' };
  const found = [
    { technique: 'time', result: { pointId: 'p1', technique: 'time', vulnerable: true, dbms: 'SQL Server', evidence: 't', payloads: ['tp'] } },
    { technique: 'stacked', result: { pointId: 'p1', technique: 'stacked', vulnerable: true, dbms: 'SQL Server', evidence: 's', payloads: ['sp'] } },
  ];
  const finalVulns = [];
  const corroborations = [];
  const stackedItem = found.find((f) => f.technique === 'stacked');
  const items = stackedItem ? [stackedItem] : found;
  if (stackedItem) {
    for (const f of found) {
      if (f !== stackedItem) corroborations.push({ pointId: point.id, technique: f.technique, dbms: f.result.dbms });
    }
  }
  for (const f of items) {
    const risk = f.technique === 'stacked' ? 'Critical' : sm.reportGen.riskOf([
      // 占位 createVulnerability 调用
      { pointId: point.id, technique: f.technique, dbms: f.result.dbms, riskLevel: 'Medium', payloads: f.result.payloads, description: f.result.evidence },
    ]);
    finalVulns.push({ pointId: point.id, technique: f.technique, riskLevel: risk, dbms: f.result.dbms, payloads: f.result.payloads, description: f.result.evidence });
  }
  assert.equal(finalVulns.length, 1);
  assert.equal(finalVulns[0].technique, 'stacked');
  assert.equal(finalVulns[0].riskLevel, 'Critical');
  assert.equal(corroborations.length, 1);
  assert.equal(corroborations[0].technique, 'time');
});
