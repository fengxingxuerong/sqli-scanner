// [P0 2026-09-09 实战批次] 失效值替换（--invalid-*）+ 已知注入点直通（knownPoint）单测
// 覆盖：① invalidize 三种模式语义；② applyInvalidValues/applyKnownPoints 点级改写；
//      ③ probeBoundary knownPoint 短路（13 候选探测 → 1 基线请求）；
//      ④ _prefilterPoints 直通点保守保留且并入返回集；⑤ _selectedTechs 技术位交集；
//      ⑥ sanitizeStart REST 透传。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { invalidize, applyInvalidValues, isValidInvalidMode } from '../src/engine/invalidValue.js';
import { applyKnownPoints, normalizeKnownPoint } from '../src/engine/knownPoint.js';
import { Detector } from '../src/engine/Detector.js';
import { ScanManager } from '../src/engine/ScanManager.js';
import { sanitizeStart } from '../src/api/scanRoutes.js';

const mkPoints = (defs) =>
  defs.map(([param, originalValue]) => ({
    id: `p_${param}_${originalValue}`,
    param,
    location: 'url',
    originalValue,
  }));

test('invalidize：三种模式语义正确，非法模式零行为变化', () => {
  assert.equal(isValidInvalidMode('bignum'), true);
  assert.equal(isValidInvalidMode('nope'), false);
  // bignum：纯数字且数值量级 ≥1e6
  const big = invalidize('1', 'bignum');
  assert.match(big, /^\d+$/);
  assert.ok(Number(big) >= 1_000_000, `bignum 量级不足: ${big}`);
  // logical：恒真等值式 n=n（基线语义安全，绝不产出 1=2 恒假式）
  const lg = invalidize('7', 'logical');
  assert.match(lg, /^\d+=\d+$/);
  const [a, b] = lg.split('=').map(Number);
  assert.equal(a, b, 'logical 必须是恒真等值式');
  // string：纯小写字母串
  const st = invalidize('42', 'string');
  assert.match(st, /^[a-z]{8}$/);
  // 非法模式 / 未启用：原样返回（零回归兜底）
  assert.equal(invalidize('1', null), '1');
  assert.equal(invalidize('1', 'nope'), '1');
});

test('applyInvalidValues：仅启用时改写点；未启用零改写', () => {
  const points = mkPoints([['id', '1'], ['q', 'abc']]);
  assert.equal(applyInvalidValues(points, {}), 0);
  assert.equal(points[0].originalValue, '1');
  const n = applyInvalidValues(points, { invalidValue: 'bignum' });
  assert.equal(n, 2);
  assert.notEqual(points[0].originalValue, '1');
  assert.match(points[0].originalValue, /^\d+$/);
});

test('applyKnownPoints：param 匹配打标 + 闭合形态写死；未命中零改写', () => {
  const points = mkPoints([['id', '1'], ['q', 'abc']]);
  assert.equal(applyKnownPoints(points, { knownPoint: { param: 'nope' } }), 0);
  assert.equal(points[0].knownPoint, undefined);
  const n = applyKnownPoints(points, { knownPoint: { param: 'id', quote: "'", paren: ')' } });
  assert.equal(n, 1);
  assert.equal(points[0].knownPoint, true);
  assert.equal(points[0].boundary, "')");
  assert.equal(points[0].knownBoundary, true);
  assert.equal(points[1].knownPoint, undefined);
});

test('normalizeKnownPoint：非法形状一律拒绝', () => {
  assert.equal(normalizeKnownPoint(null), null);
  assert.equal(normalizeKnownPoint({}), null);
  assert.equal(normalizeKnownPoint({ param: '  ' }), null);
  const ok = normalizeKnownPoint({ param: 'id', quote: "'", techniques: ['union', 'bad_tech', 'boolean'] });
  assert.deepEqual(ok, { param: 'id', quote: "'", techniques: ['union', 'boolean'] });
});

test('probeBoundary：knownPoint 短路（仅 1 次基线请求，无 13 候选并发）', async () => {
  const d = new Detector('union');
  let reqCount = 0;
  const httpClient = {
    async request() {
      reqCount++;
      return { status: 200, data: '<html><title>T</title>ok</html>' };
    },
  };
  const point = { id: 'p1', param: 'id', location: 'url', originalValue: '1', knownPoint: true, boundary: "'" };
  const prefix = await d.probeBoundary({ httpClient, target: { method: 'GET', baseUrl: 'http://t/?id=1' }, point, config: {} });
  assert.equal(prefix, "'");
  assert.equal(reqCount, 1, `knownPoint 应只发 1 次基线请求，实际 ${reqCount}`);
  assert.equal(point._baselineTitle, 'T', '基线请求仍应学习页面标题');
});

test('probeBoundary：普通点仍走候选探测（回归对照）', async () => {
  const d = new Detector('union');
  let reqCount = 0;
  const httpClient = {
    async request() {
      reqCount++;
      return { status: 200, data: 'ok' };
    },
  };
  const point = { id: 'p1', param: 'id', location: 'url', originalValue: '1' };
  await d.probeBoundary({ httpClient, target: { method: 'GET', baseUrl: 'http://t/?id=1' }, point, config: {} });
  // [2026-09-10] 本 mock 所有响应均为 'ok' → 13 个候选全部「相似于基线」→ 触发空基线 OR 复核
  // （上限 4 个候选 × 2 探针 = 8 请求）。故请求数由固定 14 变为区间：14（无歧义）～22（最坏）。
  assert.ok(reqCount >= 14 && reqCount <= 22, `普通点应为 1 基线 + 13 候选（+ 空基线 OR 复核 ≤8），实际 ${reqCount}`);
});

test('_prefilterPoints：knownPoint 点跳过探针且并入返回集', async () => {
  const sm = new ScanManager();
  const deadClient = { async request() { throw new Error('unreachable'); } };
  const known = { id: 'kp', param: 'id', location: 'url', originalValue: '1', knownPoint: true, boundary: "'" };
  const normal = { id: 'np', param: 'q', location: 'url', originalValue: '1' };
  const target = { url: 'http://t.local/?id=1&q=1', baseUrl: 'http://t.local/?id=1&q=1', method: 'GET' };
  const ctxBase = { httpClient: deadClient, config: { prefilterBudgetMs: 300 } };
  const kept = await sm._prefilterPoints(ctxBase, target, [known, normal]);
  // 已知点必须出现在返回集（不可达目标探针全失败也绝不丢点）
  assert.ok(kept.includes(known), 'knownPoint 点必须并入返回集');
  assert.ok(kept.includes(normal), '普通点在不可达目标下保守保留');
});

test('_selectedTechs：knownPoint.techniques 与 techniques 取交集', () => {
  const sm = new ScanManager();
  // 无 knownPoint：默认全集
  assert.ok(sm._selectedTechs({}).includes('union'));
  // knownPoint.techniques 交集
  const techs = sm._selectedTechs({ knownPoint: { param: 'id', techniques: ['union', 'boolean'] } });
  assert.deepEqual(techs.sort(), ['boolean', 'union']);
  // 与显式 techniques 双重交集
  const both = sm._selectedTechs({ techniques: ['union', 'error'], knownPoint: { param: 'id', techniques: ['union', 'boolean'] } });
  assert.deepEqual(both, ['union']);
});

test('sanitizeStart：invalidValue / knownPoint REST 透传与非法值拒绝', () => {
  const base = { url: 'http://t.local/?id=1' };
  const r1 = sanitizeStart({ target: base, config: { invalidValue: 'Bignum', knownPoint: { param: ' id ', quote: "'", techniques: ['union', 'x'] } } });
  assert.equal(r1.config.invalidValue, 'bignum');
  assert.equal(r1.config.knownPoint.param, 'id');
  assert.equal(r1.config.knownPoint.quote, "'");
  assert.deepEqual(r1.config.knownPoint.techniques, ['union']);
  // 非法模式丢弃；knownPoint 缺 param 整体丢弃
  const r2 = sanitizeStart({ target: base, config: { invalidValue: 'evil', knownPoint: { quote: "'" } } });
  assert.equal(r2.config.invalidValue, undefined);
  assert.equal(r2.config.knownPoint, undefined);
});

