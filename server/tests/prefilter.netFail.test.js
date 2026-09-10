// ============================================================================
// tests/prefilter.netFail.test.js —— 「探测失败」绝不能变成「这个点不用测」
// [P0-FIX 2026-09-09]
//
// 这是 sendInjection 从「失败返回 null」改成「失败返回带 __netErr 的响应对象」时，
// 必须一起收口的地方：预筛选 / 静态跳过 / 输入校验短路都以「拿不到响应 → 保守保留」为安全底线，
// 判据写的是 `res == null`。对象永远非 null，于是两次失败会被读成
// 「基线与注入响应同构 → 无注入迹象 → 跳过完整检测」——这是**新增假阴性**，
// 而且只在目标不稳定时出现（最难复现、最容易带进交付的那类错）。
// 同时锁住时间指纹：超时不是「延迟命中」，否则误定库 → payload 族错配 → 整轮漏检。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanManager } from '../src/engine/ScanManager.js';
import { DBFingerprinter } from '../src/engine/DBFingerprinter.js';

const mkTarget = () => ({
  mode: 'http',
  url: 'http://t.test/?id=1',
  baseUrl: 'http://t.test/?id=1',
  method: 'GET',
  bodyParams: {},
  cookieParams: {},
  headerParams: {},
  config: {},
});
const mkPoints = (n = 2) =>
  Array.from({ length: n }, (_, i) => ({
    id: `p${i}`,
    location: 'url',
    param: ['id', 'cat'][i] || `p${i}`,
    originalValue: '1',
  }));

// 一切请求都「发不出去」：抛 ECONNREFUSED（httpClient 会包成 AppError(3002)）
const deadClient = {
  async request() {
    throw Object.assign(new Error('connect ECONNREFUSED 10.0.0.7:80'), { code: 'ECONNREFUSED' });
  },
};

test('预筛选：目标不可达时保留全部注入点（不得因探测失败而跳过）', async () => {
  const sm = new ScanManager();
  const target = mkTarget();
  const points = mkPoints(2);
  const ctxBase = { httpClient: deadClient, config: { prefilter: true, prefilterSinglePoint: true }, target };
  // 基线 RTT 探测必须判为「拿不到」→ null（旧写法 `res == null` 在新返回形态下会失守）
  assert.equal(await sm._probeBaselineRttMs(deadClient, { ...ctxBase, target }, target, points[0]), null);
  const kept = await sm._prefilterPoints(ctxBase, target, points);
  assert.equal(kept.length, points.length, `不可达目标的预筛必须零跳过，实际保留 ${kept.length}/${points.length}`);
});

test('输入校验短路：探测失败时不跳过任何点', async () => {
  const sm = new ScanManager();
  const target = mkTarget();
  const points = mkPoints(2);
  const ctxBase = { httpClient: deadClient, config: { validationSkip: true }, target };
  const out = await sm._validationGuardedSkipPoints(ctxBase, target, points);
  assert.deepEqual(out.skipped, [], '探测全失败却把点判为「输入被校验拦死」= 假阴性');
  assert.equal(out.candidate.length, points.length);
});

test('静态跳过：哨兵探测失败时保留该点（同值去重不适用于不同值）', async () => {
  const sm = new ScanManager();
  const target = mkTarget();
  // 两个点用不同的原始值：避开「同值去重」这条与网络无关的规则，只测「探测失败 → 保守保留」
  const points = [
    { id: 'p0', location: 'url', param: 'id', originalValue: '1' },
    { id: 'p1', location: 'url', param: 'cat', originalValue: '7' },
  ];
  const ctxBase = { httpClient: deadClient, config: { skipStatic: true }, target };
  const kept = await sm._skipStaticPoints(ctxBase, target, points);
  assert.equal(kept.length, points.length, `哨兵探测失败应保守保留，实际保留 ${kept.length}/${points.length}`);
});

test('时间指纹：请求失败不得被当成「延迟命中」（会误定库）', async () => {
  const fp = new DBFingerprinter();
  const target = mkTarget();
  const point = mkPoints(1)[0];
  const config = { fingerprintSleepSec: 1, fingerprintTimeThresholdMs: 1 };
  const obf = (s) => s;
  // 关键：故意把阈值压到 1ms（任何耗时都算「延迟」）——只有正确排除不可用响应才不会定库
  const dbms = await fp._fingerprintByTime({ httpClient: deadClient, target, point, config }, deadClient, target, point, obf, config, 0);
  assert.equal(dbms, null, `超时/拒连不得定库，实际定成 ${dbms}`);
});
