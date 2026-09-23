// errorDetector.compact.test.js —— 报错模板「按机制族裁剪」的不变量
// ============================================================================
// 背景（2026-09-23）：`pickErrorTemplates` 在 dbms 已知时**整包返回**（MySQL 61 条）。
// 命中即停让"能注入的点"很便宜，但**不命中的点会把整包走完** —— 而真实扫描里绝大多数
// 点是不命中的。故按「报错机制族」有界裁剪（默认档），高阶档（level/risk ≥3）仍走全量。
//
// 这组用例只钉**不变量**（不许用漏检换请求数），不钉具体条数（模板会随库演进）：
//   ① 不许丢机制族 —— 丢一族 = 关掉一类报错机制，那不是优化是阉割；
//   ② 条数有界；
//   ③ 族表覆盖不足时**必须拒绝裁剪**（宁可不省）；
//   ④ 保持原相对顺序（原顺序 ≈ 历史收益序）；
//   ⑤ 高阶档不得裁剪。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ERROR_MECHANISMS,
  compactErrorTemplates,
  pickErrorTemplates,
} from '../src/engine/detectors/ErrorDetector.js';
import { PAYLOADS } from '../src/engine/payloads/index.js';

const famOf = (t) => (ERROR_MECHANISMS.find(([, re]) => re.test(t)) || [null])[0];
const famSet = (list) => new Set(list.map(famOf).filter(Boolean));

test('① 裁剪后每种报错机制都还在（丢族 = 关掉一类报错通道）', () => {
  for (const dbms of ['MySQL', 'PostgreSQL', 'SQL Server']) {
    const all = PAYLOADS[dbms]?.error;
    if (!all?.length) continue;
    const r = compactErrorTemplates(all, {});
    if (!r.compacted) continue; // 覆盖不足的库本就不裁（由 ③ 单独钉）
    const before = famSet(all);
    const after = famSet(r.tpls);
    const lost = [...before].filter((f) => !after.has(f));
    assert.deepEqual(
      lost,
      [],
      `${dbms}：裁剪后丢失了机制族 ${lost.join(',')}（${all.length} → ${r.tpls.length}）`,
    );
  }
});

test('② 条数有界（预算不随模板增长而膨胀）', () => {
  const all = PAYLOADS.MySQL.error;
  const r = compactErrorTemplates(all, {});
  assert.ok(r.tpls.length <= 24, `裁剪后 ${r.tpls.length} 条超过上限 24`);
  assert.ok(r.tpls.length < all.length, '本例应当真的变小（否则说明探针/阈值失效）');
  assert.ok(compactErrorTemplates(all, { maxTotal: 8 }).tpls.length <= 8);
});

test('③ 未识别机制占比过高时必须拒绝裁剪（宁可不省，不可瞎裁）', () => {
  // 构造族表覆盖不到的模板：全部落进 other → 占比 100% → 必须原样返回
  const alien = Array.from({ length: 30 }, (_, i) => `{ORIG}' AND unknown_func_${i}(1)-- -`);
  const r = compactErrorTemplates(alien, {});
  assert.equal(r.compacted, false, '未识别占比 100% 时不得裁剪');
  assert.equal(r.tpls.length, 30);
  assert.match(r.reason ?? '', /未识别机制/);
});

test('④ 保持原相对顺序（原数组顺序 ≈ 历史收益序，打乱会让高收益模板后移）', () => {
  const all = PAYLOADS.MySQL.error;
  const r = compactErrorTemplates(all, {});
  const rank = new Map(all.map((t, i) => [t, i]));
  const idx = r.tpls.map((t) => rank.get(t));
  for (let i = 1; i < idx.length; i++) {
    assert.ok(idx[i] > idx[i - 1], `第 ${i} 条顺序倒挂（idx ${idx[i - 1]} → ${idx[i]}）`);
  }
  // 第一条应是全量里的第一条（最高收益模板不得被挤掉）
  assert.equal(r.tpls[0], all[0]);
});

// [口径修正 2026-09-23] 初版是「默认档就裁」，CI 立刻给出代价：CRS PL1 技术位 8 → 6
// （干净场景零损失，但 WAF 场景需要更多同机制不同形态的弹药）。
// 本仓口径：**不用检出能力换请求数** → 默认全量，显式 compact 才裁。
test('⑤ 默认档不裁剪；显式 compact 才裁；compact:false 恒全量', () => {
  const all = PAYLOADS.MySQL.error;
  assert.equal(pickErrorTemplates('MySQL', {}).length, all.length, '默认档应全量（能力优先）');
  assert.equal(pickErrorTemplates('MySQL', { compact: false }).length, all.length);
  const compacted = pickErrorTemplates('MySQL', { compact: true }).length;
  assert.ok(compacted < all.length, `显式开启后应变小（现在 ${compacted}/${all.length}）`);
  assert.ok(compacted <= 24);
});

test('⑥ 小模板集不裁剪（避免无意义计算 + 顺序/语义扰动）', () => {
  const small = ['{ORIG} AND 1=1-- -', '{ORIG} AND 2=2-- -'];
  const r = compactErrorTemplates(small, {});
  assert.equal(r.compacted, false);
  assert.deepEqual(r.tpls, small);
});

test('⑦ 族表本身不得腐烂：每条 MySQL 报错模板都应能归类（否则会落进 other 被整体放弃）', () => {
  const unclassified = PAYLOADS.MySQL.error.filter((t) => !famOf(t));
  assert.deepEqual(
    unclassified,
    [],
    `以下模板未匹配任何机制族（新增报错机制请同步补 ERROR_MECHANISMS）：${unclassified.join(' | ')}`,
  );
});
