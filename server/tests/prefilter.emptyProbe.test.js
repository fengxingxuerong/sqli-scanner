// ============================================================================
// tests/prefilter.emptyProbe.test.js —— 「时间探针为空」绝不能读成「该点无迹象」
//
// 判据本体：prefilterPoints 用 `timed.some(...)` 决定要不要跳过完整检测，而
// timeProbeValues('SQLite') 返回**空数组**（SQLite 无服务端 sleep）。空数组上
// `.some()` 恒 false ⇒ 只要基线与单引号探针同构，点就被整点剪掉 —— 与
// 本模块文件头那条红线（「任何不可判定都保留，绝不因探测失败漏检」）相反：
// 这里不是探测失败，是**判据落在不存在的探针上**。
// 后果只在显式 --dbms SQLite 时出现（未定库走 default 分支有 3 条探针），
// 而布尔/时间型注入点恰恰是最不该被剪的那类。
//
// 同时锁住反方向：探针非空且两探皆无信号时**必须仍然剪**，否则这条修复会把
// 预筛的剪枝收益整个赔掉（实测削减 200+ 请求 → 个位数的意义就没了）。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ScanManager } from '../src/engine/ScanManager.js';
import { timeProbeValues } from '../src/engine/scan/prefilter.js';

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
// 2 个点：预筛默认 ≥2 点才跑
const mkPoints = () => [
  { id: 'p0', location: 'url', param: 'id', originalValue: '1' },
  { id: 'p1', location: 'url', param: 'cat', originalValue: '2' },
];

// 「静默目标」：任何输入都秒回同一张 200 页 —— 基线/单引号/时间探针全部同构且无延迟。
// 这正是「无信号」形态，用来检验预筛在**不同探针数量**下各自的判定方向。
const silentClient = {
  async request() {
    return { status: 200, data: '<h1>same page</h1>', headers: {} };
  },
};

const runPrefilter = async (dbms) => {
  const sm = new ScanManager();
  const target = mkTarget();
  const points = mkPoints();
  const ctxBase = {
    httpClient: silentClient,
    // 固定预算：跳过 probeBaselineRttMs，让用例与本机网络无关（确定性）
    config: { prefilter: true, prefilterSinglePoint: true, prefilterBudgetMs: 1500, dbms },
    target,
  };
  const kept = await sm._prefilterPoints(ctxBase, target, points);
  return { kept, total: points.length };
};

test('前置事实：SQLite 的时间探针为空（修复的成立前提）', () => {
  assert.deepEqual(timeProbeValues('SQLite', 2), [], 'SQLite 无服务端 sleep，探针表为空');
  // 未定库不能为空 —— 否则下面的用例就成了「全部保守保留」的空断言
  assert.ok(timeProbeValues(null, 2).length > 0, '未定库必须仍有探针，否则预筛整体失去意义');
});

test('★假阴性★ 显式 --dbms SQLite：探针为空时不得判「无迹象」而剪掉整点', async () => {
  const { kept, total } = await runPrefilter('SQLite');
  assert.equal(
    kept.length,
    total,
    `时间探针为空 = 不可判定，必须保守保留全部 ${total} 点，实际保留 ${kept.length}（空数组上的 .some() 恒 false ⇒ 整点漏检）`
  );
});

test('反方向：探针非空且确实无信号时仍要剪（别把剪枝收益一起赔掉）', async () => {
  const { kept } = await runPrefilter('MySQL');
  assert.equal(kept.length, 0, 'MySQL 目标两探皆无信号 → 预筛就该剪，修复不得把它变成全保留');
});

test('未定库（探针 3 条）无信号时同样剪', async () => {
  const { kept } = await runPrefilter(undefined);
  assert.equal(kept.length, 0, '未定库走 default 分支有探针，无信号判定方向不变');
});
