// =====================================================================
// prefilter.pure.test.js —— scan/prefilter.js 纯函数簇的直接单测
//
// [为什么单独建文件]
// [大文件拆分 2026-09-20] 预过滤家族（9 方法 / ~390 行）从 ScanManager.js 外移到
// scan/prefilter.js。其中 5 个是**无状态纯函数**，此前只能通过整个扫描链路间接验证
// （要起真靶场、发真探测请求）。
//
// 抽成纯函数后可以穷举判定边界 —— 这是拆分真正带来的价值，不只是"文件变小"。
// 本文件只测纯函数；带 I/O 的三个（skipStaticPoints / prefilterPoints /
// validationGuardedSkipPoints）仍由 prefilter.netFail / prefilter.validation 覆盖。
//
// 这些判定的共同红线是**保守**：判错的方向必须是「多测」而非「漏检」。
// 故下面每个 `false`/边界用例都是在钉「绝不误判为可跳过」。
// =====================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  staticSentinel,
  normalizeForStatic,
  normEcho,
  prefilterSimilar,
  timeProbeValues,
} from '../src/engine/scan/prefilter.js';

// ── staticSentinel ───────────────────────────────────────────────────

test('staticSentinel：整数 +1001（1→1002）', () => {
  assert.equal(staticSentinel('1'), '1002');
  assert.equal(staticSentinel('42'), '1043');
  assert.equal(staticSentinel('0'), '1001');
  assert.equal(staticSentinel('-5'), '996');
});

test('staticSentinel：小数保留小数部分（3.14→1004.14）', () => {
  assert.equal(staticSentinel('3.14'), '1004.14');
  assert.equal(staticSentinel('-0.5'), '1000.5');
});

test('staticSentinel：非数字字符串加 _sst 后缀', () => {
  assert.equal(staticSentinel('abc'), 'abc_sst');
  assert.equal(staticSentinel(''), '_sst');
});

test('staticSentinel：科学计数法/十六进制等**不当数字**处理（保守）', () => {
  // 正则 ^-?\d+(\.\d+)?$ 不匹配 → 走字符串分支。
  // 这是有意的：把 "1e9" 当数字会算出 1000001001，形态过于"像原值的变体"，
  // 反而更容易被目标当成同一类输入 → 哨兵探测失去区分力。
  assert.equal(staticSentinel('1e9'), '1e9_sst');
  assert.equal(staticSentinel('0x10'), '0x10_sst');
  assert.equal(staticSentinel('1,000'), '1,000_sst');
});

test('staticSentinel：哨兵值必须与原值不同（否则探测恒同构 → 全部误判静态）', () => {
  for (const v of ['1', '0', '-1', '999', 'a', '']) {
    assert.notEqual(staticSentinel(v), v, `哨兵不得等于原值: ${JSON.stringify(v)}`);
  }
});

// ── normalizeForStatic ───────────────────────────────────────────────

test('normalizeForStatic：折叠连续空白并去首尾', () => {
  assert.equal(normalizeForStatic('  a \n b \t c  '), 'a b c');
  assert.equal(normalizeForStatic('a\r\n\r\nb'), 'a b');
  assert.equal(normalizeForStatic('\t\n  '), '');
});

test('normalizeForStatic：**仅**折叠空白 —— 大小写/标点/内容差异必须保留', () => {
  // 这些差异一旦被"顺手归一化"，动态参数（时间戳/CSRF）就会被误判成静态 → 漏检。
  assert.notEqual(normalizeForStatic('abc'), normalizeForStatic('ABC'), '大小写须保留');
  assert.notEqual(normalizeForStatic('a.b'), normalizeForStatic('a,b'), '标点须保留');
  assert.notEqual(normalizeForStatic('page v1'), normalizeForStatic('page v2'), '内容须保留');
  assert.notEqual(normalizeForStatic('id=1'), normalizeForStatic('id=2'), '数字须保留');
});

test('normalizeForStatic：null/undefined → 空串（不抛错）', () => {
  assert.equal(normalizeForStatic(null), '');
  assert.equal(normalizeForStatic(undefined), '');
});

// ── normEcho ─────────────────────────────────────────────────────────

test('normEcho：剥离原样回显的值', () => {
  assert.equal(normEcho("Invalid id: 1' -- end", "1'"), 'Invalid id:  -- end');
});

test('normEcho：剥离 URL 编码形式', () => {
  // 如实记录一个既有事实（不是美化）：encodeURIComponent **不编码单引号**
  // （单引号是 URI 合法字符），故 `encodeURIComponent("1'")` === `"1'"`，
  // 该 variant 对含单引号的值是冗余的 —— 单引号回显靠 `raw` 那条剥离。
  assert.equal(encodeURIComponent("1'"), "1'", '前提：encodeURIComponent 不动单引号');
  assert.equal(normEcho('bad input 1%27 here', "1'"), 'bad input 1%27 here',
    '%27 不会被剥离（实现未覆盖该形式）—— 钉住现状，勿想当然');
  // 对**空格**这类确实会被编码的字符，URL 变体才真正起作用：
  assert.equal(normEcho('err zz%20qx here', 'zz qx'), 'err  here',
    'encodeURIComponent("zz qx") = "zz%20qx" → 可剥离');
  // 明文形式仍可剥离：
  assert.equal(normEcho("bad input 1' here", "1'"), 'bad input  here');
});

test('normEcho：剥离 HTML 实体形式（&#39; / &#34;）', () => {
  assert.equal(normEcho('err 1&#39; stop', "1'"), 'err  stop');
  assert.equal(normEcho('err 1&#34; stop', '1"'), 'err  stop');
});

test('★保守红线★ normEcho：值短于 2 字符不做剥离（防误剔）', () => {
  // 若剥离单字符（如 '1'），而正文里到处是 1 → 一切响应变得相同 → 假跳过 → 漏检。
  assert.equal(normEcho('id=1 page', '1'), 'id=1 page');
  assert.equal(normEcho("id=' page", "'"), "id=' page");
  assert.equal(normEcho('abc', ''), 'abc');
});

test('normEcho：body 为空 → 原样返回（不抛错）', () => {
  assert.equal(normEcho('', 'abc'), '');
  assert.equal(normEcho(null, 'abc'), '');
});

test('normEcho：值未出现在正文 → 正文不变', () => {
  assert.equal(normEcho('nothing here', 'zz9qx0'), 'nothing here');
});

// ── prefilterSimilar ─────────────────────────────────────────────────

test('prefilterSimilar：状态码不同 → 不同构', () => {
  assert.equal(prefilterSimilar('abc', 200, 'abc', 500), false);
});

test('prefilterSimilar：正文完全相同 → 同构', () => {
  assert.equal(prefilterSimilar('hello world', 200, 'hello world', 200), true);
});

test('prefilterSimilar：长度差超出容差 → 不同构', () => {
  const a = 'x'.repeat(100);
  const b = 'x'.repeat(100) + 'y'.repeat(50); // 差 50 > max(24, 150*0.12=18)
  assert.equal(prefilterSimilar(a, 200, b, 200), false);
});

test('prefilterSimilar：长度差在容差内但前缀差异大 → 不同构', () => {
  const a = 'a'.repeat(100);
  const b = 'b'.repeat(100); // 长度同，公共前缀 0 < 85%
  assert.equal(prefilterSimilar(a, 200, b, 200), false);
});

test('prefilterSimilar：公共前缀恰好 85% → 同构（含边界）', () => {
  const a = 'x'.repeat(100);
  const b = 'x'.repeat(85) + 'y'.repeat(15);
  assert.equal(prefilterSimilar(a, 200, b, 200), true, '85% 应判同构（>= 而非 >）');
  const c = 'x'.repeat(84) + 'y'.repeat(16);
  assert.equal(prefilterSimilar(a, 200, c, 200), false, '84% 应判不同构');
});

test('prefilterSimilar：两侧都空 → 同构；一侧空 → 视前缀而定', () => {
  assert.equal(prefilterSimilar('', 200, '', 200), true);
  assert.equal(prefilterSimilar('abc', 200, '', 200), false);
});

test('prefilterSimilar：status 为 null 时跳过状态码比对（只看正文）', () => {
  assert.equal(prefilterSimilar('same', null, 'same', 500), true);
  assert.equal(prefilterSimilar('same', 500, 'same', null), true);
});

// ── timeProbeValues ──────────────────────────────────────────────────

test('timeProbeValues：MySQL 族带**双上下文**（字符串 + 数值）', () => {
  const v = timeProbeValues('mysql', 2);
  assert.equal(v.length, 2, '须为 [字符串型, 数值型]');
  assert.ok(v[0].startsWith("' "), '第一项为字符串上下文（带前导单引号）');
  assert.ok(!v[1].startsWith("'"), '第二项为数值上下文（无前导单引号）');
  assert.ok(v.every((x) => x.includes('SLEEP(2)')), '均含 SLEEP(2)');
});

test('timeProbeValues：mariadb / tidb 归入 MySQL 族', () => {
  assert.deepEqual(timeProbeValues('mariadb', 2), timeProbeValues('mysql', 2));
  assert.deepEqual(timeProbeValues('TiDB', 2), timeProbeValues('mysql', 2), '大小写不敏感');
});

test('timeProbeValues：PostgreSQL 用 pg_sleep', () => {
  const v = timeProbeValues('postgresql', 3);
  assert.equal(v.length, 2);
  assert.ok(v.every((x) => x.includes('pg_sleep(3) IS NULL')));
});

test('timeProbeValues：SQL Server 用 WAITFOR DELAY（堆叠，两条都带引号）', () => {
  const v = timeProbeValues('sql server', 2);
  assert.equal(v.length, 2);
  assert.ok(v.every((x) => x.includes("WAITFOR DELAY '0:0:2'")));
  assert.ok(v[0].startsWith("'; "), '堆叠断句以 ; 开头');
});

test('timeProbeValues：Oracle / DM8 用 DBMS_PIPE', () => {
  for (const db of ['oracle', 'dm8']) {
    const v = timeProbeValues(db, 2);
    assert.equal(v.length, 2, `${db} 应双上下文`);
    assert.ok(v.every((x) => x.includes('DBMS_PIPE.RECEIVE_MESSAGE')));
  }
});

test('timeProbeValues：SQLite 返回空数组（无服务器端 sleep）', () => {
  assert.deepEqual(timeProbeValues('sqlite', 2), []);
});

test('timeProbeValues：未知库 → MySQL 双上下文 + PG 单条 = 3 条', () => {
  const v = timeProbeValues(null, 2);
  assert.equal(v.length, 3, '未知库须覆盖 MySQL 两上下文 + PG 字符串上下文');
  assert.ok(v[0].includes('SLEEP'), '项1: MySQL 字符串');
  assert.ok(v[1].includes('SLEEP'), '项2: MySQL 数值');
  assert.ok(v[2].includes('pg_sleep'), '项3: PG 字符串');
  // 有意不给 PG 数值变体（见源码注释）：多一条探针会让多参数目标更容易撞上
  // 「预算不足 → 放弃预筛」这条线，把 MySQL 目标的剪枝收益一起赔进去。
  assert.ok(!v.some((x) => !x.startsWith("'") && x.includes('pg_sleep')), '不得有 PG 数值变体');
});

test('timeProbeValues：sleepSec 缺省/非法 → 回落到 2', () => {
  assert.ok(timeProbeValues('mysql', 0).every((x) => x.includes('SLEEP(2)')), '0 视为缺省');
  assert.ok(timeProbeValues('mysql', undefined).every((x) => x.includes('SLEEP(2)')));
  assert.ok(timeProbeValues('mysql', 'abd').every((x) => x.includes('SLEEP(2)')));
  assert.ok(timeProbeValues('mysql', 5).every((x) => x.includes('SLEEP(5)')), '合法值须生效');
});
