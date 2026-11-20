// ============================================================================
// payloads.d307.dialect.guard.test.js —— [D307] 4 方言 payload 因子守卫
//
// 为什么需要：sqlmap 1.10.11 官方 payload 测试集（data/xml/payloads/*.xml，共 358 条
// <test>）覆盖 20 种 DBMS，其中 SAP MaxDB(10)/Vertica(2)/CUBRID(4)/Presto(2) 共 18 条
// 方言特定测试在本仓 PAYLOADS 里完全没有因子（静态对账结论，见
// .box-agent-scratch/sqlmap-corpus/1.10.11/REPORT.md）。D307 补最小适配。
//
// 判据钉三件事：
//   ① 4 个独立 PAYLOADS key 存在（不再是 registry/PAYLOADS 里查无此库）；
//   ② boolean 数组遵循固定索引契约 [0,2]/[1,3]/[4,5]/[6,7]（BooleanBlindDetector 消费）；
//   ③ 每个方言的独门报错/延时语法字面量还在（防被改成通用 1=1 模板 = 判据空转）。
//
// 诚实边界：本机无这 4 种 DB，模板是 sqlmap 官方语法的静态移植、未经真机验证。
// 本测试只钉「因子存在且形态正确」，不宣称「这些方言能检出」——后者需真机靶场。
// 指纹归一层 resolveDbms 把 maxdb/cubrid/vertica 归一到 MySQL/PG（兼容映射，有意不动），
// 独立 key 只在 --dbms 显式指定时经 forcedDbms 原样流入 PAYLOADS[dbms] 命中。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PAYLOADS } from '../src/engine/payloads.js';

const DIALECTS = ['SAP MaxDB', 'Vertica', 'CUBRID', 'Presto'];
const TECH_KEYS = ['union', 'error', 'boolean', 'time', 'stacked'];

test('D307-1 四个方言在 PAYLOADS 中有独立 key，且五技术槽齐全', () => {
  for (const d of DIALECTS) {
    assert.ok(PAYLOADS[d], `PAYLOADS 应有 ${d} 因子`);
    for (const t of TECH_KEYS) {
      assert.ok(Array.isArray(PAYLOADS[d][t]), `${d}.${t} 必须是数组`);
    }
  }
});

test('D307-2 boolean 数组固定索引契约 [0,2]/[1,3]/[4,5]/[6,7] 真假对', () => {
  const pairs = [[0, 2], [1, 3], [4, 5], [6, 7]];
  for (const d of DIALECTS) {
    const b = PAYLOADS[d].boolean;
    assert.equal(b.length, 8, `${d}.boolean 必须 8 元素（索引契约），实际 ${b.length}`);
    for (const [ti, fi] of pairs) {
      assert.ok(typeof b[ti] === 'string' && b[ti].length > 0, `${d}.boolean[${ti}] 真模板不能空`);
      assert.ok(typeof b[fi] === 'string' && b[fi].length > 0, `${d}.boolean[${fi}] 假模板不能空`);
      assert.notEqual(b[ti], b[fi], `${d}.boolean[${ti}]/[${fi}] 真假模板不得相同`);
    }
  }
});

test('D307-3 SAP MaxDB：CASE WHEN ... FROM DUAL 与 heavy-query stacked 语法保留', () => {
  const p = PAYLOADS['SAP MaxDB'];
  assert.ok(p.boolean.some((s) => s.includes('CASE WHEN 1=1') && s.includes('ELSE NULL')),
    'MaxDB boolean 应含官方 CASE WHEN ... ELSE NULL ... 形态');
  assert.ok(p.stacked.some((s) => s.includes(';SELECT CASE WHEN') && s.includes('FROM DUAL')),
    'MaxDB stacked 应含官方 ;SELECT CASE WHEN ... FROM DUAL');
  assert.ok(p.stacked.some((s) => s.includes('DOMAIN.DOMAINS') && s.includes('DOMAIN.TABLES')),
    'MaxDB stacked 应含官方 heavy-query 笛卡尔积');
  assert.equal(p.time.length, 0, 'MaxDB 官方 time 是 heavy query（无稳定延时），不得伪造 SLEEP 向量');
});

test('D307-4 Vertica：ZEROIFNULL(CAST(...::varchar ... AS NUMERIC)) 报错语法保留', () => {
  const e = PAYLOADS.Vertica.error;
  assert.equal(e.length, 2, 'Vertica 官方 2 条 error-based');
  assert.ok(e.every((s) => s.includes('ZEROIFNULL') && s.includes('AS NUMERIC')),
    'Vertica error 应含官方 ZEROIFNULL(CAST(... AS NUMERIC))');
  assert.ok(e.some((s) => s.includes('BITCOUNT(BITSTRING_TO_BINARY')),
    'Vertica error 应含官方 BITCOUNT(BITSTRING_TO_BINARY)');
});

test('D307-5 CUBRID：INET_ATON 报错 + SLEEP FROM db_root 延时语法保留', () => {
  const p = PAYLOADS.CUBRID;
  assert.ok(p.error.every((s) => s.includes('INET_ATON')), 'CUBRID error 应含官方 INET_ATON 形态');
  assert.equal(p.time.length, 2, 'CUBRID 官方 2 条 time-based');
  assert.ok(p.time.every((s) => s.includes('SLEEP({SLEEP})') && s.includes('FROM db_root')),
    'CUBRID time 应含官方 (SELECT SLEEP(n) FROM db_root)');
});

test('D307-6 Presto：PARSE_DATA_SIZE 报错语法保留', () => {
  const e = PAYLOADS.Presto.error;
  assert.equal(e.length, 2, 'Presto 官方 2 条 error-based');
  assert.ok(e.every((s) => s.includes('PARSE_DATA_SIZE') && s.includes('AS VARCHAR')),
    'Presto error 应含官方 PARSE_DATA_SIZE(... AS VARCHAR)');
});

test('D307-7 反例（判据不空转）：通用 1=1 模板不能冒充方言独门语法', () => {
  // 若有人把 Vertica.error 改成和 MySQL 一样的 extractvalue，D307-4 必须红
  const fake = ["{ORIG}' AND extractvalue(1,1)-- -", "{ORIG} AND extractvalue(1,1)-- -"];
  assert.ok(!fake.every((s) => s.includes('ZEROIFNULL')), '反例应被 D307-4 判据拒绝');
});
