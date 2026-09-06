import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  HIGH_FREQ_DBMS, WRAP, INLINE_CONCAT, resolveDbms,
  escCols,
} from '../src/engine/DialectSqlBuilder.js';
import { DBMS_LIST, SUPPORTED, TIME_VECTORS, ERROR_SIG_BY_DBMS, dbmsFromError } from '../src/engine/payloads/index.js';

// ─── 辅助：读取 extractionMaps.js 内部常量（非 export，通过 eval 文件源码提取）───
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
const __dirname = dirname(fileURLToPath(import.meta.url));
const extractorSrc = readFileSync(join(__dirname, '../src/engine/extractionMaps.js'), 'utf-8');

// 从源码中提取常量定义（正则匹配）
function extractConstMap(src, constName) {
  // 匹配 `const NAME = { ... };` 块，提取 key 列表
  const re = new RegExp(`const ${constName}\\s*=\\s*\\{([\\s\\S]*?)\\n\\};`);
  const m = src.match(re);
  if (!m) return [];
  const body = m[1];
  const keys = [];
  for (const line of body.split('\n')) {
    const km = line.match(/^\s*(?:'([^']+)'|"([^"]+)"|(\w+))\s*:/);
    if (km) keys.push(km[1] || km[2] || km[3]);
    // 也匹配 // 注释行中的库名
    const cmt = line.match(/\/\/\s*(\w[\w\s]*?)[:：]/);
    if (cmt && !keys.includes(cmt[1].trim())) {
      // 跳过，注释不算 key
    }
  }
  return keys;
}

const TIME_COND_KEYS = extractConstMap(extractorSrc, 'TIME_COND');
const LEN_FN_KEYS = extractConstMap(extractorSrc, 'LEN_FN');
const SUB_FN_KEYS = extractConstMap(extractorSrc, 'SUB_FN');
const ASCII_FN_KEYS = extractConstMap(extractorSrc, 'ASCII_FN');

// ─── 1. HIGH_FREQ_DBMS 覆盖全部 18 库 ───
describe('[C-16] DBMS 覆盖率补全', () => {
  test('HIGH_FREQ_DBMS 覆盖全部 18 库', () => {
    assert.equal(HIGH_FREQ_DBMS.length, 18, `期望 18 库，实际 ${HIGH_FREQ_DBMS.length}`);
    for (const dbms of DBMS_LIST) {
      assert.ok(HIGH_FREQ_DBMS.includes(dbms), `HIGH_FREQ_DBMS 缺少 ${dbms}`);
    }
  });

  test('TIME_VECTORS 覆盖所有 time:true 的库', () => {
    const timeDbmsInSupported = Object.entries(SUPPORTED)
      .filter(([_, caps]) => caps.time === true)
      .map(([dbms]) => dbms);
    const timeDbmsInVectors = TIME_VECTORS.map(v => v.dbms);
    // MariaDB/TiDB/DM8 经 resolveDbms 归一化到 MySQL/Oracle，TIME_VECTORS 用 MySQL/Oracle 条目覆盖
    for (const dbms of timeDbmsInSupported) {
      const resolved = resolveDbms(dbms) || dbms;
      assert.ok(
        timeDbmsInVectors.includes(dbms) || timeDbmsInVectors.includes(resolved),
        `TIME_VECTORS 缺少 ${dbms}（resolved=${resolved}）`
      );
    }
  });

  test('TIME_COND 覆盖所有 time:true 且有标量延迟原语的库', () => {
    // ClickHouse 标了 time:true 且有 sleep() 函数，应存在 TIME_COND 条目
    assert.ok(TIME_COND_KEYS.includes('ClickHouse'), 'TIME_COND 缺少 ClickHouse');
    // [P1] H2/MonetDB 新增标量延时原语 → TIME_COND 应有条目
    assert.ok(TIME_COND_KEYS.includes('H2'), 'TIME_COND 缺少 H2');
    assert.ok(TIME_COND_KEYS.includes('MonetDB'), 'TIME_COND 缺少 MonetDB');
    // SQL Server/Sybase 的 WAITFOR DELAY 是语句级，TIME_COND 返回 null 是正确降级
    // 但 Sybase 标了 time:true，其盲注走 PAYLOADS.time 堆叠模板，不走 TIME_COND
  });

  test('ERROR_SIG_BY_DBMS 包含 TiDB 和 DM8', () => {
    const dbmsList = ERROR_SIG_BY_DBMS.map(e => e.dbms);
    assert.ok(dbmsList.includes('TiDB'), 'ERROR_SIG_BY_DBMS 缺少 TiDB');
    assert.ok(dbmsList.includes('DM8'), 'ERROR_SIG_BY_DBMS 缺少 DM8');
  });

  test('WRAP 覆盖全部 18 库', () => {
    for (const dbms of DBMS_LIST) {
      assert.ok(WRAP[dbms], `WRAP 缺少 ${dbms}`);
    }
  });

  test('INLINE_CONCAT 覆盖全部 18 库', () => {
    for (const dbms of DBMS_LIST) {
      assert.ok(INLINE_CONCAT[dbms] !== undefined, `INLINE_CONCAT 缺少 ${dbms}`);
    }
  });

  test('escCols 不再有大小写 bug（MariaDB 用大写 M）', () => {
    // MariaDB 应该走反引号分支，而不是 default 裸列名
    const result = escCols(['test_col'], 'MariaDB');
    assert.equal(result, '`test_col`', `MariaDB 应走反引号分支，实际返回 ${result}`);
    // 小写 'mariadb' 不再作为 case（旧 bug 已修复）
    const resultLower = escCols(['test_col'], 'mariadb');
    // 'mariadb' 不匹配任何 case，走 default 返回裸列名（预期行为）
    assert.equal(resultLower, 'test_col', `小写 'mariadb' 应走 default（非有效 DBMS 名）`);
  });

  test('LEN_FN 覆盖全部 18 库（含 resolveDbms 归一化）', () => {
    for (const dbms of DBMS_LIST) {
      const resolved = resolveDbms(dbms) || dbms;
      assert.ok(LEN_FN_KEYS.includes(resolved), `LEN_FN 缺少 ${dbms}（resolved=${resolved}）`);
    }
  });

  test('SUB_FN 覆盖全部 18 库（含 resolveDbms 归一化）', () => {
    for (const dbms of DBMS_LIST) {
      const resolved = resolveDbms(dbms) || dbms;
      assert.ok(SUB_FN_KEYS.includes(resolved), `SUB_FN 缺少 ${dbms}（resolved=${resolved}）`);
    }
  });

  test('ASCII_FN 覆盖全部 18 库（含 resolveDbms 归一化）', () => {
    for (const dbms of DBMS_LIST) {
      const resolved = resolveDbms(dbms) || dbms;
      assert.ok(ASCII_FN_KEYS.includes(resolved), `ASCII_FN 缺少 ${dbms}（resolved=${resolved}）`);
    }
  });

  test('TIME_DBMS_ORDER 包含 ClickHouse 和 Sybase', async () => {
    // 读取 TimeBlindDetector.js 源码验证
    const src = readFileSync(join(__dirname, '../src/engine/detectors/TimeBlindDetector.js'), 'utf-8');
    assert.ok(/ClickHouse/.test(src), 'TimeBlindDetector 应包含 ClickHouse');
    assert.ok(/Sybase/.test(src), 'TimeBlindDetector 应包含 Sybase');
    // [P1] H2/MonetDB 新增到候选序
    assert.ok(/'H2'/.test(src), 'TimeBlindDetector 应包含 H2');
    assert.ok(/'MonetDB'/.test(src), 'TimeBlindDetector 应包含 MonetDB');
  });

  test('ColumnTypeEnumerator typeSql 覆盖 12+ 库', async () => {
    const src = readFileSync(join(__dirname, '../src/engine/ColumnTypeEnumerator.js'), 'utf-8');
    // 原有 5 库 + 新增 7 库 = 12 库（Sybase/Access/Derby 降级）
    const expectedDbms = ['MySQL', 'PostgreSQL', 'SQLite', 'SQL Server', 'Oracle',
      'ClickHouse', 'DB2', 'H2', 'HSQLDB', 'MonetDB', 'Informix', 'Firebird'];
    for (const dbms of expectedDbms) {
      assert.ok(src.includes(dbms), `ColumnTypeEnumerator 缺少 ${dbms} 的 typeSql 条目`);
    }
  });

  test('TIME_VECTORS 新增 ClickHouse/Sybase/H2/MonetDB 条目', () => {
    const dbmsList = TIME_VECTORS.map(v => v.dbms);
    assert.ok(dbmsList.includes('ClickHouse'), 'TIME_VECTORS 缺少 ClickHouse');
    assert.ok(dbmsList.includes('Sybase'), 'TIME_VECTORS 缺少 Sybase');
    // [P1] H2/MonetDB 新增
    assert.ok(dbmsList.includes('H2'), 'TIME_VECTORS 缺少 H2');
    assert.ok(dbmsList.includes('MonetDB'), 'TIME_VECTORS 缺少 MonetDB');
  });

  test('ERROR_SIG_BY_DBMS TiDB 签名匹配 TiDB 报错文本', () => {
    const tidbErr = dbmsFromError('TiDB: syntax error near...');
    assert.equal(tidbErr, 'TiDB');
  });

  test('ERROR_SIG_BY_DBMS DM8 签名匹配达梦报错文本', () => {
    const dm8Err = dbmsFromError('达梦数据库 SQL 错误');
    assert.equal(dm8Err, 'DM8');
  });
});
