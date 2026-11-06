// [D256] 方言声明化判据（guard 类）
//
// 钉住三件事：
//   ① 方言知识确实搬出了代码（源码里没有 switch case / 字面量方言字典）；
//   ② 数据与既有行为逐条等价（字面量期望，不从被测数据派生，防自证）；
//   ③ 新增一种方言只改数据即可获得查表型能力，不改 DialectSqlBuilder.js。
//
// 边界（如实）：WRAP / WRAP_NOCAST / INLINE_CONCAT / HIGH_FREQ_DBMS / 别名正则 /
// hashComment 正则是**模块加载期**从数据派生的常量，运行时往内存对象加条目不会
// 让它们即时变化 —— 改磁盘上的 dialects.json 后重启进程即生效，仍属「不改代码」。
// 这些常量的等价性由 dialectSqlBuilder.test.js 等 12 份既有方言单测覆盖。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import dialectData from '../src/engine/payloads/dialects.json' with { type: 'json' };
import {
  resolveDbms, dialectToDbms, fromDummy, escCols, escColsNN, tableRef, quoteCol,
  nullSafeQuoteCol, commentSuffix, WRAP, WRAP_NOCAST, HIGH_FREQ_DBMS, INLINE_CONCAT,
  renderDialectTemplate,
} from '../src/engine/DialectSqlBuilder.js';

const SRC = fileURLToPath(new URL('../src/engine/DialectSqlBuilder.js', import.meta.url));

test('[D256] 方言知识已搬出代码：无 switch case、无字面量方言语录', () => {
  const src = readFileSync(SRC, 'utf8');
  const code = src.split('\n')
    .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
    .join('\n');
  assert.equal((code.match(/\bcase\s+'/g) || []).length, 0, '不应残留 switch case 硬编码方言分支');
  assert.ok(!/['"](MySQL|Oracle|PostgreSQL|SQLite|SQL Server|HSQLDB|Derby)['"]\s*:/.test(code),
    '不应残留字面量方言字典键');
  assert.ok(code.includes("from './payloads/dialects.json'"), '必须从 JSON 真源加载');
});

test('[D256] 数据完整性：18 种方言、必需字段齐全、高频顺序与方言集合一致', () => {
  const names = Object.keys(dialectData.dialects);
  assert.equal(names.length, 18);
  for (const n of names) {
    const d = dialectData.dialects[n];
    assert.ok(d && typeof d === 'object', `${n} 必须是对象`);
    for (const k of ['fromDummy', 'identifier', 'quoteCol', 'tableRef', 'nnExpr', 'nullSafeQuoteCol', 'inlineConcat', 'wrap']) {
      assert.notEqual(d[k], undefined, `${n} 缺 ${k}`);
    }
  }
  assert.deepEqual([...HIGH_FREQ_DBMS].sort(), [...names].sort(), '高频顺序必须覆盖全部方言且不重不漏');
  assert.equal(HIGH_FREQ_DBMS[0], 'MySQL', '高频库顺序不得漂移（命中即停策略依赖）');
});

test('[D256] 等价性：字面量期望钉住迁移前后的真实输出', () => {
  // 归一化
  assert.equal(resolveDbms('MariaDB'), 'MySQL');
  assert.equal(resolveDbms('DM8'), 'Oracle');
  assert.equal(resolveDbms('CockroachDB'), 'PostgreSQL');
  assert.equal(resolveDbms('SQLite'), 'SQLite');
  assert.equal(resolveDbms(null), null);
  assert.equal(dialectToDbms('mssql'), 'SQL Server');
  assert.equal(dialectToDbms('nope'), null);
  // 伪表
  assert.equal(fromDummy('Oracle'), ' FROM dual');
  assert.equal(fromDummy('DB2'), ' FROM SYSIBM.SYSDUMMY1');
  assert.equal(fromDummy('HSQLDB'), ' FROM (VALUES(0)) t');
  assert.equal(fromDummy('MySQL'), '');
  // 标识符与表引用
  assert.equal(escCols(['id', 'name'], 'MySQL'), '`id`,`name`');
  assert.equal(escCols(['id'], 'SQL Server'), '[id]');
  assert.equal(escCols(['id'], 'PostgreSQL'), '"id"');
  assert.equal(escCols(['id'], 'Informix'), 'id');
  assert.equal(escCols([], 'MySQL'), '*');
  assert.equal(tableRef('MySQL', 'mydb', 'users'), '`mydb`.`users`');
  assert.equal(tableRef('SQL Server', 'd', 'users'), '[users]');
  assert.equal(tableRef('PostgreSQL', 'd', 'us"ers'), '"us""ers"');
  assert.equal(quoteCol('c', 'SQLite'), '`c`');
  assert.equal(quoteCol('c', 'SQL Server'), '"c"');
  // NULL 安全表达式
  assert.equal(escColsNN(['c'], 'Derby'), 'COALESCE(CAST("c" AS VARCHAR(4000)),\'\')');
  assert.equal(escColsNN(['c'], 'ClickHouse'), 'ifNull(toString(`c`),\'\')');
  assert.equal(nullSafeQuoteCol('c', 'Oracle'), 'NVL(CAST("c" AS VARCHAR2(4000)),\'\')');
  // 包裹模板 / 串接符 / 尾注
  assert.equal(WRAP.PostgreSQL('1'), "('__S__' || CAST((1) AS TEXT) || '__E__')");
  assert.equal(WRAP.MySQL('1'), "CONVERT(CONCAT('__S__',CAST((1) AS CHAR),'__E__') USING utf8mb4) COLLATE utf8mb4_bin");
  assert.equal(WRAP_NOCAST.Access('1'), "('__S__' & (1) & '__E__')");
  assert.equal(WRAP_NOCAST['SQL Server'], undefined, "SQL Server 的 '+' 不支持隐式转文本，不得有 noCast 变体");
  assert.equal(INLINE_CONCAT.Access, '&');
  assert.equal(INLINE_CONCAT['SQL Server'], '+');
  assert.equal(commentSuffix('MySQL', { tamperEnabled: true }), '#');
  assert.equal(commentSuffix('PostgreSQL', { tamperEnabled: true }), '-- -');
});

test('[D256] 新增方言只改数据：查表型能力即时生效，无需改代码', () => {
  const name = 'GuardDB';
  dialectData.dialects[name] = {
    fromDummy: ' FROM GUARD_DUAL',
    identifier: { open: '<', close: '>' },
    quoteCol: { open: '<', close: '>' },
    tableRef: '<${t}>',
    nnExpr: 'COALESCE(${id},0)',
    nullSafeQuoteCol: 'COALESCE(${id},0)',
    inlineConcat: '@',
  };
  try {
    assert.equal(fromDummy(name), ' FROM GUARD_DUAL');
    assert.equal(escCols(['a'], name), '<a>');
    assert.equal(quoteCol('c', name), '<c>');
    assert.equal(tableRef(name, 'd', 't'), '<t>');
    assert.equal(escColsNN(['c'], name), 'COALESCE(<c>,0)');
    assert.equal(nullSafeQuoteCol('c', name), 'COALESCE(<c>,0)');
    assert.equal(resolveDbms(name), name, '未声明别名时原样保留');
  } finally {
    delete dialectData.dialects[name];
  }
});

test('[D256] 未知方言安全回落 + 模板占位符未命中不静默吞掉', () => {
  assert.equal(fromDummy('TotallyUnknown'), '');
  assert.equal(escCols(['x'], 'TotallyUnknown'), 'x');
  assert.equal(quoteCol('x', 'TotallyUnknown'), '"x"');
  assert.equal(renderDialectTemplate('A${known}B${missing}C', { known: 'K' }), 'AKB${missing}C');
});
