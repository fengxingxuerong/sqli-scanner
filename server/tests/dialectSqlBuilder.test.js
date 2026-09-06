// DialectSqlBuilder 专项测试 —— 验证方言 SQL 知识收敛后的正确性与向后兼容性
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  escSql, escBacktick, escDq, escBracket,
  resolveDbms, fromDummy, escCols, tableRef, quoteCol,
  WRAP, HIGH_FREQ_DBMS, INLINE_CONCAT,
} from '../src/engine/DialectSqlBuilder.js';

// ── 转义函数 ──────────────────────────────────────────────────────────────
describe('DialectSqlBuilder: 转义函数', () => {
  it('escSql: 单引号 → 双单引号', () => {
    assert.equal(escSql("hello'world"), "hello''world");
    assert.equal(escSql('normal'), 'normal');
    assert.equal(escSql("a'b'c"), "a''b''c");
  });

  it('escBacktick: 反引号 → 双反引号', () => {
    assert.equal(escBacktick('`tbl`'), '``tbl``');
    assert.equal(escBacktick('safe'), 'safe');
  });

  it('escDq: 双引号 → 双双引号', () => {
    assert.equal(escDq('"col"'), '""col""');
    assert.equal(escDq('plain'), 'plain');
  });

  it('escBracket: ] → ]]', () => {
    assert.equal(escBracket('col]'), 'col]]');
    assert.equal(escBracket('col'), 'col');
  });

  it('非字符串入参被 String() 规范化', () => {
    assert.equal(escSql(42), '42');
    assert.equal(escBacktick(null), 'null');
  });
});

// ── resolveDbms ───────────────────────────────────────────────────────────
describe('DialectSqlBuilder: resolveDbms', () => {
  it('MariaDB → MySQL（协议互通）', () => {
    assert.equal(resolveDbms('MariaDB'), 'MySQL');
  });

  it('TiDB → MySQL（协议互通）', () => {
    assert.equal(resolveDbms('TiDB'), 'MySQL');
  });

  it('DM8 → Oracle（兼容）', () => {
    assert.equal(resolveDbms('DM8'), 'Oracle');
  });

  it('Dameng → Oracle', () => {
    assert.equal(resolveDbms('Dameng'), 'Oracle');
  });

  it('原生 DBMS 名保留不变', () => {
    assert.equal(resolveDbms('MySQL'), 'MySQL');
    assert.equal(resolveDbms('PostgreSQL'), 'PostgreSQL');
    assert.equal(resolveDbms('SQLite'), 'SQLite');
    assert.equal(resolveDbms('SQL Server'), 'SQL Server');
    assert.equal(resolveDbms('Oracle'), 'Oracle');
    assert.equal(resolveDbms('ClickHouse'), 'ClickHouse');
  });

  it('null → null', () => {
    assert.equal(resolveDbms(null), null);
    assert.equal(resolveDbms(undefined), null);
    assert.equal(resolveDbms(''), null); // 空串是 falsy，当作 null
  });
});

// ── fromDummy ────────────────────────────────────────────────────────────
describe('DialectSqlBuilder: fromDummy', () => {
  it('Oracle/DM8 → FROM dual', () => {
    assert.equal(fromDummy('Oracle'), ' FROM dual');
    assert.equal(fromDummy('DM8'), ' FROM dual');
  });

  it('DB2/Derby → SYSIBM.SYSDUMMY1', () => {
    assert.equal(fromDummy('DB2'), ' FROM SYSIBM.SYSDUMMY1');
    assert.equal(fromDummy('Derby'), ' FROM SYSIBM.SYSDUMMY1');
  });

  it('MySQL/PG/SQLite/MSSQL/ClickHouse → 空串', () => {
    assert.equal(fromDummy('MySQL'), '');
    assert.equal(fromDummy('PostgreSQL'), '');
    assert.equal(fromDummy('SQLite'), '');
    assert.equal(fromDummy('SQL Server'), '');
    assert.equal(fromDummy('ClickHouse'), '');
  });

  it('Firebird → RDB$DATABASE', () => {
    assert.equal(fromDummy('Firebird'), ' FROM RDB$DATABASE');
  });

  it('Access → MSysObjects', () => {
    assert.equal(fromDummy('Access'), ' FROM MSysObjects');
  });
});

// ── escCols ───────────────────────────────────────────────────────────────
describe('DialectSqlBuilder: escCols', () => {
  it('MySQL 列名用反引号', () => {
    assert.equal(escCols(['id', 'name'], 'MySQL'), '`id`,`name`');
  });

  it('PostgreSQL 列名用双引号', () => {
    assert.equal(escCols(['id', 'name'], 'PostgreSQL'), '"id","name"');
  });

  it('SQL Server 列名用方括号', () => {
    assert.equal(escCols(['id', 'name'], 'SQL Server'), '[id],[name]');
  });

  it('空数组 → *', () => {
    assert.equal(escCols([], 'MySQL'), '*');
    assert.equal(escCols(null, 'MySQL'), '*');
  });

  it('恶意列名（含引号/反引号/方括号）被剥离', () => {
    const safe = escCols(['ev`il', 'nor"mal'], 'MySQL');
    assert.ok(!safe.includes('`ev`il`')); // 不允许未转义的原始反引号穿越
  });
});

// ── tableRef ───────────────────────────────────────────────────────────────
describe('DialectSqlBuilder: tableRef', () => {
  it('MySQL: `db`.`table` 带库前缀', () => {
    const r = tableRef('MySQL', 'mydb', 'users');
    assert.equal(r, '`mydb`.`users`');
  });

  it('SQL Server: [table] 无库前缀', () => {
    const r = tableRef('SQL Server', 'mydb', 'users');
    assert.equal(r, '[users]');
  });

  it('PostgreSQL: "table" 无库前缀', () => {
    const r = tableRef('PostgreSQL', 'mydb', 'users');
    assert.equal(r, '"users"');
  });

  it('MySQL 恶意表名被转义', () => {
    const r = tableRef('MySQL', 'safe', 'ev`il');
    assert.ok(r.includes('ev``il')); // ` → ``
  });
});

// ── quoteCol ──────────────────────────────────────────────────────────────
describe('DialectSqlBuilder: quoteCol', () => {
  it('MySQL → 反引号', () => {
    assert.equal(quoteCol('col', 'MySQL'), '`col`');
    assert.equal(quoteCol('col', 'MariaDB'), '`col`');
    assert.equal(quoteCol('col', 'SQLite'), '`col`');
  });

  it('PostgreSQL/SQL Server/Oracle → 双引号', () => {
    assert.equal(quoteCol('col', 'PostgreSQL'), '"col"');
    assert.equal(quoteCol('col', 'SQL Server'), '"col"');
    assert.equal(quoteCol('col', 'Oracle'), '"col"');
  });
});

// ── WRAP ──────────────────────────────────────────────────────────────────
describe('DialectSqlBuilder: WRAP', () => {
  it('MySQL: CONCAT + CAST AS CHAR', () => {
    const r = WRAP.MySQL('1+1');
    assert.ok(r.includes('CONCAT'));
    assert.ok(r.includes("'__S__'"));
    assert.ok(r.includes("'__E__'"));
    assert.ok(r.includes('CAST((1+1) AS CHAR)'));
  });

  it('Oracle: || + TO_CHAR', () => {
    const r = WRAP.Oracle('1+1');
    assert.ok(r.includes('||'));
    assert.ok(r.includes('TO_CHAR'));
  });

  it('SQL Server: + + CAST AS VARCHAR(MAX)', () => {
    const r = WRAP['SQL Server']('1+1');
    assert.ok(r.includes('+'));
    assert.ok(r.includes('VARCHAR(MAX)'));
  });

  it('SQLite: || 无 CAST', () => {
    const r = WRAP.SQLite('1+1');
    assert.ok(r.includes('||'));
    assert.ok(!r.includes('CAST'));
  });

  it('ClickHouse: concat + toString', () => {
    const r = WRAP.ClickHouse('1+1');
    assert.ok(r.includes('concat'));
    assert.ok(r.includes('toString'));
  });

  it('TiDB: 与 MySQL 相同（CONCAT + CAST）', () => {
    assert.equal(WRAP.TiDB('x'), WRAP.MySQL('x'));
  });

  it('DM8: 与 Oracle 相同（|| + TO_CHAR）', () => {
    assert.equal(WRAP.DM8('x'), WRAP.Oracle('x'));
  });

  it('所有 18 库都有 WRAP 定义', () => {
    const all = ['MySQL', 'PostgreSQL', 'SQLite', 'SQL Server', 'Oracle',
      'TiDB', 'DM8', 'ClickHouse', 'DB2', 'Firebird', 'Informix', 'H2',
      'Sybase', 'Access', 'HSQLDB', 'Derby', 'MonetDB'];
    for (const db of all) {
      assert.ok(typeof WRAP[db] === 'function', `${db} 缺少 WRAP`);
    }
  });
});

// ── HIGH_FREQ_DBMS ─────────────────────────────────────────────────────────
describe('DialectSqlBuilder: HIGH_FREQ_DBMS', () => {
  it('包含 10 库，MySQL 排首位', () => {
    assert.ok(Array.isArray(HIGH_FREQ_DBMS));
    assert.ok(HIGH_FREQ_DBMS.length >= 10);
    assert.equal(HIGH_FREQ_DBMS[0], 'MySQL');
  });

  it('包含 Sybase', () => {
    assert.ok(HIGH_FREQ_DBMS.includes('Sybase'));
  });
});

// ── INLINE_CONCAT ──────────────────────────────────────────────────────────
describe('DialectSqlBuilder: INLINE_CONCAT', () => {
  it('Oracle/PG/MySQL/MariaDB → ||', () => {
    assert.equal(INLINE_CONCAT.Oracle, '||');
    assert.equal(INLINE_CONCAT.PostgreSQL, '||');
    assert.equal(INLINE_CONCAT.MySQL, '||');
    assert.equal(INLINE_CONCAT.MariaDB, '||');
  });

  it('SQL Server → +', () => {
    assert.equal(INLINE_CONCAT['SQL Server'], '+');
  });
});

// ── 向后兼容：re-export 路径 ──────────────────────────────────────────────
describe('DialectSqlBuilder: 向后兼容 re-export', () => {
  it('Extractor.js re-export WRAP 可从原路径导入', async () => {
    const mod = await import('../src/engine/Extractor.js');
    assert.ok(typeof mod.WRAP === 'object');
    assert.ok(typeof mod.WRAP.MySQL === 'function');
  });

  it('DBFingerprinter.js re-export WRAP/HIGH_FREQ_DBMS/fromDummy 可从原路径导入', async () => {
    const mod = await import('../src/engine/DBFingerprinter.js');
    assert.ok(typeof mod.WRAP === 'object');
    assert.ok(Array.isArray(mod.HIGH_FREQ_DBMS));
    assert.equal(typeof mod.fromDummy, 'function');
  });
});
