// [P2 审计修复 2026-09-20] Oracle / DB2 拖库 data 模板 CONCAT 参数超限回归
//
// 缺陷背景（真实、已由官方文档证实）：
//   Oracle 的 CONCAT **恰好接受 2 个参数**（3 个参数 → ORA-00909 invalid number of arguments）
//   DB2    的 CONCAT **只接受 2 个参数**（与 MySQL 的变参 CONCAT 不同）
//   而旧模板写成 CONCAT(CHR(31), <escCols 逗号连接的多列>)，列数 ≥2 时参数即超限：
//     cols=["a","b"]   -> CONCAT(CHR(31), "a","b")        // 3 参数 → 恒报错
//     cols=["a","b","c"] -> CONCAT(CHR(31), "a","b","c")  // 4 参数 → 恒报错
//   即：Oracle/DB2 拖库对**多列表必然失败**（单列表侥幸可用），属静默功能性缺陷。
//
// 修复：改用各方言的 || 运算符逐列拼接（无参数上限），并经 escColsNNJoin 逐列包
//   Oracle NVL(CAST(... AS VARCHAR2(4000)),'') / DB2 COALESCE(CAST(... AS VARCHAR(4000)),'')
// 做 NULL 安全（NULL 列若不兜底，该行串长少一段，解析器按 0x1F 切列会整体错位）。
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { SYS_QUERIES, SCHEMA_QUERY } from '../src/engine/extractionMaps.js';

// 统计 SQL 中每个 CONCAT(...) 调用点的「顶层参数个数」
function concatArities(sql) {
  const out = [];
  const re = /CONCAT\s*\(/gi;
  let m;
  while ((m = re.exec(sql))) {
    let depth = 0;
    let i = m.index + m[0].length - 1;
    for (; i < sql.length; i++) {
      const ch = sql[i];
      if (ch === '(') depth++;
      else if (ch === ')') { depth--; if (depth === 0) break; }
    }
    const inner = sql.slice(m.index + m[0].length, i);
    let d = 0;
    let arity = 1;
    for (const ch of inner) {
      if (ch === '(') d++;
      else if (ch === ')') d--;
      else if (ch === ',' && d === 0) arity++;
    }
    out.push(arity);
  }
  return out;
}

describe('[P2] Oracle/DB2 data 模板：CONCAT 参数不得超限', () => {
  // 3 列是最能暴露超限的用例（≥2 列即触发）
  const COLS = ['a', 'b', 'c'];

  for (const dbms of ['Oracle', 'DM8', 'DB2']) {
    it(`${dbms}: 多列拖库不得生成 CONCAT（2 参数上限的库）`, () => {
      const sql = SYS_QUERIES[dbms].data('d', 't', COLS, 10, 0, null);
      assert.equal(typeof sql, 'string', `${dbms} data 应返回 SQL 字符串`);
      const arities = concatArities(sql);
      const over = arities.filter((n) => n > 2);
      assert.deepEqual(
        over, [],
        `${dbms} 生成了参数超限的 CONCAT（Oracle ORA-00909 / DB2 同类报错）: ${sql}`,
      );
    });
  }

  it('Oracle: 多列用 || 逐列拼接，且每列做 NVL(NULL 安全)', () => {
    const sql = SYS_QUERIES.Oracle.data('d', 't', COLS, 10, 0, null);
    assert.ok(sql.includes('||'), 'Oracle 应使用 || 运算符拼接');
    // 3 列 → 3 个 NVL 兜底
    assert.equal((sql.match(/NVL\(CAST\(/g) || []).length, 3, `每列都应 NVL 兜底: ${sql}`);
    // 列间分隔符 CHR(31) 出现在列之间（3 列 → 至少 3 次：前缀 + 2 个列间）
    assert.ok(sql.includes('CHR(31)'), 'Oracle 列分隔符应为 CHR(31)');
    // 行分隔符 CHR(30)
    assert.ok(sql.includes('CHR(30)'), 'Oracle 行分隔符应为 CHR(30)');
  });

  it('DB2: 多列用 || 逐列拼接，且每列做 COALESCE(NULL 安全)', () => {
    const sql = SYS_QUERIES.DB2.data('d', 't', COLS, 10, 0, null);
    assert.ok(sql.includes('||'), 'DB2 应使用 || 运算符拼接');
    assert.equal((sql.match(/COALESCE\(CAST\(/g) || []).length, 3, `每列都应 COALESCE 兜底: ${sql}`);
    assert.ok(sql.includes('CHAR(31)'), 'DB2 列分隔符应为 CHAR(31)');
    assert.ok(sql.includes('CHAR(30)'), 'DB2 行分隔符应为 CHAR(30)');
    assert.ok(sql.includes('listagg('), 'DB2 聚合应为 listagg');
  });
});

describe('[P2] nnExpr 补 Oracle/DB2 分支（escColsNN 契约）', () => {
  it('escColsNN 对 Oracle 产生 NVL，对 DB2 产生 COALESCE', async () => {
    const { escColsNN, escColsNNJoin } = await import('../src/engine/DialectSqlBuilder.js');
    const o = escColsNN(['x'], 'Oracle');
    assert.ok(o.includes('NVL(CAST("x" AS VARCHAR2(4000)),\'\')'), `Oracle escColsNN 异常: ${o}`);
    const d = escColsNN(['x'], 'DB2');
    assert.ok(d.includes('COALESCE(CAST("x" AS VARCHAR(4000)),\'\')'), `DB2 escColsNN 异常: ${d}`);
    // DM8 归一为 Oracle 方言
    const dm = escColsNN(['x'], 'DM8');
    assert.ok(dm.includes('NVL(CAST('), `DM8 escColsNN 应走 Oracle 分支: ${dm}`);
    // Join 变体：连接符注入后仍保留兜底
    const j = escColsNNJoin(['x', 'y'], 'Oracle', ' || CHR(31) || ');
    assert.equal((j.match(/NVL\(/g) || []).length, 2, `Join 变体应逐列 NVL: ${j}`);
    assert.ok(j.includes('|| CHR(31) ||'), 'Join 变体应保留指定连接符');
  });
});

// ── [P2 审计修复 2026-09-20 第二批] ClickHouse / Firebird 整行丢失 ──────────────
// 危害比 CONCAT 超限更重：不是「报错」也不是「列错位」，而是**行从结果里静默消失**。
//   · ClickHouse：concat() 任一参数 NULL → 整个 concat 返回 NULL；groupArray 默认跳过 NULL
//     → 该行整行不在聚合数组里 → 拖库少行且无任何报错。
//   · Firebird：'a' || NULL = NULL（官方手册明示）→ list() 聚合时该行整行丢失。
describe('[P2] ClickHouse/Firebird：NULL 列不得导致整行丢失', () => {
  const COLS = ['a', 'b', 'c'];

  it('ClickHouse: 每列 ifNull(toString(...)) 兜底，且分隔符保留', () => {
    const sql = SYS_QUERIES.ClickHouse.data('d', 't', COLS, 10, 0, null);
    assert.equal((sql.match(/ifNull\(toString\(/g) || []).length, 3, `每列都应 ifNull 兜底: ${sql}`);
    // 分隔符必须出现在列之间：3 列 → 3 个 CHAR(31)（前缀 1 + 列间 2）
    assert.equal((sql.match(/CHAR\(31\)/g) || []).length, 3, `列分隔符个数异常: ${sql}`);
    assert.ok(sql.includes('CHAR(30)'), '行分隔符应为 CHAR(30)');
    assert.ok(sql.includes('arrayStringConcat(groupArray('), '聚合形态应保持');
  });

  it('Firebird: 每列 COALESCE 兜底，且不再用 replace 反模式', () => {
    const sql = SYS_QUERIES.Firebird.data('d', 't', COLS, 10, 0, null);
    assert.equal((sql.match(/COALESCE\(CAST\(/g) || []).length, 3, `每列都应 COALESCE 兜底: ${sql}`);
    assert.equal((sql.match(/ASCII_CHAR\(31\)/g) || []).length, 3, `列分隔符个数异常: ${sql}`);
    assert.ok(sql.includes('ASCII_CHAR(30)'), '行分隔符应为 ASCII_CHAR(30)');
    assert.ok(sql.includes('list('), 'Firebird 聚合应为 list');
  });

  it('全 15 个有 data 模板的方言均含 NULL 兜底（防未来的新模板漏包）', () => {
    const missing = [];
    for (const db of Object.keys(SYS_QUERIES)) {
      const d = SYS_QUERIES[db]?.data;
      if (typeof d !== 'function') continue; // Informix/Access 的 data=null 为有意降级
      const sql = d('d', 't', COLS, 10, 0, null);
      if (!/IFNULL\(|ISNULL\(|COALESCE\(|NVL\(|ifNull\(/i.test(sql)) missing.push(db);
    }
    assert.deepEqual(missing, [], `以下方言的 data 模板缺 NULL 兜底（NULL 列会丢行/错位）: ${missing.join(', ')}`);
  });
});

// ── [P2 审计修复 2026-09-20 第三批] MySQL SCHEMA_QUERY 的 SEPARATOR 语法错 ──────
// 缺陷：`... SEPARATOR CHAR(30)` —— MySQL 的 GROUP_CONCAT 分隔符语法节点是
//   `SEPARATOR_SYM text_string`，**只接受字面量**（MySQL Bug #64600，官方答复
//   "works as designed"；sql_yacc.yy 同形），传表达式即 **ERROR 1064 语法错误**。
//   → `enumerateSchema` 在 MySQL / MariaDB / TiDB 上**恒失败返回 null**。
//   同文件 SYS_QUERIES.MySQL.data 早已因同一原因改用 hex 字面量 0x1E。
// 注：多 expr 形态 GROUP_CONCAT(a,CHAR(31),b) 合法（多 expr 之间用分隔符连接），保留。
describe('[P2] MySQL SCHEMA_QUERY：SEPARATOR 不得传表达式', () => {
  for (const db of ['MySQL', 'MariaDB', 'TiDB']) {
    it(`${db}: enumerateSchema SQL 不含 \`SEPARATOR CHAR(\` / \`SEPARATOR CHR(\``, () => {
      const sql = SCHEMA_QUERY[db]('db1', 'users');
      // 通用判据：SEPARATOR 后面必须是字面量（引号串或 0x.. hex），不能是函数调用
      assert.doesNotMatch(
        sql, /SEPARATOR\s+(CHAR|CHR|CONCAT|CONVERT)\s*\(/i,
        `${db} 的 SEPARATOR 传了表达式 → MySQL 1064 语法错，enumerateSchema 恒失败: ${sql}`,
      );
      assert.match(sql, /SEPARATOR\s+0x1E\b/i, `${db} 行分隔符应为 hex 字面量 0x1E: ${sql}`);
      // 该形态本身必须仍在（防顺手改坏）
      assert.ok(sql.includes('information_schema.COLUMNS'), '应仍查 information_schema.COLUMNS');
      assert.ok(sql.includes('COLUMN_NAME') && sql.includes('COLUMN_TYPE'), '字段列表不应丢');
    });
  }

  it('全局：任何方言的 SCHEMA_QUERY 都不得用函数调用作 SEPARATOR', () => {
    const bad = [];
    for (const db of Object.keys(SCHEMA_QUERY)) {
      const q = SCHEMA_QUERY[db];
      if (typeof q !== 'function') continue;
      const sql = q('db1', 'users');
      if (/SEPARATOR\s+\w+\s*\(/i.test(sql)) bad.push(db + ' :: ' + sql.slice(0, 70));
    }
    assert.deepEqual(bad, [], `以下方言 SCHEMA_QUERY 的 SEPARATOR 用了表达式（MySQL 系直接 1064）:\n${bad.join('\n')}`);
  });
});

// ── [P2 审计修复 2026-09-22 第四批] H2 / HSQLDB / Derby 真引擎实测 ──────────────
// 取证方式：e2e/multi-engine-lab 的 EngineBridge（真 JDBC：H2 2.x / HSQLDB 2.x / Derby 10.16，
// Java 21），把生成的 SQL 原样投给引擎，记录引擎自己的返回。详见
// docs/P2-dialect-probe-2026-09-22.md。**不采信文档推测**。
//
// 三条引擎实证结论：
//   ① HSQLDB 的 GROUP_CONCAT 分隔符**只接受引号字面量**，表达式被语法分析器拒绝：
//        SELECT GROUP_CONCAT(NAME SEPARATOR CHAR(30)) ...
//        -> unexpected token : CHAR required: a quoted string
//      与 MySQL 的 SEPARATOR_SYM text_string 是**同一类**限制（两库独立命中同坑）。
//      修法：U&'\001E'（标准 Unicode 转义字面量）。实测 X'1E' 仍被拒。
//   ② H2 **接受**表达式分隔符（MODE=MySQL）：SEPARATOR CHAR(30) 实测产出 a<RS>b（真的生效）。
//      → 同一条 SQL 在 H2 合法、在 HSQLDB 非法，佐证「不能按写法类推方言合法性」。
//   ③ Derby 拖库通道**结构性不可用**：无 GROUP_CONCAT/LISTAGG/STRING_AGG；
//      且 CHAR(31) 返回字符串 "31"（11 字符）而非 ASCII 31 → 控制字符分隔符造不出来。
//      按「做不到就写做不到」降级为 data=null（与 Access/Informix 同处置）。
//
// 另修复标识符引号：HSQLDB 实测拒绝反引号（unexpected token），双引号可用。
// 该错误发生在 quoteCol / escCols / tableRef 三处独立判定里（本轮全部收敛）。
describe('[P2] HSQLDB：GROUP_CONCAT 分隔符必须是引号字面量（引擎实测）', () => {
  const COLS = ['id', 'name'];

  it('SYS_QUERIES.HSQLDB.data：SEPARATOR 用 U& 字面量，不得是 CHAR() 表达式', () => {
    const sql = SYS_QUERIES.HSQLDB.data('d', 't', COLS, 10, 0, null);
    assert.doesNotMatch(
      sql, /SEPARATOR\s+CHAR\s*\(/i,
      `HSQLDB SEPARATOR 传了表达式 → 引擎报 "CHAR required: a quoted string": ${sql}`,
    );
    assert.match(sql, /SEPARATOR\s+U&'\\001E'/i, `HSQLDB 行分隔符应为 U&'\\001E': ${sql}`);
    // 列间分隔符仍可用 CHAR(31)（实测行表达式里 CHAR() 合法，仅 SEPARATOR 操作数受限）
    assert.ok(sql.includes('CHAR(31)'), '列分隔符应保留 CHAR(31)');
    // 标识符必须双引号（反引号在 HSQLDB 实测语法错）
    assert.ok(sql.includes('"id"'), `HSQLDB 列引用应为双引号: ${sql}`);
    assert.ok(!sql.includes('`'), `HSQLDB 不得出现反引号（引擎实测拒绝）: ${sql}`);
  });

  it('HSQLDB 的枚举/列查询同样不得用反引号', () => {
    const tables = SYS_QUERIES.HSQLDB.tables();
    const cols = SYS_QUERIES.HSQLDB.columns('d', 't');
    for (const sql of [tables, cols]) {
      assert.ok(!sql.includes('`'), `HSQLDB 查询不得含反引号: ${sql}`);
    }
  });
});

describe('[P2] H2：接受表达式分隔符（与 HSQLDB 相反的实测结果）', () => {
  it('SYS_QUERIES.H2.data 的 SEPARATOR 保持 CHAR(30)（引擎实测真的生效）', () => {
    const sql = SYS_QUERIES.H2.data('d', 't', ['id', 'name'], 10, 0, null);
    assert.match(sql, /SEPARATOR\s+CHAR\(30\)/i, `H2 的 SEPARATOR CHAR(30) 实测生效，不应改动: ${sql}`);
    assert.ok(sql.includes('"id"'), `H2 列引用应为双引号: ${sql}`);
    assert.ok(!sql.includes('`'), `H2 不得出现反引号: ${sql}`);
  });
});

describe('[P2] Derby：拖库与枚举通道结构性不可用 → 诚实降级', () => {
  it('SYS_QUERIES.Derby 的 data/tables/columns 均为 null，databases 保留', () => {
    assert.equal(
      SYS_QUERIES.Derby.data, null,
      'Derby 无 GROUP_CONCAT/LISTAGG/STRING_AGG，且 CHAR(31) 返回字符串 "31" 而非控制字符 → 应降级为 null',
    );
    assert.equal(SYS_QUERIES.Derby.tables, null,
      'Derby 的 tables 枚举用 GROUP_CONCAT（实测函数不存在）→ 应降级为 null');
    assert.equal(SYS_QUERIES.Derby.columns, null,
      'Derby 的 columns 枚举用 GROUP_CONCAT（实测函数不存在）→ 应降级为 null');
    // databases 用 `SELECT CURRENT SCHEMA FROM SYSIBM.SYSDUMMY1` 只取单值，实测返回 ["APP"] → 保留
    assert.equal(typeof SYS_QUERIES.Derby.databases, 'string',
      'Derby 的 databases 实测可用，应保留');
  });

  it('escColsNN 对 Derby 用 COALESCE + 显式 VARCHAR 长度（引擎实测）', async () => {
    const { escColsNN } = await import('../src/engine/DialectSqlBuilder.js');
    const d = escColsNN(['x'], 'Derby');
    // CAST(x AS VARCHAR) 无长度 → Derby 报 Syntax error；IFNULL(CAST(int AS VARCHAR(4000))) →
    // 报 Cannot convert types 'INTEGER' to 'VARCHAR'。只有 COALESCE + VARCHAR(4000) 实测通过。
    assert.ok(d.includes('COALESCE(CAST('), `Derby escColsNN 应为 COALESCE: ${d}`);
    assert.ok(d.includes('VARCHAR(4000)'), `Derby CAST 必须带长度: ${d}`);
    assert.ok(!/IFNULL/.test(d), `Derby 不应使用 IFNULL（实测 INTEGER→VARCHAR 转换被拒）: ${d}`);
  });
});

// ── [P2 审计修复 2026-09-22 第五批] 枚举空查询在运行时抛错（而非返回空列表）──────
// 缺陷：Extractor 的 enumerateTables/Columns 写作
//     resolveSysQueries(edb, ver)?.tables(db)
// 可选链只保护**对象**，`tables` 属性本身为 null 时（Access，以及本轮新降级的 Derby）
// 会以 `?.tables is not a function` 抛错。实测复现（修复前）：
//     new Extractor().enumerateTables({dbms:'Access', …})
//     -> TypeError: resolveSysQueries(...)?.tables is not a function
// 即「把能力标记为不支持」与「运行时崩溃」错配——调用方以为拿到空列表，实际拿到异常。
// 修法：改用 `?.tables?.(db)`（属性可选 + 调用可选），与 enumerateDatabases 的
// `if (q == null) return []` 语义一致。
describe('[P2] 枚举：tables/columns 为 null 时应返回空列表而非抛错', () => {
  it('Access（tables/columns 均为 null）枚举不抛错', async () => {
    const { Extractor } = await import('../src/engine/Extractor.js');
    const ex = new Extractor();
    // 只验「不因 null 属性抛错」：此处故意用极简 ctx，即使后续因缺 method 抛错，
    // 错误信息也**不得**是 `is not a function`（那才是本缺陷的特征）。
    for (const fn of ['enumerateTables', 'enumerateColumns']) {
      const args = fn === 'enumerateColumns' ? ['db', 't'] : ['db'];
      try {
         
        const r = await ex[fn]({ dbms: 'Access', point: {}, config: {} }, ...args);
        assert.ok(Array.isArray(r), `${fn} 应返回数组，实得 ${typeof r}`);
      } catch (e) {
        assert.doesNotMatch(
          String(e.message), /is not a function/,
          `${fn} 因 null 属性抛错（本缺陷特征）: ${e.message}`,
        );
      }
    }
  });

  it('Derby（本轮新降级为 null）枚举不抛 is not a function', async () => {
    const { Extractor } = await import('../src/engine/Extractor.js');
    const ex = new Extractor();
    for (const fn of ['enumerateTables', 'enumerateColumns']) {
      const args = fn === 'enumerateColumns' ? ['db', 't'] : ['db'];
      try {
         
        await ex[fn]({ dbms: 'Derby', point: {}, config: {} }, ...args);
      } catch (e) {
        assert.doesNotMatch(String(e.message), /is not a function/,
          `${fn} 因 null 属性抛错: ${e.message}`);
      }
    }
  });

  it('源码契约：enumerateTables/Columns 必须用双可选链', async () => {
    const { readFile } = await import('node:fs/promises');
    const src = await readFile(new URL('../src/engine/Extractor.js', import.meta.url), 'utf8');
    assert.match(src, /\?\.tables\?\.\(/, 'enumerateTables 应使用 ?.tables?.(db) 双可选链');
    assert.match(src, /\?\.columns\?\.\(/, 'enumerateColumns 应使用 ?.columns?.(db, table) 双可选链');
  });
});

describe('[P2] buildStackPageSql：default 分支不得再套 MySQL 语法', () => {
  it('HSQLDB 用 U& 字面量分隔符（不再落 default 的 SEPARATOR CHAR）', async () => {
    const { buildStackPageSql } = await import('../src/engine/Exploiter.js');
    const sql = buildStackPageSql('HSQLDB', null, 't', ['id', 'name'], 0, 10);
    assert.equal(typeof sql, 'string', 'HSQLDB 应返回 SQL 字符串');
    assert.match(sql, /SEPARATOR\s+U&'\\000A'/i, `HSQLDB 行分隔符应为 U&'\\000A': ${sql}`);
    assert.doesNotMatch(sql, /SEPARATOR\s+CHAR\s*\(/i, `HSQLDB 不得用表达式分隔符: ${sql}`);
    assert.ok(!sql.includes('`'), `HSQLDB 不得出现反引号: ${sql}`);
  });

  it('H2 保持 SEPARATOR CHAR(10)（引擎实测生效）', async () => {
    const { buildStackPageSql } = await import('../src/engine/Exploiter.js');
    const sql = buildStackPageSql('H2', null, 't', ['id', 'name'], 0, 10);
    assert.match(sql, /SEPARATOR\s+CHAR\(10\)/i, `H2 应保留 CHAR(10) 分隔符: ${sql}`);
    assert.ok(!sql.includes('`'), `H2 不得出现反引号: ${sql}`);
  });

  it('未通过真引擎验证的方言一律返回 null（不生成必然报错的 SQL）', async () => {
    const { buildStackPageSql } = await import('../src/engine/Exploiter.js');
    const unverified = [
      'DB2', 'ClickHouse', 'Firebird', 'Informix', 'MonetDB',
      'Oracle', 'Sybase', 'Access', 'DM8', 'Derby',
    ];
    for (const d of unverified) {
      assert.equal(
        buildStackPageSql(d, null, 't', ['id'], 0, 10), null,
        `${d} 的聚合语法未经真引擎验证，应返回 null 而非一条必然报错的 SQL`,
      );
    }
  });

  it('已验证方言仍返回字符串（不得误伤）', async () => {
    const { buildStackPageSql } = await import('../src/engine/Exploiter.js');
    for (const d of ['MySQL', 'SQLite', 'PostgreSQL', 'SQL Server', 'HSQLDB', 'H2']) {
      const sql = buildStackPageSql(d, null, 't', ['id'], 0, 10);
      assert.equal(typeof sql, 'string', `${d} 应返回 SQL 字符串（已验证支持）`);
    }
  });
});

describe('[P2] 标识符引号：HSQLDB/MonetDB 必须双引号（反引号非法）', () => {
  it('escCols / quoteCol / tableRef 对 HSQLDB 均产出双引号（引擎实测反引号语法错）', async () => {
    const { escCols, quoteCol, tableRef } = await import('../src/engine/DialectSqlBuilder.js');
    assert.equal(escCols(['id'], 'HSQLDB'), '"id"', 'escCols HSQLDB 应为双引号');
    assert.equal(quoteCol('id', 'HSQLDB'), '"id"', 'quoteCol HSQLDB 应为双引号');
    assert.equal(tableRef('HSQLDB', null, 't'), '"t"', 'tableRef HSQLDB 应为双引号');
  });

  // [P2 审计修复 2026-09-22] MonetDB 与 HSQLDB 同类：官方手册《Lexical Structure》规定
  // 引号标识符只有双引号一种形态（"encapsulation with double quotes"），未定义反引号。
  // 原 escCols 把 MonetDB 归反引号组，与同一语句里 tableRef 产出的 `"users"`（双引号）
  // 自相矛盾。本机无 MonetDB 引擎，结论基于官方文档 + 静态自洽性（未经真机执行）。
  it('escCols / quoteCol / tableRef 对 MonetDB 均产出双引号（文档取证）', async () => {
    const { escCols, quoteCol, tableRef } = await import('../src/engine/DialectSqlBuilder.js');
    assert.equal(escCols(['id'], 'MonetDB'), '"id"', 'escCols MonetDB 应为双引号');
    assert.equal(quoteCol('id', 'MonetDB'), '"id"', 'quoteCol MonetDB 应为双引号');
    assert.equal(tableRef('MonetDB', null, 't'), '"t"', 'tableRef MonetDB 应为双引号');
  });

  it('MonetDB.data 模板内部引号自洽（列与表同为双引号，不得混用反引号）', async () => {
    const sql = SYS_QUERIES.MonetDB.data('db', 'users', ['id', 'name'], 5, 0, null);
    assert.ok(!sql.includes('`'), `MonetDB.data 不得含反引号: ${sql}`);
    assert.ok(sql.includes('"id"') && sql.includes('"name"'), 'MonetDB.data 列名应为双引号');
    assert.ok(sql.includes('FROM "users"'), 'MonetDB.data 表名应为双引号');
  });

  it('全局：非 MySQL 家族方言的标识符一律不得用反引号（SQLite 除外）', async () => {
    const { escCols } = await import('../src/engine/DialectSqlBuilder.js');
    // 反引号家族 = MySQL 系 + ClickHouse（ClickHouse 兼容 MySQL 语法，接受反引号）
    // [P2 修复] MonetDB 已移出：官方手册只认双引号，与 HSQLDB 同类。
    const backtickFamily = new Set(['MySQL', 'TiDB', 'MariaDB', 'ClickHouse']);
    const wrong = [];
    for (const db of Object.keys(SYS_QUERIES)) {
      if (backtickFamily.has(db)) continue;
      // escCols 里 SQLite 归双引号组；此处只校验 escCols 自身的一致性，
      // 故 SQLite 需单独排除（quoteCol 侧保留反引号是另一处既有契约，见 dialectSqlBuilder.test.js）
      if (db === 'SQLite') continue;
      if (escCols(['x'], db).includes('`')) wrong.push(db);
    }
    assert.deepEqual(
      wrong, [],
      `以下方言被误用反引号（HSQLDB 实测语法错、MonetDB 文档明文双引号；其余按各库标准亦非反引号）: ${wrong.join(', ')}`,
    );
  });
});
