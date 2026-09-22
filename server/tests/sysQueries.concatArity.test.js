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
import { SYS_QUERIES } from '../src/engine/extractionMaps.js';

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
