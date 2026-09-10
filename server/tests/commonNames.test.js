// 字典爆破（--common-tables / --common-columns）单测
// 重点不是「能不能找到表」，而是「通道不可用时绝不返回空结果」——
// 空结果会被上层当成「目标确实没有这些表」，那是假阴性，比漏报更危险。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';
import { COMMON_TABLES, COMMON_COLUMNS } from '../src/engine/commonNames.js';

// 构造一个可编程的 Extractor 桩：按 candidate → 返回值 的映射回答探针
const mkExtractor = ({ tables = {}, columns = {}, sanity = '1', controlReturnsNumber = false }) => {
  const ex = new Extractor();
  ex._guessColumnsCached = async () => [1, 2, 3];
  ex.extractScalar = async (ctx, sql) => {
    // 通道自检：提取常量
    if (sql === '1') return sanity;
    // 表存在性探针：(SELECT COUNT(*) FROM <ref>)
    //   注意 tableRef 生成的是反引号/方括号引用（如 `shop`.`users`），
    //   解析时必须取「最后一段」而不是取第一个标识符 —— 否则拿到的是库名。
    const m = /SELECT COUNT\(\*\) FROM\s+(.+?)\)\s*$/.exec(sql.trim());
    if (m) {
      const ref = m[1];
      const name = ref.split('.').pop().replace(/[`"[\]]/g, '');
      if (name.includes('missing_probe')) return controlReturnsNumber ? '7' : null;
      return Object.prototype.hasOwnProperty.call(tables, name) ? String(tables[name]) : null;
    }
    // 列存在性探针：(SELECT COUNT(<col>) FROM <ref>)
    const c = /SELECT COUNT\(([A-Za-z0-9_]+)\) FROM/.exec(sql);
    if (c) {
      return Object.prototype.hasOwnProperty.call(columns, c[1]) ? String(columns[c[1]]) : null;
    }
    return null;
  };
  return ex;
};

const ctx = { dbms: 'MySQL', config: {}, point: {} };

test('字典本身有规模且不含重复项', () => {
  assert.ok(COMMON_TABLES.length >= 100, `表名字典应覆盖常见系统（当前 ${COMMON_TABLES.length}）`);
  assert.ok(COMMON_COLUMNS.length >= 100, `列名字典应覆盖常见字段（当前 ${COMMON_COLUMNS.length}）`);
  assert.equal(new Set(COMMON_TABLES).size, COMMON_TABLES.length, '表名字典不应有重复');
  assert.equal(new Set(COMMON_COLUMNS).size, COMMON_COLUMNS.length, '列名字典不应有重复');
});

test('findCommonTables：只返回真实存在的表，且带 tried/found 统计', async () => {
  const ex = mkExtractor({ tables: { users: 5, orders: 0 } });
  const r = await ex.findCommonTables(ctx, 'shop');
  assert.deepEqual(r.tables.sort(), ['orders', 'users']);
  assert.equal(r.tried, COMMON_TABLES.length);
  assert.equal(r.found, 2);
});

test('findCommonTables：提取通道不可用 → 必须报 CHANNEL_UNAVAILABLE，不能返回空结果当"没找到"', async () => {
  const ex = mkExtractor({ sanity: null, tables: { users: 5 } });
  const r = await ex.findCommonTables(ctx, 'shop');
  assert.deepEqual(r.tables, []);
  assert.equal(r.reason, 'CHANNEL_UNAVAILABLE', '通道坏了必须显式说明，否则上层会把假阴性当结论');
});

test('findCommonTables：不存在对照名竟返回行数（判定不可信）→ CONTROL_UNRELIABLE', async () => {
  const ex = mkExtractor({ controlReturnsNumber: true, tables: { users: 5 } });
  const r = await ex.findCommonTables(ctx, 'shop');
  assert.equal(r.reason, 'CONTROL_UNRELIABLE');
  assert.deepEqual(r.tables, []);
});

test('findCommonColumns：只返回真实存在的列（含全 NULL 列，COUNT 为 0 也算存在）', async () => {
  const ex = mkExtractor({ columns: { id: 5, name: 5, secret: 0 } });
  const r = await ex.findCommonColumns(ctx, 'shop', 'users');
  assert.deepEqual(r.columns.sort(), ['id', 'name', 'secret']);
  assert.equal(r.found, 3);
});

test('findCommonColumns：未给表名直接返回 NO_TABLE（不发起请求）', async () => {
  const ex = mkExtractor({});
  const r = await ex.findCommonColumns(ctx, 'shop', '');
  assert.equal(r.reason, 'NO_TABLE');
  assert.equal(r.tried, 0);
});

test('表不存在时列探针全部为 null → 返回空列集（表名错误不该猜出列）', async () => {
  const ex = mkExtractor({ columns: {} });
  const r = await ex.findCommonColumns(ctx, 'shop', 'nope');
  assert.deepEqual(r.columns, []);
  assert.equal(r.tried, COMMON_COLUMNS.length);
});
