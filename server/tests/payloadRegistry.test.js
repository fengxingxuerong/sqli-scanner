import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  PAYLOAD_REGISTRY,
  selectPayloads,
  listRegistry,
} from '../src/engine/payloadRegistry.js';

describe('payloadRegistry · 注册表完整性', () => {
  it('PAYLOAD_REGISTRY 至少 50 条', () => {
    assert.ok(PAYLOAD_REGISTRY.length >= 50, `期望 >=50，实际 ${PAYLOAD_REGISTRY.length}`);
  });

  it('每条声明具备必填元数据字段', () => {
    for (const p of PAYLOAD_REGISTRY) {
      assert.ok(p.id, `缺 id: ${JSON.stringify(p).slice(0, 80)}`);
      assert.ok(Array.isArray(p.dbms) && p.dbms.length, `缺 dbms: ${p.id}`);
      assert.ok(typeof p.technique === 'string' && p.technique, `缺 technique: ${p.id}`);
      assert.ok(typeof p.level === 'number' && p.level >= 1 && p.level <= 5, `level 非法: ${p.id}`);
      assert.ok(typeof p.risk === 'number' && p.risk >= 1 && p.risk <= 3, `risk 非法: ${p.id}`);
      assert.ok(Array.isArray(p.clause) && p.clause.length, `缺 clause: ${p.id}`);
      assert.ok(Array.isArray(p.boundary) && p.boundary.length, `缺 boundary: ${p.id}`);
      assert.ok(typeof p.template === 'string' && p.template, `缺 template: ${p.id}`);
      assert.ok(p.where === 'value' || p.where === 'position', `where 非法: ${p.id}`);
    }
  });

  it('id 全局唯一', () => {
    const ids = PAYLOAD_REGISTRY.map((p) => p.id);
    assert.equal(new Set(ids).size, ids.length, '存在重复 id');
  });

  it('至少覆盖 5 个 DBMS，每个 DBMS >=10 条', () => {
    const counts = {};
    for (const p of PAYLOAD_REGISTRY) for (const d of p.dbms) counts[d] = (counts[d] || 0) + 1;
    const core = ['MySQL', 'PostgreSQL', 'SQL Server', 'Oracle', 'SQLite'];
    for (const d of core) {
      assert.ok((counts[d] || 0) >= 10, `${d} 条数 ${counts[d] || 0} < 10`);
    }
    assert.ok(Object.keys(counts).length >= 5, 'DBMS 覆盖不足 5 个');
  });
});

describe('payloadRegistry · selectPayloads 筛选', () => {
  it('按 dbms 筛选正确（仅 MySQL 命中 MySQL/MariaDB/TiDB 条目）', () => {
    const r = selectPayloads({ dbms: 'MySQL' });
    assert.ok(r.length > 0);
    for (const p of r) assert.ok(p.dbms.includes('MySQL'), `${p.id} 不含 MySQL`);
    // PostgreSQL 专属条目不应出现在 MySQL 结果里
    // pgOnly unused — 直接用 pgExclusive 校验
    const pgExclusive = PAYLOAD_REGISTRY.filter(
      (p) => p.dbms.includes('PostgreSQL') && !p.dbms.includes('MySQL'),
    );
    for (const p of pgExclusive) {
      assert.ok(!r.includes(p), `${p.id} 是 PG 专属，不应出现在 MySQL 结果`);
    }
  });

  it('按 technique 筛选正确（boolean 仅返回 boolean）', () => {
    const r = selectPayloads({ technique: 'boolean' });
    assert.ok(r.length > 0);
    for (const p of r) assert.equal(p.technique, 'boolean');
  });

  it('MySQL boolean level=1 返回正确子集（全部 level<=1）', () => {
    const r = selectPayloads({ dbms: 'MySQL', technique: 'boolean', level: 1 });
    assert.ok(r.length > 0, 'MySQL boolean level=1 应有命中');
    for (const p of r) {
      assert.equal(p.technique, 'boolean');
      assert.ok(p.dbms.includes('MySQL'));
      assert.ok(p.level <= 1, `${p.id} level=${p.level} > 1`);
    }
    // level=1 不应包含 level=2 的 OR 变体
    const orIds = r.filter((p) => p.id.includes('or'));
    assert.equal(orIds.length, 0, 'level=1 不应含 OR 变体（OR 均 level>=2）');
  });

  it('level=5 返回全部（无 level>5 条目）', () => {
    const r = selectPayloads({ level: 5 });
    assert.equal(r.length, PAYLOAD_REGISTRY.length, 'level=5 应返回全部条目');
  });

  it('clause=["where"] 返回正确子集（仅含 where 子句条目）', () => {
    const r = selectPayloads({ clause: ['where'] });
    assert.ok(r.length > 0);
    for (const p of r) assert.ok(p.clause.includes('where'), `${p.id} 不含 where`);
    // orderby 专属条目不应命中
    const orderbyOnly = PAYLOAD_REGISTRY.filter(
      (p) => p.clause.includes('orderby') && !p.clause.includes('where'),
    );
    for (const p of orderbyOnly) assert.ok(!r.includes(p), `${p.id} 是 orderby 专属，不应命中 where`);
  });

  it("boundary=\"'\" 返回包含单引号闭合的 payload", () => {
    const r = selectPayloads({ boundary: "'" });
    assert.ok(r.length > 0, "boundary='\"' 应有命中");
    for (const p of r) assert.ok(p.boundary.includes("'"), `${p.id} 不含单引号闭合`);
    // 仅空串闭合的条目不应命中
    const emptyOnly = PAYLOAD_REGISTRY.filter(
      (p) => p.boundary.length === 1 && p.boundary[0] === '',
    );
    for (const p of emptyOnly) assert.ok(!r.includes(p), `${p.id} 仅空串闭合，不应命中单引号`);
  });

  it('risk 筛选：risk=1 不含 risk>1 条目', () => {
    const r = selectPayloads({ risk: 1 });
    assert.ok(r.length > 0);
    for (const p of r) assert.ok(p.risk <= 1, `${p.id} risk=${p.risk} > 1`);
  });

  it('组合筛选：MySQL + time + level<=2 + risk<=2', () => {
    const r = selectPayloads({ dbms: 'MySQL', technique: 'time', level: 2, risk: 2 });
    assert.ok(r.length > 0, '应至少命中 mysql-time-sleep-1');
    for (const p of r) {
      assert.ok(p.dbms.includes('MySQL'));
      assert.equal(p.technique, 'time');
      assert.ok(p.level <= 2);
      assert.ok(p.risk <= 2);
    }
  });

  it('无命中返回空数组（非法 dbms）', () => {
    const r = selectPayloads({ dbms: 'NoSuchDB' });
    assert.equal(r.length, 0);
  });

  it('listRegistry 返回全量（与 PAYLOAD_REGISTRY 同长）', () => {
    assert.equal(listRegistry().length, PAYLOAD_REGISTRY.length);
  });
});

describe('payloadRegistry · 布尔对完整性', () => {
  it('声明了 falseTemplate 的 boolean 条目为有效真假对（非空字符串）', () => {
    const bools = selectPayloads({ technique: 'boolean' });
    const paired = bools.filter((p) => p.falseTemplate !== undefined);
    assert.ok(paired.length > 0, '应至少有一条含 falseTemplate 的布尔对');
    for (const p of paired) {
      assert.ok(
        typeof p.falseTemplate === 'string' && p.falseTemplate,
        `boolean 条目 ${p.id} 声明了 falseTemplate 但为空/非字符串`,
      );
      assert.notEqual(p.template, p.falseTemplate, `${p.id} 真假模板不应相同`);
    }
  });
});
