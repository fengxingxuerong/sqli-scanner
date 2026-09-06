// selectPayloads testFilter / testSkip / level / risk 过滤语义测试
// 对标 sqlmap --test-filter / --test-skip / --level / --risk 的 id 与分级过滤
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  PAYLOAD_REGISTRY,
  selectPayloads,
} from '../../src/engine/payloadRegistry.js';

// ---- 辅助：从全量注册表中取 id 子串匹配的条目（用于构造期望集） ----
function idsContaining(substr) {
  return PAYLOAD_REGISTRY.filter((p) => p.id.toLowerCase().includes(substr.toLowerCase()));
}

describe('selectPayloads · testFilter（白名单）', () => {
  it('testFilter 单子串：仅返回 id 包含该子串的条目', () => {
    const r = selectPayloads({ testFilter: 'mysql-time' });
    assert.ok(r.length > 0, 'mysql-time 应有命中');
    for (const p of r) {
      assert.ok(
        p.id.toLowerCase().includes('mysql-time'),
        `${p.id} 不含 mysql-time，不应出现在 testFilter 结果`,
      );
    }
    // 确认确实过滤掉了非匹配条目（全量 > 过滤后）
    assert.ok(r.length < PAYLOAD_REGISTRY.length, 'testFilter 应缩减结果集');
  });

  it('testFilter 大小写不敏感', () => {
    const lower = selectPayloads({ testFilter: 'mysql-time' });
    const upper = selectPayloads({ testFilter: 'MYSQL-TIME' });
    const mixed = selectPayloads({ testFilter: 'MySql-Time' });
    assert.equal(lower.length, upper.length, '大小写应等价');
    assert.equal(lower.length, mixed.length, '大小写应等价');
  });

  it('testFilter 逗号分隔多子串：任一匹配即保留', () => {
    const r = selectPayloads({ testFilter: 'mysql-time,pg-time' });
    assert.ok(r.length > 0, 'mysql-time,pg-time 应有命中');
    for (const p of r) {
      const idLower = p.id.toLowerCase();
      assert.ok(
        idLower.includes('mysql-time') || idLower.includes('pg-time'),
        `${p.id} 不含 mysql-time 或 pg-time`,
      );
    }
    // 结果应等于两个子串分别匹配的并集
    const expected = new Set([
      ...idsContaining('mysql-time').map((p) => p.id),
      ...idsContaining('pg-time').map((p) => p.id),
    ]);
    assert.deepEqual(
      new Set(r.map((p) => p.id)),
      expected,
      '逗号分隔 testFilter 应为并集',
    );
  });

  it('testFilter 空串 / 空子串不生效（返回全量）', () => {
    const r = selectPayloads({ testFilter: '' });
    assert.equal(r.length, PAYLOAD_REGISTRY.length, '空 testFilter 不应过滤');

    const r2 = selectPayloads({ testFilter: '   ' });
    assert.equal(r2.length, PAYLOAD_REGISTRY.length, '空白 testFilter 不应过滤');
  });

  it('testFilter 无匹配返回空数组', () => {
    const r = selectPayloads({ testFilter: 'nonexistent-payload-id' });
    assert.equal(r.length, 0, '无匹配应返回空数组');
  });
});

describe('selectPayloads · testSkip（黑名单）', () => {
  it('testSkip 单子串：匹配条目被排除', () => {
    const r = selectPayloads({ testSkip: 'benchmark' });
    assert.ok(r.length > 0, '排除 benchmark 后仍应有条目');
    for (const p of r) {
      assert.ok(
        !p.id.toLowerCase().includes('benchmark'),
        `${p.id} 含 benchmark，应被 testSkip 排除`,
      );
    }
    // 确认确实排除了部分条目
    const benchmarkCount = idsContaining('benchmark').length;
    assert.ok(benchmarkCount > 0, '注册表中应有 benchmark 条目');
    assert.equal(
      r.length,
      PAYLOAD_REGISTRY.length - benchmarkCount,
      'testSkip 应排除所有 benchmark 条目',
    );
  });

  it('testSkip 大小写不敏感', () => {
    const lower = selectPayloads({ testSkip: 'benchmark' });
    const upper = selectPayloads({ testSkip: 'BENCHMARK' });
    assert.equal(lower.length, upper.length, '大小写应等价');
  });

  it('testSkip 逗号分隔多子串：任一匹配即排除', () => {
    const r = selectPayloads({ testSkip: 'benchmark,orderby' });
    for (const p of r) {
      const idLower = p.id.toLowerCase();
      assert.ok(
        !idLower.includes('benchmark') && !idLower.includes('orderby'),
        `${p.id} 含 benchmark 或 orderby，应被排除`,
      );
    }
  });

  it('testSkip 空串不生效（返回全量）', () => {
    const r = selectPayloads({ testSkip: '' });
    assert.equal(r.length, PAYLOAD_REGISTRY.length, '空 testSkip 不应过滤');
  });
});

describe('selectPayloads · testFilter + testSkip 组合', () => {
  it('先白名单再黑名单：filter 限定范围，skip 在范围内排除', () => {
    // 白名单：仅 mysql-time 系列；黑名单：排除 sleep
    const r = selectPayloads({ testFilter: 'mysql-time', testSkip: 'sleep' });
    for (const p of r) {
      assert.ok(
        p.id.toLowerCase().includes('mysql-time'),
        `${p.id} 不含 mysql-time`,
      );
      assert.ok(
        !p.id.toLowerCase().includes('sleep'),
        `${p.id} 含 sleep，应被 skip 排除`,
      );
    }
    // mysql-time 系列中不含 sleep 的条目应为结果
    const expected = idsContaining('mysql-time').filter(
      (p) => !p.id.toLowerCase().includes('sleep'),
    );
    assert.equal(r.length, expected.length, '组合过滤结果数应匹配');
    assert.deepEqual(
      r.map((p) => p.id).sort(),
      expected.map((p) => p.id).sort(),
    );
  });

  it('filter 与 skip 组合可收敛到空集', () => {
    // mysql-time 全部含 sleep 或 benchmark，skip sleep 后剩余 benchmark
    // 再 skip benchmark → 空
    const r = selectPayloads({ testFilter: 'mysql-time', testSkip: 'sleep,benchmark' });
    const mysqlTimeIds = idsContaining('mysql-time').map((p) => p.id);
    const allSkipped = mysqlTimeIds.every(
      (id) => id.toLowerCase().includes('sleep') || id.toLowerCase().includes('benchmark'),
    );
    if (allSkipped) {
      assert.equal(r.length, 0, '全部被 skip 后应返回空数组');
    }
  });
});

describe('selectPayloads · level 过滤', () => {
  it('level=1 不包含 level>1 的条目', () => {
    const r = selectPayloads({ level: 1 });
    assert.ok(r.length > 0, 'level=1 应有命中');
    for (const p of r) {
      assert.ok(p.level <= 1, `${p.id} level=${p.level} > 1`);
    }
    // 确认排除了 level>1 的条目
    const levelGt1 = PAYLOAD_REGISTRY.filter((p) => p.level > 1);
    assert.ok(levelGt1.length > 0, '注册表中应有 level>1 条目');
    for (const p of levelGt1) {
      assert.ok(!r.includes(p), `${p.id} level=${p.level} 不应出现在 level=1 结果`);
    }
  });

  it('level=5 返回全部（无 level>5 条目）', () => {
    const r = selectPayloads({ level: 5 });
    assert.equal(r.length, PAYLOAD_REGISTRY.length, 'level=5 应返回全部');
  });

  it('MySQL time level=1 仅含 level<=1 条目', () => {
    const r = selectPayloads({ dbms: 'MySQL', technique: 'time', level: 1 });
    assert.ok(r.length > 0, 'MySQL time level=1 应有命中');
    for (const p of r) {
      assert.ok(p.dbms.includes('MySQL'));
      assert.equal(p.technique, 'time');
      assert.ok(p.level <= 1, `${p.id} level=${p.level} > 1`);
    }
    // mysql-time-benchmark-1 是 level=3，不应出现
    const hasBenchmark = r.some((p) => p.id === 'mysql-time-benchmark-1');
    assert.ok(!hasBenchmark, 'mysql-time-benchmark-1 (level=3) 不应出现在 level=1 结果');
  });
});

describe('selectPayloads · risk 过滤', () => {
  it('risk=1 不包含 risk>1 的条目', () => {
    const r = selectPayloads({ risk: 1 });
    assert.ok(r.length > 0, 'risk=1 应有命中');
    for (const p of r) {
      assert.ok(p.risk <= 1, `${p.id} risk=${p.risk} > 1`);
    }
    // 确认排除了 risk>1 的条目
    const riskGt1 = PAYLOAD_REGISTRY.filter((p) => p.risk > 1);
    assert.ok(riskGt1.length > 0, '注册表中应有 risk>1 条目');
    for (const p of riskGt1) {
      assert.ok(!r.includes(p), `${p.id} risk=${p.risk} 不应出现在 risk=1 结果`);
    }
  });

  it('risk=3 返回全部（无 risk>3 条目）', () => {
    const r = selectPayloads({ risk: 3 });
    assert.equal(r.length, PAYLOAD_REGISTRY.length, 'risk=3 应返回全部');
  });

  it('MySQL time risk=1 不含 time 条目（time 均 risk>=2）', () => {
    const r = selectPayloads({ dbms: 'MySQL', technique: 'time', risk: 1 });
    // 所有 MySQL time 条目 risk=2，risk=1 应全部排除
    assert.equal(r.length, 0, 'MySQL time 条目 risk 均>=2，risk=1 应返回空');
  });
});

describe('selectPayloads · 逗号分隔 testFilter 跨技术', () => {
  it('"mysql-time,mysql-bool" 返回两类条目的并集', () => {
    const r = selectPayloads({ testFilter: 'mysql-time,mysql-bool' });
    assert.ok(r.length > 0);
    const timeEntries = r.filter((p) => p.id.toLowerCase().includes('mysql-time'));
    const boolEntries = r.filter((p) => p.id.toLowerCase().includes('mysql-bool'));
    assert.ok(timeEntries.length > 0, '应含 mysql-time 条目');
    assert.ok(boolEntries.length > 0, '应含 mysql-bool 条目');
    assert.equal(r.length, timeEntries.length + boolEntries.length, '应为两类并集（无交集）');
  });

  it('"mysql-time,pg-time" 跨 DBMS 并集', () => {
    const r = selectPayloads({ testFilter: 'mysql-time,pg-time' });
    assert.ok(r.length > 0);
    const mysqlTime = r.filter((p) => p.id.toLowerCase().includes('mysql-time'));
    const pgTime = r.filter((p) => p.id.toLowerCase().includes('pg-time'));
    assert.ok(mysqlTime.length > 0, '应含 mysql-time 条目');
    assert.ok(pgTime.length > 0, '应含 pg-time 条目');
    // MySQL 条目应包含 MySQL dbms
    for (const p of mysqlTime) assert.ok(p.dbms.includes('MySQL'));
    // PG 条目应包含 PostgreSQL dbms
    for (const p of pgTime) assert.ok(p.dbms.includes('PostgreSQL'));
  });
});
