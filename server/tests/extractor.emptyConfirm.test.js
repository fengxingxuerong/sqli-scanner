// [P0 2026-09-09 实战批次] 拖库「0 行」恒真对照测试
// 背景：空结果与「空表」不可区分——UNION 回显被 WAF/类型限制拦死时，非空表被写成
// 「0 行」交付给客户。修复：主循环 0 行时补 1 次行存在性探针区分「真空表 / 提取通路不稳」。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Extractor } from '../src/engine/Extractor.js';

function mkExtractor(scalarQueue) {
  const ex = new Extractor();
  const calls = [];
  ex._guessColumnsCached = async () => ['c1'];
  ex.extractScalar = async (ctx, sql) => {
    calls.push(sql);
    const next = scalarQueue.shift();
    if (next instanceof Error) throw next;
    return next ?? null;
  };
  return { ex, calls };
}

test('dumpData：0 行 + 探针有行 → onUnconfirmedEmpty 回调（提取通路不稳）', async () => {
  // 队列：第一页 data 查询返回空 → break；探针返回 '1'（有行）
  const { ex } = mkExtractor([null, '1']);
  const seen = [];
  const rows = await ex.dumpData({ dbms: 'MySQL', config: {} }, 'app', 'users', ['id'], 100, {
    onUnconfirmedEmpty: (db, table) => seen.push(`${db}.${table}`),
  });
  assert.deepEqual(rows, []);
  assert.deepEqual(seen, ['app.users']);
});

test('dumpData：0 行 + 探针无行 → 真空表，不回调', async () => {
  const { ex } = mkExtractor([null, null]);
  const seen = [];
  await ex.dumpData({ dbms: 'MySQL', config: {} }, 'app', 'empty_t', ['id'], 100, {
    onUnconfirmedEmpty: (db, table) => seen.push(`${db}.${table}`),
  });
  assert.deepEqual(seen, []);
});

test('dumpData：探针异常 → 保守标未确认', async () => {
  const { ex } = mkExtractor([null, new Error('probe failed')]);
  const seen = [];
  await ex.dumpData({ dbms: 'MySQL', config: {} }, 'app', 't', ['id'], 100, {
    onUnconfirmedEmpty: (db, table) => seen.push(`${db}.${table}`),
  });
  assert.deepEqual(seen, ['app.t']);
});

test('dumpData：非空结果不发探针（零额外请求）', async () => {
  const colSep = String.fromCharCode(0x1f);
  const { ex, calls } = mkExtractor([`v1${colSep}v2`]);
  const rows = await ex.dumpData({ dbms: 'MySQL', config: {} }, 'app', 't', ['id'], 100, {
    onUnconfirmedEmpty: () => assert.fail('非空结果不应触发探针'),
  });
  assert.equal(rows.length, 1);
  assert.equal(calls.length, 1, '仅 1 次 data 查询，无探针请求');
});

test('_confirmEmptyTable：方言探针 SQL 形状正确', async () => {
  const cases = [
    ['MySQL', 'SELECT 1 FROM app.t LIMIT 1'],
    ['PostgreSQL', 'SELECT 1 FROM app.t LIMIT 1'],
    ['SQL Server', 'SELECT TOP 1 1 FROM app.t'],
    ['Oracle', 'SELECT 1 FROM app.t WHERE ROWNUM = 1'],
  ];
  for (const [dbms, expected] of cases) {
    const { ex, calls } = mkExtractor(['1']);
    const verdict = await ex._confirmEmptyTable({ dbms, config: {} }, 'app', 't');
    assert.equal(verdict, 'unconfirmed');
    assert.ok(calls[0].includes(expected.split('FROM ')[1]), `${dbms} 探针 SQL 应限定 app.t：${calls[0]}`);
  }
});

test('dumpAllDatabases：聚合 meta.dumpUnconfirmed（带 db. 前缀）', async () => {
  const ex = new Extractor();
  ex.dumpDatabase = async (ctx, db, opts) => {
    if (db === 'dbB') opts.onUnconfirmedEmpty?.(db, 'ghost');
    return { tables: ['t1'], columns: { t1: ['id'] }, rows: { t1: [{ id: '1' }] } };
  };
  const res = await ex.dumpAllDatabases({ config: {} }, ['dbA', 'dbB']);
  assert.deepEqual(res.meta.dumpUnconfirmed, ['dbB.ghost']);
});
