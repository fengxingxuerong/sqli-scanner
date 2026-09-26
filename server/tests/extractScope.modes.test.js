// extractScope.modes.test.js —— 拖库范围解析（engine/extractScope.js）专属单测
// ============================================================================
// 为什么补这一份：extractScope.js 449 行、**此前零测试挂载**（覆盖率 lines 67.6% /
// func 57.1%），是「枚举/拖库范围」这一整块能力的唯一入口（--dbs/--tables/--columns/
// --dump/--current-db/--users/--passwords/--schema/--count/--search …）。
// 未覆盖的恰好是「结果脏但不报错」的分支：系统库过滤、单库失败隔离、null 是有效结果、
// 强实现降级、限流、失败记空而非丢字段。
//
// 手法：stub 驱动真实入口（extractAll / extractByScope），断言落在返回结构与
// 调用面上（哪些 extractor 方法被调用、被调几次），不抄内部逻辑。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractAll, extractByScope } from '../src/engine/extractScope.js';
import * as eventBus from '../src/core/eventBus.js';

let uid = 0;
const nextScanId = () => `extract-scope-${++uid}`;

/**
 * @param {object} o
 * @param {Record<string, any>} [o.extractor] Extractor 桩：方法名 → 返回值 / 抛错 / 函数
 */
function build(o = {}) {
  const scanId = nextScanId();
  const events = [];
  const em = eventBus.create(scanId);
  em.on('event', (e) => events.push(e));

  const calls = [];
  const rec = (name) => {
    calls.push(name);
    return calls.filter((c) => c === name).length;
  };

  const extractor = {
    enumerateDatabases: async () => { rec('enumerateDatabases'); return o.dbs ?? ['appdb', 'mysql', 'information_schema']; },
    enumerateTables: async (_ctx, db) => { rec(`enumerateTables:${db}`); return o.tables?.[db] ?? ['users', 'logs']; },
    enumerateColumns: async (_ctx, db, t) => { rec(`enumerateColumns:${db}.${t}`); return o.columns?.[`${db}.${t}`] ?? ['id', 'name']; },
    dumpData: async (_ctx, db, t, cols, _n, opts) => { rec(`dumpData:${db}.${t}`); calls.push(`dumpWhere:${opts?.where ?? 'null'}`); return o.rows?.[`${db}.${t}`] ?? [{ id: 1 }]; },
    dumpAllDatabases: async (_ctx, dbs, opts) => {
      rec('dumpAllDatabases');
      if (o.onDumpAll) o.onDumpAll(opts);
      return o.dumpAll ?? { databases: dbs, tables: { appdb: ['users'] }, columns: { 'appdb.users': ['id'] }, rows: { 'appdb.users': [{ id: 1 }] }, meta: o.dumpAllMeta };
    },
    findCommonTables: async () => ({ tables: o.commonTables ?? ['admin'], tried: 20 }),
    findCommonColumns: async () => ({ columns: o.commonColumns ?? ['passwd'] }),
    searchTables: o.searchTables,
    searchColumns: o.searchColumns,
    ...(o.extractor || {}),
  };

  const sm = {
    extractor,
    exploiter: { deepDump: async () => { rec('deepDump'); return [{ id: 9 }]; } },
    _colTypeCache: new Map(),
    colTypeEnum: o.colTypeEnum === null ? undefined : {
      enumerate: async (_ctx, db, t, cols) => { rec(`colType:${db}.${t}`); return (cols || []).map((c) => ({ name: c, type: 'int' })); },
      ...(o.colTypeEnum || {}),
    },
    async _mapPool(items, worker, limit) {
      rec(`_mapPool:${limit}`);
      let i = 0;
      const runners = Array.from({ length: Math.max(1, Math.min(limit ?? 1, items.length)) }, async () => {
        while (i < items.length) await worker(items[i++], i - 1);
      });
      await Promise.all(runners);
    },
  };

  const ctx = {
    scanId,
    config: { ...(o.config || {}) },
    target: { config: { ...(o.targetConfig || {}) } },
  };

  return {
    sm, scanId, ctx, calls, events,
    times: (name) => calls.filter((c) => c === name).length,
    done: () => eventBus.dispose(scanId),
  };
}

// ── extractAll：全量拖库 ────────────────────────────────────────────────

test('① 全量拖库：默认过滤系统库（对标 --exclude-sysdbs）', async () => {
  const h = build();
  try {
    const data = await extractAll(h.sm, h.scanId, h.ctx);
    assert.deepEqual(data.databases, ['appdb'], 'mysql / information_schema 必须被过滤');
  } finally { h.done(); }
});

test('① 反向：config.excludeSysdbs=false 时保留系统库（显式关过滤才生效）', async () => {
  const h = build({ targetConfig: { excludeSysdbs: false } });
  try {
    const data = await extractAll(h.sm, h.scanId, h.ctx);
    assert.equal(data.databases.length, 3);
    assert.ok(data.databases.includes('mysql'));
  } finally { h.done(); }
});

test('② 全量拖库：union 提取失败走 deepDump 兜底，兜底表名进 meta（报告要能看见）', async () => {
  // onDumpAll 钩子模拟「union 提取失败 → dumpAllDatabases 回调 onFallback 转 deepDump」
  const h = build({ onDumpAll: (opts) => opts.onFallback?.('appdb.users') });
  try {
    const data = await extractAll(h.sm, h.scanId, h.ctx);
    assert.deepEqual(data.meta?.deepDumpTables, ['appdb.users'], '走了 fallback 的表必须在产物里可见');
  } finally { h.done(); }
});

test('③ 全量拖库：0 行未确认的表必须透出（空结果 ≠ 空表）', async () => {
  const h = build({ dumpAllMeta: { dumpUnconfirmed: ['appdb.logs'] } });
  try {
    const data = await extractAll(h.sm, h.scanId, h.ctx);
    assert.deepEqual(data.meta?.dumpUnconfirmed, ['appdb.logs']);
  } finally { h.done(); }
});

test('④ 全量拖库：列类型枚举结果写回 columns，且同表只枚举一次（缓存）', async () => {
  const h = build({ dumpAll: { databases: ['appdb'], tables: { appdb: ['users'] }, columns: { 'appdb.users': ['id', 'name'] }, rows: { 'appdb.users': [{ id: 1 }] } } });
  try {
    const data = await extractAll(h.sm, h.scanId, h.ctx);
    assert.deepEqual(data.columns['appdb.users'], ['id:int', 'name:int'], '类型枚举结果要落到 columns');
    // 同一 sm 再跑一次：缓存必须挡掉第二次枚举（缓存失效 = 每轮多 1 请求/表）
    await extractAll(h.sm, h.scanId, h.ctx);
    assert.equal(h.times('colType:appdb.users'), 1);
  } finally { h.done(); }
});

test('⑤ 全量拖库：extractor 抛错被吞，返回空结构而不是把异常抛给调用方', async () => {
  const h = build({ extractor: { enumerateDatabases: async () => { throw new Error('权限不足'); } } });
  try {
    const data = await extractAll(h.sm, h.scanId, h.ctx);
    assert.deepEqual(data.databases, []);
    assert.deepEqual(data.tables, {});
  } finally { h.done(); }
});

test('⑥ 全量拖库：有 extractScope.mode 时改走定向枚举（不重复跑全量）', async () => {
  const h = build({ config: { extractScope: { mode: 'dbs' } } });
  try {
    const data = await extractAll(h.sm, h.scanId, h.ctx);
    assert.deepEqual(data.databases, ['appdb']);
    assert.equal(h.times('dumpAllDatabases'), 0, '定向枚举模式不得再触发全量拖库');
  } finally { h.done(); }
});

// ── extractByScope：各枚举模式 ──────────────────────────────────────────

test('⑦ --dbs：过滤系统库；scope.excludeSysdbs 优先级高于 config', async () => {
  const h = build();
  try {
    const a = await extractByScope(h.sm, h.scanId, h.ctx, { mode: 'dbs' });
    assert.deepEqual(a.databases, ['appdb']);
    const b = await extractByScope(h.sm, h.scanId, { ...h.ctx, target: { config: { excludeSysdbs: false } } }, { mode: 'dbs', excludeSysdbs: true });
    assert.deepEqual(b.databases, ['appdb'], 'scope 显式值必须压过 config（否则 CLI 参数被配置吃掉）');
  } finally { h.done(); }
});

test('⑧ --tables：指定 -D 时只枚举指定库；单库失败隔离为 []（不影响其它库）', async () => {
  const h = build({
    extractor: { enumerateTables: async (_ctx, db) => { if (db === 'broken') throw new Error('拒绝访问'); return ['t1']; } },
  });
  try {
    const data = await extractByScope(h.sm, h.scanId, h.ctx, { mode: 'tables', dbs: ['appdb', 'broken'] });
    assert.deepEqual(data.tables.appdb, ['t1']);
    assert.deepEqual(data.tables.broken, [], '失败的库记空，不得整体失败');
    assert.equal(h.times('enumerateDatabases'), 0, '指定了 -D 就不该再枚举库');
  } finally { h.done(); }
});

test('⑨ --columns：逐表失败记 []；cols 未指定时才调 enumerateColumns', async () => {
  const h = build({
    extractor: { enumerateColumns: async (_ctx, db, t) => { if (t === 'logs') throw new Error('无权限'); return ['id']; } },
  });
  try {
    const data = await extractByScope(h.sm, h.scanId, h.ctx, { mode: 'columns', dbs: ['appdb'], tables: ['users', 'logs'] });
    assert.deepEqual(data.columns['appdb.users'], ['id']);
    assert.deepEqual(data.columns['appdb.logs'], [], '失败的表列记空，不能让调用方拿到 undefined');
  } finally { h.done(); }
});

test('⑩ --dump：cols 显式指定时不再调 enumerateColumns，且 dumpWhere 透传进 SQL', async () => {
  const h = build({ config: { dumpWhere: 'id > 10' } });
  try {
    const data = await extractByScope(h.sm, h.scanId, h.ctx, { mode: 'dump', dbs: ['appdb'], tables: ['users'], cols: 'id,name' });
    assert.equal(h.times('enumerateColumns:appdb.users'), 0, '-C 已给列就别再枚举（省请求）');
    assert.deepEqual(data.columns['appdb.users'], ['id', 'name'], '逗号串要切成数组');
    assert.ok(h.calls.includes('dumpWhere:id > 10'), 'where 必须原样透传给 dumpData');
  } finally { h.done(); }
});

test('⑪ --current-db：null 是有效结果（SQLite 无会话库），不得被当成「未提取」丢掉', async () => {
  const h = build({ extractor: { currentDb: async () => null } });
  try {
    const data = await extractByScope(h.sm, h.scanId, h.ctx, { mode: 'currentDb' });
    assert.equal(data.currentDb, null);
    assert.ok('currentDb' in data);
  } finally { h.done(); }
});

test('⑫ ensureExtractor：Extractor 缺方法时抛错被吞，返回空结构（不把 CLI 打崩）', async () => {
  const h = build();
  try {
    const data = await extractByScope(h.sm, h.scanId, h.ctx, { mode: 'currentUser' });
    assert.equal(data.currentUser, undefined, '未实现的能力返回未提取，而不是 undefined 之外的脏值');
  } finally { h.done(); }
});

test('⑬ --count：行数转 Number，枚举失败记 null（不得记 0 —— 0 会被当成「空表」）', async () => {
  const h = build({
    extractor: {
      // logs：枚举抛错（走 catch 分支）；users：返回字符串行数（走 Number 转换分支）
      countRows: async (_ctx, db, t) => {
        if (t === 'logs') throw new Error('count 被拦');
        return '42';
      },
    },
  });
  try {
    const data = await extractByScope(h.sm, h.scanId, h.ctx, { mode: 'count', dbs: ['appdb'], tables: ['users', 'logs'] });
    assert.equal(data.counts['appdb.users'], 42, '字符串行数必须转成数字');
    assert.equal(data.counts['appdb.logs'], null);
  } finally { h.done(); }
});

test('⑭ --search：keyword 为空直接返回空结果（不得白跑一轮全库枚举）', async () => {
  const h = build();
  try {
    const data = await extractByScope(h.sm, h.scanId, h.ctx, { mode: 'search' });
    assert.deepEqual(data.databases, []);
    assert.deepEqual(data.search, { keyword: '', matchedTables: [], matchedColumns: [] });
    assert.equal(h.times('enumerateTables:appdb'), 0, '空关键词不得触发枚举');
  } finally { h.done(); }
});

test('⑮ --search：强实现（searchTables/searchColumns）命中时优先，不再逐库枚举', async () => {
  const h = build({
    searchTables: async () => ['appdb.user_info'],
    searchColumns: async () => ['appdb.users.email'],
  });
  try {
    const data = await extractByScope(h.sm, h.scanId, h.ctx, { mode: 'search', keyword: 'user' });
    assert.deepEqual(data.search.matchedTables, ['appdb.user_info']);
    assert.deepEqual(data.search.matchedColumns, [{ table: 'appdb.users', columns: ['email'] }]);
    assert.equal(h.times('enumerateTables:appdb'), 0, '强实现已覆盖全库，逐库枚举是白花请求');
  } finally { h.done(); }
});

test('⑮ 反向：强实现抛错时降级朴素枚举（限流 3 库 × 10 表），结果仍要出来', async () => {
  const h = build({
    dbs: ['appdb', 'db2', 'db3', 'db4'],
    tables: Object.fromEntries(['appdb', 'db2', 'db3', 'db4'].map((d) => [d, Array.from({ length: 12 }, (_, i) => `t${i}`)])),
    searchTables: async () => { throw new Error('information_schema 被拦'); },
    searchColumns: async () => { throw new Error('information_schema 被拦'); },
  });
  try {
    const data = await extractByScope(h.sm, h.scanId, h.ctx, { mode: 'search', keyword: 't1' });
    assert.equal(h.times('enumerateTables:db4'), 0, '限流：第 4 个库不该被枚举');
    assert.equal(Object.keys(data.tables).length, 3);
    assert.equal(data.tables.appdb.length, 10, '限流：每库最多 10 张表');
    assert.ok(data.search.matchedTables.includes('appdb.t1'));
  } finally { h.done(); }
});

test('⑯ --search：朴素兜底时 SQLite 裸表名补 main. 前缀（强实现路径的规范化）', async () => {
  const h = build({ searchTables: async () => ['users'], searchColumns: async () => [] });
  try {
    const data = await extractByScope(h.sm, h.scanId, h.ctx, { mode: 'search', keyword: 'user' });
    assert.deepEqual(data.search.matchedTables, ['main.users'], '裸表名要补前缀，与展示一致');
  } finally { h.done(); }
});

test('⑰ 未知 mode：抛错被吞且不崩（返回空结构，而不是让扫描中断）', async () => {
  const h = build();
  try {
    const data = await extractByScope(h.sm, h.scanId, h.ctx, { mode: 'no-such-mode' });
    assert.deepEqual(data.databases, []);
    assert.deepEqual(data.tables, {});
  } finally { h.done(); }
});

test('⑱ --dumpAll：未枚举到任何库时不再拖（空库列表直接收，不空跑并发池）', async () => {
  const h = build({ dbs: ['mysql'] }); // 过滤后为空
  try {
    const data = await extractByScope(h.sm, h.scanId, h.ctx, { mode: 'dumpAll' });
    assert.equal(h.times('dumpAllDatabases'), 0);
    assert.deepEqual(data.rows, {});
  } finally { h.done(); }
});
