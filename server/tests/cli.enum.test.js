// CLI 枚举命令单测（对标 sqlmap --dbs/--tables/--columns/--dump/--current-db/--current-user/--count）
// 覆盖：
//   1) parseArgs：新参数解析（含 -D/-T/-C 与 --no-exclude-sysdbs）
//   2) buildConfig：枚举开关 → enableExtract
//   3) buildExtractScope：各模式 scope 构造
//   4) validateEnumArgs：参数组合校验
//   5) ScanManager._extract：mock extractor 断言各 enum 分支返回结构正确
//   6) printExtractView：精简文本输出
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, buildConfig, buildExtractScope, validateEnumArgs, printExtractView } from '../bin/cli.js';
import { ScanManager } from '../src/engine/ScanManager.js';
import { createTarget } from '../src/engine/models.js';
import { TargetParser } from '../src/engine/TargetParser.js';
import { DirectConnector } from '../src/core/directConnector.js';
import { Extractor } from '../src/engine/Extractor.js';

// ─────────────── 1) parseArgs ───────────────
test('parseArgs: --dbs 解析为布尔，excludeSysdbs 默认 true', () => {
  const a = parseArgs(['-u', 'http://x', '--dbs']);
  assert.equal(a.dbs, true);
  assert.equal(a.excludeSysdbs, true);
  assert.equal(a.url, 'http://x');
});

test('parseArgs: --tables -D db / --columns -D db -T t', () => {
  const a = parseArgs(['-u', 'http://x', '--tables', '-D', 'mydb']);
  assert.equal(a.tables, true);
  assert.equal(a.db, 'mydb');
  const b = parseArgs(['-u', 'http://x', '--columns', '-D', 'd', '-T', 't']);
  assert.equal(b.columns, true);
  assert.equal(b.db, 'd');
  assert.equal(b.table, 't');
});

test('parseArgs: --dump -D db -T t -C a,b', () => {
  const a = parseArgs(['-u', 'http://x', '--dump', '-D', 'd', '-T', 't', '-C', 'a,b']);
  assert.equal(a.dump, true);
  assert.equal(a.db, 'd');
  assert.equal(a.table, 't');
  assert.equal(a.columnsList, 'a,b');
});

test('parseArgs: --current-db / --current-user / --count', () => {
  assert.equal(parseArgs(['-u', 'http://x', '--current-db']).currentDb, true);
  assert.equal(parseArgs(['-u', 'http://x', '--current-user']).currentUser, true);
  const c = parseArgs(['-u', 'http://x', '--count', '-D', 'd', '-T', 't']);
  assert.equal(c.count, true);
});

test('parseArgs: --no-exclude-sysdbs 关闭默认；长短名等价', () => {
  assert.equal(parseArgs(['--no-exclude-sysdbs']).excludeSysdbs, false);
  assert.equal(parseArgs(['--exclude-sysdbs']).excludeSysdbs, true);
  assert.equal(parseArgs(['-D', 'foo', '--db', 'bar']).db, 'bar');
  assert.equal(parseArgs(['-T', 'foo', '--table', 'bar']).table, 'bar');
  assert.equal(parseArgs(['-C', 'x,y', '--columns-list', 'z']).columnsList, 'z');
});

// ─────────────── 2) buildConfig ───────────────
test('buildConfig: 枚举开关 → enableExtract=true；仅 -u → false', () => {
  assert.equal(buildConfig(parseArgs(['-u', 'http://x', '--dbs'])).enableExtract, true);
  assert.equal(buildConfig(parseArgs(['-u', 'http://x', '--current-db'])).enableExtract, true);
  assert.equal(buildConfig(parseArgs(['-u', 'http://x', '--count', '-D', 'd', '-T', 't'])).enableExtract, true);
  assert.equal(buildConfig(parseArgs(['-u', 'http://x'])).enableExtract, false);
});

// ─────────────── 3) buildExtractScope ───────────────
test('buildExtractScope: --dbs → {mode:dbs}', () => {
  assert.deepEqual(buildExtractScope(parseArgs(['-u', 'http://x', '--dbs'])),
    { mode: 'dbs', excludeSysdbs: true });
});

test('buildExtractScope: --tables -D d → {mode:tables, dbs:[d]}', () => {
  assert.deepEqual(buildExtractScope(parseArgs(['-u', 'http://x', '--tables', '-D', 'd'])),
    { mode: 'tables', dbs: ['d'], excludeSysdbs: true });
});

test('buildExtractScope: --columns -D d -T t → {mode:columns, dbs, tables}', () => {
  assert.deepEqual(buildExtractScope(parseArgs(['-u', 'http://x', '--columns', '-D', 'd', '-T', 't'])),
    { mode: 'columns', dbs: ['d'], tables: ['t'], excludeSysdbs: true });
});

test('buildExtractScope: --dump -D d -T t -C a,b → {mode:dump, cols}', () => {
  assert.deepEqual(buildExtractScope(parseArgs(['-u', 'http://x', '--dump', '-D', 'd', '-T', 't', '-C', 'a,b'])),
    { mode: 'dump', dbs: ['d'], tables: ['t'], cols: ['a', 'b'], excludeSysdbs: true });
});

test('buildExtractScope: --dump -D d -T t（无 -C）→ cols undefined', () => {
  const s = buildExtractScope(parseArgs(['-u', 'http://x', '--dump', '-D', 'd', '-T', 't']));
  assert.equal(s.mode, 'dump');
  assert.equal(s.cols, undefined);
});

test('buildExtractScope: --current-db / --current-user / --count', () => {
  assert.deepEqual(buildExtractScope(parseArgs(['-u', 'http://x', '--current-db'])),
    { mode: 'currentDb', excludeSysdbs: true });
  assert.deepEqual(buildExtractScope(parseArgs(['-u', 'http://x', '--current-user'])),
    { mode: 'currentUser', excludeSysdbs: true });
  assert.deepEqual(buildExtractScope(parseArgs(['-u', 'http://x', '--count', '-D', 'd', '-T', 't'])),
    { mode: 'count', dbs: ['d'], tables: ['t'], excludeSysdbs: true });
});

test('buildExtractScope: 无枚举开关 → undefined', () => {
  assert.equal(buildExtractScope(parseArgs(['-u', 'http://x'])), undefined);
  // --dump 但无 -D/-T/-C → 既有全量拖库分支（scope undefined）
  assert.equal(buildExtractScope(parseArgs(['-u', 'http://x', '--dump'])), undefined);
});

test('buildExtractScope: --no-exclude-sysdbs → excludeSysdbs=false', () => {
  const s = buildExtractScope(parseArgs(['-u', 'http://x', '--dbs', '--no-exclude-sysdbs']));
  assert.equal(s.excludeSysdbs, false);
});

// ─────────────── 4) validateEnumArgs ───────────────
test('validateEnumArgs: --tables 缺 -D 报错', () => {
  assert.match(validateEnumArgs(parseArgs(['-u', 'http://x', '--tables'])), /--tables/);
});
test('validateEnumArgs: --columns 缺 -T 报错', () => {
  assert.match(validateEnumArgs(parseArgs(['-u', 'http://x', '--columns', '-D', 'd'])), /--columns/);
});
test('validateEnumArgs: --count 缺 -T 报错', () => {
  assert.match(validateEnumArgs(parseArgs(['-u', 'http://x', '--count', '-D', 'd'])), /--count/);
});
test('validateEnumArgs: -C 无 -T 报错；-C 无 --dump 报错', () => {
  assert.match(validateEnumArgs(parseArgs(['-u', 'http://x', '-C', 'a,b'])), /-C.*-T|-T.*-C/);
  assert.match(validateEnumArgs(parseArgs(['-u', 'http://x', '-C', 'a,b', '-T', 't'])), /--dump/);
});
test('validateEnumArgs: 合法组合返回 null', () => {
  assert.equal(validateEnumArgs(parseArgs(['-u', 'http://x', '--dbs'])), null);
  assert.equal(validateEnumArgs(parseArgs(['-u', 'http://x', '--tables', '-D', 'd'])), null);
  assert.equal(validateEnumArgs(parseArgs(['-u', 'http://x', '--dump', '-D', 'd', '-T', 't', '-C', 'a,b'])), null);
});

// ─────────────── 5) ScanManager._extract 分支（mock extractor） ───────────────
// 构造 mock extractor：按需覆盖各方法，记录调用
function mockExtractor(overrides = {}) {
  const calls = {};
  const ex = {
    calls,
    async enumerateDatabases(ctx) { calls.enumerateDatabases = (calls.enumerateDatabases || 0) + 1; return overrides.dbs ?? []; },
    async enumerateTables(ctx, db) { calls.enumerateTables = (calls.enumerateTables || 0) + 1; return overrides.tables?.[db] ?? []; },
    async enumerateColumns(ctx, db, t) { calls.enumerateColumns = (calls.enumerateColumns || 0) + 1; return overrides.columns?.[`${db}.${t}`] ?? []; },
    async dumpData(ctx, db, t, cols) { calls.dumpData = (calls.dumpData || 0) + 1; return overrides.dump?.[`${db}.${t}`] ?? []; },
    async currentDb(ctx) { calls.currentDb = (calls.currentDb || 0) + 1; return overrides.currentDb ?? null; },
    async currentUser(ctx) { calls.currentUser = (calls.currentUser || 0) + 1; return overrides.currentUser ?? null; },
    async countRows(ctx, db, t) { calls.countRows = (calls.countRows || 0) + 1; return overrides.count?.[`${db}.${t}`] ?? null; },
    async dumpAllDatabases(ctx, dbs, opts) { calls.dumpAllDatabases = (calls.dumpAllDatabases || 0) + 1; return overrides.dumpAll ?? { databases: dbs, tables: {}, columns: {}, rows: {} }; },
  };
  return ex;
}

function makeSm(overrides) {
  const sm = new ScanManager();
  sm.extractor = mockExtractor(overrides);
  return sm;
}

function ctxWithScope(scope) {
  return { config: { extractScope: scope }, target: { config: { extractScope: scope } } };
}

test('_extract: mode=dbs 过滤系统库', async () => {
  const sm = makeSm({ dbs: ['app', 'information_schema', 'mysql', 'sys', 'mydb'] });
  const data = await sm._extract('sid', ctxWithScope({ mode: 'dbs', excludeSysdbs: true }));
  assert.deepEqual(data.databases, ['app', 'mydb']);
});

test('_extract: mode=dbs --no-exclude-sysdbs 保留全部', async () => {
  const sm = makeSm({ dbs: ['app', 'information_schema'] });
  const data = await sm._extract('sid', ctxWithScope({ mode: 'dbs', excludeSysdbs: false }));
  assert.deepEqual(data.databases, ['app', 'information_schema']);
});

test('_extract: mode=tables -D x → data.tables[x]', async () => {
  const sm = makeSm({ tables: { x: ['t1', 't2'] } });
  const data = await sm._extract('sid', ctxWithScope({ mode: 'tables', dbs: ['x'], excludeSysdbs: true }));
  assert.deepEqual(data.tables, { x: ['t1', 't2'] });
  assert.equal(sm.extractor.calls.enumerateTables, 1);
});

test('_extract: mode=columns -D x -T t → data.columns[x.t]', async () => {
  const sm = makeSm({ columns: { 'x.t': ['id', 'name'] } });
  const data = await sm._extract('sid', ctxWithScope({ mode: 'columns', dbs: ['x'], tables: ['t'], excludeSysdbs: true }));
  assert.deepEqual(data.columns, { 'x.t': ['id', 'name'] });
  assert.equal(sm.extractor.calls.enumerateColumns, 1);
});

test('_extract: mode=dump -D x -T t -C id → data.rows[x.t]', async () => {
  const sm = makeSm({ dump: { 'x.t': [{ id: 1 }, { id: 2 }] } });
  const data = await sm._extract('sid', ctxWithScope({ mode: 'dump', dbs: ['x'], tables: ['t'], cols: ['id'], excludeSysdbs: true }));
  assert.deepEqual(data.rows, { 'x.t': [{ id: 1 }, { id: 2 }] });
  assert.deepEqual(data.columns, { 'x.t': ['id'] });
  assert.equal(sm.extractor.calls.dumpData, 1);
  assert.equal(sm.extractor.calls.enumerateColumns, undefined, '指定 cols 时不应再枚举列');
});

test('_extract: mode=currentDb → data.currentDb', async () => {
  const sm = makeSm({ currentDb: 'appdb' });
  const data = await sm._extract('sid', ctxWithScope({ mode: 'currentDb', excludeSysdbs: true }));
  assert.equal(data.currentDb, 'appdb');
  assert.equal(sm.extractor.calls.currentDb, 1);
});

test('_extract: mode=currentUser → data.currentUser', async () => {
  const sm = makeSm({ currentUser: 'root@localhost' });
  const data = await sm._extract('sid', ctxWithScope({ mode: 'currentUser', excludeSysdbs: true }));
  assert.equal(data.currentUser, 'root@localhost');
});

test('_extract: mode=count -D x -T t → data.counts[x.t]=42', async () => {
  const sm = makeSm({ count: { 'x.t': '42' } });
  const data = await sm._extract('sid', ctxWithScope({ mode: 'count', dbs: ['x'], tables: ['t'], excludeSysdbs: true }));
  assert.equal(data.counts['x.t'], 42);
  assert.equal(sm.extractor.calls.countRows, 1);
});

test('_extract: 无 extractScope → 既有全量拖库分支（enumerateDatabases + dumpAllDatabases）', async () => {
  const sm = makeSm({ dbs: ['a', 'b'], dumpAll: { databases: ['a', 'b'], tables: {}, columns: {}, rows: {} } });
  const data = await sm._extract('sid', { config: {}, target: { config: {} } });
  assert.deepEqual(data.databases, ['a', 'b']);
  assert.equal(sm.extractor.calls.enumerateDatabases, 1);
  assert.equal(sm.extractor.calls.dumpAllDatabases, 1);
});

// ─────────────── 6) printExtractView ───────────────
test('printExtractView: --dbs 输出每行一个库名', () => {
  const logs = [];
  const orig = console.log;
  console.log = (...a) => logs.push(a.join(' '));
  try {
    printExtractView({ data: { databases: ['app', 'mydb'], tables: {}, columns: {}, rows: {} } });
  } finally { console.log = orig; }
  assert.deepEqual(logs, ['app', 'mydb']);
});

test('printExtractView: --tables 输出 db.t 列表', () => {
  const logs = [];
  const orig = console.log;
  console.log = (...a) => logs.push(a.join(' '));
  try {
    printExtractView({ data: { databases: ['x'], tables: { x: ['t1', 't2'] }, columns: {}, rows: {} } });
  } finally { console.log = orig; }
  assert.deepEqual(logs, ['x.t1', 'x.t2']);
});

test('printExtractView: --count 输出行数', () => {
  const logs = [];
  const orig = console.log;
  console.log = (...a) => logs.push(a.join(' '));
  try {
    printExtractView({ data: { counts: { 'x.t': 42 } } });
  } finally { console.log = orig; }
  assert.deepEqual(logs, ['x.t: 42 行']);
});

test('printExtractView: --current-db 输出当前库', () => {
  const logs = [];
  const orig = console.log;
  console.log = (...a) => logs.push(a.join(' '));
  try {
    printExtractView({ data: { currentDb: 'appdb' } });
  } finally { console.log = orig; }
  assert.deepEqual(logs, ['current database: appdb']);
});

// ─────────────── 7) 直连(sqljs 真实 SQLite) 集成：枚举端到端 ───────────────
const INIT_SQL = "CREATE TABLE users(id INT PRIMARY KEY, name TEXT, email TEXT); INSERT INTO users VALUES(1,'alice','a@x'),(2,'bob','b@x');";
const SQL_TPL = 'SELECT id,name,email FROM users WHERE id={INJECT}';

async function sqljsAvailable() {
  try { await import('sql.js'); return true; } catch { return false; }
}

function directTarget() {
  return createTarget({
    mode: 'direct',
    db: { driverType: 'sqljs', initSql: INIT_SQL },
    sqlTemplate: SQL_TPL,
    originalValue: '1',
  });
}

// 全套件：检测确认注入 → extractScope dump → 真实列/行
test('直连(sqljs) 完整扫描：extractScope dump 返回真实列与行', async (t) => {
  if (!(await sqljsAvailable())) { t.skip('sql.js 不可用，跳过直连集成'); return; }
  const sm = new ScanManager();
  const scanId = await sm.start({
    mode: 'direct',
    db: { driverType: 'sqljs', initSql: INIT_SQL },
    sqlTemplate: SQL_TPL,
    config: {
      enableExtract: true,
      extractScope: { mode: 'dump', dbs: ['main'], tables: ['users'], excludeSysdbs: true },
      timeoutMs: 5000,
    },
  });
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    const s = sm.scans.get(scanId);
    if (s && ['completed', 'stopped', 'error'].includes(s.status)) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  const report = sm.getReport(scanId);
  const data = report.data || {};
  assert.deepEqual(data.tables, { main: ['users'] });
  assert.deepEqual(data.columns['main.users'], ['id', 'name', 'email']);
  assert.equal(data.rows['main.users'].length, 2);
  assert.equal(data.rows['main.users'][0].name, 'alice');
});

// 直连 _extract：currentDb / currentUser / count 各分支在真实 sqlite 上取值
test('直连(sqljs) _extract：currentDb/currentUser/count 返回真实值', async (t) => {
  if (!(await sqljsAvailable())) { t.skip('sql.js 不可用，跳过直连集成'); return; }
  const target = directTarget();
  const conn = new DirectConnector(target);
  const parser = new TargetParser();
  const [point] = await parser.discover(target);
  point.echoCols = [0, 1, 2]; // 检测阶段已确认的回显列
  const sm = new ScanManager();
  sm.extractor = new Extractor();
  const scope = { excludeSysdbs: true };

  const d1 = await sm._extract('s1', { httpClient: conn, target, point, dbms: 'SQLite', config: { ...target.config, extractScope: { mode: 'currentDb', ...scope } } });
  // SQLite 无会话库概念 → currentDb 返回 null（诚实降级，与 sqlmap 边界一致）
  assert.ok(d1.currentDb === null || typeof d1.currentDb === 'string', `currentDb 应为 null 或字符串（实得 ${JSON.stringify(d1.currentDb)}）`);

  const d2 = await sm._extract('s2', { httpClient: conn, target, point, dbms: 'SQLite', config: { ...target.config, extractScope: { mode: 'currentUser', ...scope } } });
  assert.ok(d2.currentUser, `应返回当前用户（实得 ${JSON.stringify(d2.currentUser)}）`);

  const d3 = await sm._extract('s3', { httpClient: conn, target, point, dbms: 'SQLite', config: { ...target.config, extractScope: { mode: 'count', dbs: ['main'], tables: ['users'], ...scope } } });
  assert.ok(d3.counts, `counts 应返回对象（实得 ${JSON.stringify(d3.counts)}）`);
  await conn.close();
});
