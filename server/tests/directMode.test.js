// D 方向：直连模式（对标 sqlmap -d）最小适配回归
// 验证：createTarget / TargetParser / buildInjectionRequest 的 direct 分支；
// DirectConnector 与 HttpClient 同契约（req.sql 经 driver 直连执行）；
// 直连通道下 union / error / boolean 检测链路被复用并命中（零依赖 MemoryRecordDriver + 真实 SqlJsDriver 双验证）。
// 注：time 完整采样（TimeBlindDetector）因固定 SLEEP 多次采样过慢，未纳入本单测；
//     直连 time 通道已由「内存驱动 SLEEP 延迟特征 + DirectConnector 契约」覆盖。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTarget, createInjectionPoint } from '../src/engine/models.js';
import { TargetParser } from '../src/engine/TargetParser.js';
import { buildInjectionRequest } from '../src/engine/injection.js';
import { DirectConnector } from '../src/core/directConnector.js';
import { UnionDetector } from '../src/engine/detectors/UnionDetector.js';
import { ErrorDetector } from '../src/engine/detectors/ErrorDetector.js';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { ScanManager } from '../src/engine/ScanManager.js';

const SQL_TPL = 'SELECT id,name FROM users WHERE id={INJECT}';
const INIT_SQL = "CREATE TABLE users(id INT, name TEXT); INSERT INTO users VALUES(1,'alice'),(2,'bob');";

function directTarget(overrides = {}) {
  return createTarget({
    mode: 'direct',
    db: { driverType: 'memory' },
    sqlTemplate: SQL_TPL,
    originalValue: '1',
    ...overrides,
  });
}

function directPoint(tpl = SQL_TPL) {
  return createInjectionPoint('direct', '__INJECT__', '1', { sqlTemplate: tpl });
}

function directCtx(target, point, connector) {
  return {
    httpClient: connector,
    target,
    point,
    dbms: null,
    config: { ...target.config, timeoutMs: 5000, timeThresholdMs: 800 },
  };
}

// ===== 模型 / 解析 / 构造（direct 分支）=====
test('D: createTarget direct 缺 sqlTemplate 抛错', () => {
  assert.throws(() => createTarget({ mode: 'direct', db: {}, originalValue: '1' }));
});

test('D: createTarget direct 正常产出 mode/db/sqlTemplate', () => {
  const t = directTarget();
  assert.equal(t.mode, 'direct');
  assert.ok(t.db);
  assert.equal(t.sqlTemplate, SQL_TPL);
  assert.equal(t.originalValue, '1');
});

test('D: TargetParser direct 仅产出 1 个注入点且透传 sqlTemplate', async () => {
  const parser = new TargetParser();
  const points = await parser.discover(directTarget());
  assert.equal(points.length, 1);
  assert.equal(points[0].location, 'direct');
  assert.equal(points[0].sqlTemplate, SQL_TPL);
});

test('D: buildInjectionRequest direct 把 payload 拼进 {INJECT}', () => {
  const target = directTarget();
  const point = directPoint();
  const req = buildInjectionRequest(target, point, "1' UNION SELECT 'a','b");
  assert.equal(req.sql, "SELECT id,name FROM users WHERE id=1' UNION SELECT 'a','b");
});

// ===== Connector 契约 + 内存驱动特征响应 =====
test('D: DirectConnector 契约对齐 HttpClient（status/headers/data）', async () => {
  const c = new DirectConnector(directTarget());
  const res = await c.request({ sql: 'SELECT id,name FROM users WHERE id=1' });
  assert.equal(res.status, 200);
  assert.deepEqual(res.headers, {});
  assert.ok(res.data.includes('alice'));
  await c.close();
});

test('D: 内存驱动 union 回显 / error 被捕获为 body / boolean 差异 / time 延迟', async () => {
  const c = new DirectConnector(directTarget());
  // union 回显
  const u = await c.request({ sql: "SELECT id,name FROM users WHERE id=1 UNION SELECT 'X','Y'" });
  assert.ok(u.data.includes('X\tY'), 'union 应回显注入列');
  // error 被捕获为 body（含 SQL error code，命中 ERROR_SIG）
  const e = await c.request({ sql: "SELECT id,name FROM users WHERE id=1 AND 1=CAST((SELECT 'a') AS INTEGER)" });
  assert.ok(e.data.includes('SQL error code'), '报错注入应被捕获为 body');
  // boolean 差异：真条件有数据，假条件空
  const bT = await c.request({ sql: "SELECT id,name FROM users WHERE id=1 AND '1'='1'" });
  const bF = await c.request({ sql: "SELECT id,name FROM users WHERE id=1 AND '1'='2'" });
  assert.ok(bT.data.includes('alice'), '布尔真应有数据');
  assert.ok(!bF.data.includes('alice'), '布尔假应无数据');
  // time 延迟（SLEEP(1) 真实延迟）
  const t0 = Date.now();
  await c.request({ sql: 'SELECT 1; SELECT SLEEP(1)' });
  assert.ok(Date.now() - t0 >= 900, 'SLEEP(1) 应延迟约 1s');
  await c.close();
});

// ===== 检测器级端到端（直连通道复用检测链路）=====
test('D: 端到端 UnionDetector 直连命中（MemoryRecordDriver）', async () => {
  const target = directTarget();
  const point = directPoint();
  const c = new DirectConnector(target);
  const res = await new UnionDetector().detect(directCtx(target, point, c));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'union');
  await c.close();
});

test('D: 端到端 ErrorDetector 直连命中（MemoryRecordDriver）', async () => {
  const target = directTarget();
  const point = directPoint();
  const c = new DirectConnector(target);
  const res = await new ErrorDetector().detect(directCtx(target, point, c));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'error');
  await c.close();
});

test('D: 端到端 BooleanBlindDetector 直连命中（MemoryRecordDriver）', async () => {
  const target = directTarget();
  const point = directPoint();
  const c = new DirectConnector(target);
  const res = await new BooleanBlindDetector().detect(directCtx(target, point, c));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'boolean');
  await c.close();
});

// ===== 真实 SQLite（sql.js）端到端 =====
test('D: 真实 SQLite 端到端 UnionDetector 直连命中（SqlJsDriver）', async () => {
  const target = directTarget({ db: { driverType: 'sqljs', initSql: INIT_SQL } });
  const point = directPoint();
  const c = new DirectConnector(target);
  const res = await new UnionDetector().detect(directCtx(target, point, c));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'union');
  await c.close();
});

// [D211 口径修正] 本条原先以「注入带引号 ⇒ SQLite 报 unrecognized token」判定报错注入命中。
// 取证：在真实 SQLite 上，payload 与它的无害引号变体（`1'-- -`）**报的是同一条签名**
// （unrecognized token）—— 即报错来自「引号破坏了语法」，而 extractvalue 等 payload 函数
// **从未被执行**（SQLite 没有这些函数）。按 D211 新判据，这不该算报错注入：
// 报成 error 会暗示「可从报错中取数」，而事实不能。
// 数值上下文的点由 boolean/union 通道接住（见 directMode 的 boolean 直连用）。
const STR_TPL = "SELECT id,name FROM users WHERE name='{INJECT}'";

test('D: 真实 SQLite 直连 —— 引号语法错误不再判为报错注入（D211 归因）', async () => {
  const target = directTarget({ db: { driverType: 'sqljs', initSql: INIT_SQL } });
  const point = directPoint();
  const c = new DirectConnector(target);
  const res = await new ErrorDetector().detect(directCtx(target, point, c));
  assert.equal(res.vulnerable, false, '仅有引号引起的语法错误不得判为报错注入');
  await c.close();
});

test('D: 真实 SQLite 端到端 ErrorDetector 直连命中 —— 字符串上下文（SqlJsDriver）', async () => {
  // 与上一条的差别只在**上下文**：这里是字符串包裹（WHERE name='...'），
  // payload 的引号能闭合 ⇒ SQL 合法 ⇒ payload 函数真的被执行并报错回显
  // （SQLite 报 no such function）。这才是报错注入应有的证据形态。
  const target = directTarget({ db: { driverType: 'sqljs', initSql: INIT_SQL }, sqlTemplate: STR_TPL });
  const point = directPoint(STR_TPL);
  const c = new DirectConnector(target);
  const res = await new ErrorDetector().detect(directCtx(target, point, c));
  assert.equal(res.vulnerable, true);
  assert.equal(res.technique, 'error');
  await c.close();
});

// ===== ScanManager 连接器选择 =====
test('D: ScanManager.getConnector direct→DirectConnector，http→HttpClient 单例', () => {
  const sm = new ScanManager();
  assert.ok(sm.getConnector(directTarget()) instanceof DirectConnector);
  const h = createTarget({ url: 'http://x/?q=1' });
  assert.equal(sm.getConnector(h), sm.httpClient);
});
