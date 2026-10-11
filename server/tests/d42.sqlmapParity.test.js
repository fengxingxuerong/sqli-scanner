// [D42 2026-10-11 对标 sqlmap] 四件新能力单测：
//   --second-req（二阶触发整请求）/ --ignore-code（可信度判定忽略码）/
//   --randomize（注入请求随机化）/ --dump-format（拖库独立产物）+ --verify 开关。
// 引擎缝：SecondOrderDetector._trigger / supplementalRuns 编排门 / ScanValidityGuard.observe /
//   buildInjectionRequest / dumpFormat.formatDumpData（27 条既有测试钉实现，这里钉接线）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs, buildConfig } from '../bin/cli.js';
import { createTarget, createInjectionPoint } from '../src/engine/models.js';
import { buildInjectionRequest } from '../src/engine/injection.js';
import { ScanValidityGuard } from '../src/core/scanValidityGuard.js';
import { formatDumpData } from '../src/engine/dumpFormat.js';
import { guardSecondOrder } from '../src/api/scanGuard/objectGroups.js';
import { guardScalarsCore } from '../src/api/scanGuard/scalarsCore.js';

const tmp = mkdtempSync(join(tmpdir(), 'sqli-d42-'));
process.on?.('exit', () => {
  try { rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
});

// ===== --second-req：CLI 解析 → config.secondOrder.triggerRequest =====
test('CLI：--second-req 从抓包文件组装 triggerRequest（url/method/headers/body）', () => {
  const p = join(tmp, 'second-req.txt');
  writeFileSync(
    p,
    [
      'POST /admin/panel HTTP/1.1',
      'Host: target.example.com',
      'Cookie: SESS=abc123',
      'Content-Type: application/x-www-form-urlencoded',
      '',
      'page=1',
      '',
    ].join('\r\n'),
    'utf-8'
  );
  const config = buildConfig(parseArgs(['--second-req', p]));
  const tr = config.secondOrder.triggerRequest;
  assert.equal(config.secondOrder.enabled, true);
  assert.equal(tr.method, 'POST');
  assert.equal(tr.url, 'http://target.example.com/admin/panel');
  assert.equal(tr.headers.Cookie, 'SESS=abc123');
  assert.equal(tr.body, 'page=1');
});

test('CLI：--second-req 文件不存在/无请求行 → 显式抛错（不静默忽略）', () => {
  assert.throws(() => buildConfig(parseArgs(['--second-req', join(tmp, 'nope.txt')])), /读取失败|不存在/);
  const empty = join(tmp, 'empty-req.txt');
  writeFileSync(empty, '这不是请求文本\n', 'utf-8');
  assert.throws(() => buildConfig(parseArgs(['--second-req', empty])), /解析失败/);
});

test('REST 闸：triggerRequest 形状 clamp（method 大写化、headers 原型污染键过滤、body clamp）', () => {
  const config = {};
  guardSecondOrder(config, {
    secondOrder: {
      enabled: true,
      triggerRequest: {
        url: 'https://a.example.com/x',
        method: 'post',
        headers: { ok: '1', __proto__: 'evil', cookie: 'a=b' },
        body: 'x'.repeat(20000),
      },
    },
  });
  const tr = config.secondOrder.triggerRequest;
  assert.equal(tr.method, 'POST');
  assert.equal(tr.body.length, 16384);
  assert.equal(tr.headers.cookie, 'a=b');
  assert.ok(!Object.hasOwn(tr.headers, '__proto__'), '原型污染键不得成为自有属性');
});

test('REST 闸：triggerRequest 非法 URL → 回落 defaults（null），引擎按 URL 触发源走', () => {
  const config = {};
  guardSecondOrder(config, {
    secondOrder: { enabled: true, triggerRequest: { url: 'ftp://x/y', method: 'GET' } },
  });
  assert.equal(config.secondOrder.triggerRequest, null);
});

// ===== --ignore-code：ScanValidityGuard.observe 忽略集 =====
test('ignore-code：401 在忽略集内 → 不计 authHit，按业务响应计账', () => {
  const g = new ScanValidityGuard({ ignoreCodes: [401] });
  g.observe({ req: { url: 'http://t/?id=1' }, res: { status: 401, data: 'denied', headers: {} } });
  assert.equal(g.authChallengeHits, 0);
  assert.equal(g.nonChallengeHits, 1);
  assert.equal(g.ignoredHits, 1);
  // 403 不在忽略集 → 照常计拦截
  g.observe({ req: { url: 'http://t/?id=1' }, res: { status: 403, data: 'blocked', headers: {} } });
  assert.equal(g.blockHits, 1);
  assert.equal(g.ignoredHits, 1);
});

test('ignore-code：500 在忽略集内 → 不计 serverErr；未配置时 401/403/500 行为不变（零回归）', () => {
  const g = new ScanValidityGuard({ ignoreCodes: [500] });
  g.observe({ req: { url: 'http://t/?id=1' }, res: { status: 500, data: 'err', headers: {} } });
  assert.equal(g.serverErr, 0);
  assert.equal(g.ignoredHits, 1);
  const plain = new ScanValidityGuard({});
  plain.observe({ req: { url: 'http://t/?id=1' }, res: { status: 401, data: 'denied', headers: {} } });
  assert.equal(plain.authChallengeHits, 1);
  assert.equal(plain.ignoredHits, 0);
});

test('ignore-code：非法形态（0/越界/非整数）在构造器被过滤——0 是「网络失败」不可忽略', () => {
  const g = new ScanValidityGuard({ ignoreCodes: [0, 99, 700, 401.5, 'x', 403] });
  assert.deepEqual([...g.ignoreCodes].sort(), [403]);
});

test('CLI/REST：--ignore-code 与 REST ignoreCodes 透传', () => {
  const config = buildConfig(parseArgs(['--ignore-code', '401,403,xx']));
  assert.deepEqual(config.ignoreCodes, [401, 403]);
  const rest = {};
  guardScalarsCore(rest, { ignoreCodes: [401, 500, 99, 'x'] }, {});
  assert.deepEqual(rest.ignoreCodes, [401, 500]);
});

// ===== --randomize：buildInjectionRequest 出站随机化 =====
const rndTarget = (randomize) =>
  createTarget({
    url: 'http://t.example.com/page?id=1&session=abc&page=2',
    cookieParams: { sid: 's1', tracker: 't1' },
    headerParams: { 'X-Request-Id': 'r0', 'X-Trace': 'z' },
    config: { randomize },
  });

test('randomize：URL query / Cookie / 请求头的指定参数每请求变随机值，注入点自身不动', () => {
  const point = createInjectionPoint('url', 'id', '1');
  const req1 = buildInjectionRequest(rndTarget(['session', 'page', 'tracker', 'X-Request-Id']), point, "1' AND '1'='1");
  const req2 = buildInjectionRequest(rndTarget(['session', 'page', 'tracker', 'X-Request-Id']), point, "1' AND '1'='1");
  // 注入点自身原样携带 payload
  assert.ok(req1.url.includes('id=1%27'));
  // 列表内参数：两次请求值不同（每请求新鲜）且都不是原值
  for (const key of ['session', 'page']) {
    const v1 = new URL(req1.url).searchParams.get(key === 'session' ? 'session' : 'page');
    const v2 = new URL(req2.url).searchParams.get(key === 'session' ? 'session' : 'page');
    assert.ok(v1 && v1 !== 'abc' && v1 !== '2', `session/page 应被随机化（${key}=${v1}）`);
    assert.notEqual(v1, v2);
  }
  // Cookie：tracker 随机、sid 不在列表保持原值
  const ck1 = req1.headers.Cookie;
  assert.ok(/sid=s1/.test(ck1));
  assert.ok(!/tracker=t1/.test(ck1));
  // 头：X-Request-Id 随机、X-Trace 不在列表保持原值
  assert.equal(req1.headers['X-Trace'], 'z');
  assert.notEqual(req1.headers['X-Request-Id'], 'r0');
  assert.notEqual(req1.headers['X-Request-Id'], req2.headers['X-Request-Id']);
});

test('randomize：未配置 → 请求与旧行为逐字一致（零回归）', () => {
  const point = createInjectionPoint('url', 'id', '1');
  const req = buildInjectionRequest(rndTarget(undefined), point, "1'");
  assert.ok(req.url.includes('session=abc'));
  assert.ok(req.headers.Cookie.includes('tracker=t1'));
  assert.equal(req.headers['X-Request-Id'], 'r0');
});

test('randomize：注入点同名参数不被随机化（打断判定）；传输关键头不随机化', () => {
  const point = createInjectionPoint('url', 'session', 'abc');
  const req = buildInjectionRequest(rndTarget(['session']), point, "abc'");
  assert.ok(req.url.includes('session=abc%27'));
  const point2 = createInjectionPoint('url', 'id', '1');
  const t = rndTarget(['id']);
  t.headerParams['Content-Type'] = 'text/html';
  const req2 = buildInjectionRequest(t, point2, "1'");
  // 请求头的 content-type 恒不随机化
  assert.equal(req2.headers['Content-Type'], 'text/html');
});

test('randomize：表单伴随字段随机化', () => {
  const point = createInjectionPoint('body', 'comment', 'hi', {
    formValues: { comment: 'hi', page: '1', csrf: 'tok' },
  });
  const req = buildInjectionRequest(rndTarget(['page']), point, "hi'");
  const parsed = new URLSearchParams(req.data);
  assert.equal(parsed.get('page'), req.data && new URLSearchParams(req.data).get('page'));
  assert.notEqual(parsed.get('page'), '1');
  assert.equal(parsed.get('csrf'), 'tok'); // 不在列表保持原值
  assert.ok(/^hi'/.test(parsed.get('comment'))); // 注入值原样
});

// ===== --dump-format：产物层接线 =====
test('dump-format：CLI 归一化 + 非法值硬拒', () => {
  assert.equal(buildConfig(parseArgs(['--dump-format', 'CSV'])).dumpFormat, 'csv');
  assert.throws(() => buildConfig(parseArgs(['--dump-format', 'xlsx'])), /csv\/sql\/html\/json/);
});

test('dump-format：formatDumpData 三格式产物（sql 带表名、csv 带表头、html 带表格）', () => {
  const rows = [{ id: 1, name: 'a' }, { id: 2, name: 'b' }];
  const cols = ['id', 'name'];
  assert.ok(formatDumpData(rows, cols, 'users', 'sql').includes('INSERT INTO users'));
  assert.ok(formatDumpData(rows, cols, 'users', 'csv').includes('id,name'));
  assert.ok(formatDumpData(rows, cols, 'users', 'html').includes('<table'));
  const asJson = formatDumpData(rows, cols, 'users', 'json');
  assert.deepEqual(asJson, rows);
});

// ===== --verify / --no-verify =====
test('verify 开关：--no-verify 关 blindRobust.extractVerify；--verify 幂等；不传保持默认开', () => {
  const off = buildConfig(parseArgs(['--no-verify']));
  assert.equal(off.blindRobust.extractVerify, false);
  const on = buildConfig(parseArgs(['--verify']));
  assert.equal(on.blindRobust.extractVerify, true);
  const dflt = buildConfig(parseArgs([]));
  assert.equal(dflt.blindRobust, undefined); // 不写组键：默认由 defaults 浅合并兜底（extractVerify: true）
});
