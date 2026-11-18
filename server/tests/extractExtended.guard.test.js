// D300 guard：扩展拖库通道（二阶自动拖库 + 盲注 opt-in）判据。
// 反例可红：删 _d300 挂载 / 关掉二阶拖库调用 / 盲注默认开 / 适配器漏 URL payload ⇒ 下面对应用例红。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extractPhaseD300 } from '../src/engine/scan/extractExtended.js';
import { sanitizeExtractScope } from '../src/api/scanGuard/extractScope.js';

/** 最小 fake：只实现 extractPhaseD300 真正调用的契约面 */
function makeRun(opts = {}) {
  const extracted = { databases: [], tables: {}, columns: {}, rows: {}, counts: {} };
  const report = { summary: {} };
  const soVuln = {
    id: 'v-so', pointId: 'p-so', technique: 'second_order', dbms: 'MySQL',
    ...(opts.soCtx === false ? {} : { _d300: { pointId: 'p-so', triggerUrl: 'http://x/trigger', param: 'id' } }),
  };
  const sm = {
    _mapPool: async (items, fn) => { for (const it of items) await fn(it); },
    _mergeExtracted: (dst, src) => {
      if (!src) return;
      for (const k of ['databases', 'currentUser', 'currentDb', 'banner']) if (src[k]) dst[k] = src[k];
      for (const k of ['tables', 'columns', 'rows', 'counts']) if (src[k]) Object.assign(dst[k], src[k]);
    },
    getScanClient: () => ({}),
    extractor: {
      enumerateDatabases: async () => ['appdb'],
      dumpAllDatabases: async () => ({ tables: { appdb: ['users'] }, columns: { 'appdb.users': ['id', 'name'] }, rows: { 'appdb.users': [{ id: 1, name: 'admin' }] } }),
      extractBoolean: async (_ctx, expr) => `v(${expr})`,
    },
    secondOrderDetector: {
      _store: async () => {},
      _trigger: async () => '<pre>__S__admin__E__</pre>',
    },
  };
  const target = {
    config: { enableExtract: true, ...(opts.blindDump ? { extractScope: { blindDump: true } } : {}) },
    cookieParams: {},
  };
  return {
    sm, target, extracted, report, scanId: 'S1', s: { cancelled: false },
    finalVulns: opts.vulns || [soVuln],
    points: [{ id: 'p-so', param: 'id', actionUrl: 'http://x/store', originalValue: '1' }],
    foundByPoint: new Map(),
  };
}

test('D300-1 二阶命中：拖库结果合并进 extracted（库/表/行齐全）', async () => {
  const run = makeRun();
  await extractPhaseD300(run);
  assert.deepEqual(run.extracted.databases, ['appdb']);
  assert.deepEqual(run.extracted.tables.appdb, ['users']);
  assert.deepEqual(run.extracted.rows['appdb.users'], [{ id: 1, name: 'admin' }]);
});

test('D300-2 反例：vuln 无 _d300 上下文 ⇒ 不拖库（不凭 technique 名硬拖）', async () => {
  const run = makeRun({ soCtx: false });
  await extractPhaseD300(run);
  assert.deepEqual(run.extracted.databases, []);
  assert.deepEqual(run.extracted.rows, {});
});

test('D300-3 反例：enableExtract=false ⇒ 一阶与扩展都不跑', async () => {
  const run = makeRun();
  run.target.config.enableExtract = false;
  await extractPhaseD300(run);
  assert.deepEqual(run.extracted.databases, []);
});

test('D300-4 盲注 opt-in：默认关时 boolean 命中不提标量', async () => {
  const run = makeRun({ vulns: [{ id: 'v', pointId: 'p-bool', technique: 'boolean', dbms: 'MySQL' }] });
  await extractPhaseD300(run);
  assert.equal(run.extracted.currentUser, undefined);
});

test('D300-5 盲注 opt-in：blindDump=true 时提 currentUser/currentDb/banner', async () => {
  const run = makeRun({ blindDump: true, vulns: [{ id: 'v', pointId: 'p-bool', technique: 'boolean', dbms: 'MySQL' }] });
  await extractPhaseD300(run);
  assert.equal(run.extracted.currentUser, 'v(current_user())');
  assert.equal(run.extracted.currentDb, 'v(database())');
  assert.equal(run.extracted.banner, 'v(version())');
});

test('D300-6 二阶拖库把通道标记写进 report.summary，便于对外声明', async () => {
  const run = makeRun();
  await extractPhaseD300(run);
  assert.ok(Array.isArray(run.report.summary.d300Channels));
  assert.ok(run.report.summary.d300Channels.includes('extended-extract'));
});

test('D300-7 适配器：payload 在 URL query（伪点 location=url ⇒ 只在 req.url）也能取出并 store（解码逐字一致）', async () => {
  const run = makeRun();
  const stored = [];
  run.sm.secondOrderDetector._store = async (_c, _ctx, value) => { stored.push(value); };
  const payload = "1' UNION SELECT '__S__appdb__E__','x'-- -";
  run.sm.extractor.enumerateDatabases = async (dumpCtx) => {
    const res = await dumpCtx.httpClient.request({
      method: 'GET',
      url: `http://x/trigger?id=${encodeURIComponent(payload)}`,
      params: {},
      data: {},
    });
    return String(res?.data || '').includes('__S__') ? ['appdb'] : [];
  };
  run.sm.extractor.dumpAllDatabases = async () => ({
    databases: ['appdb'], tables: { appdb: ['users'] }, columns: {}, rows: { 'appdb.users': [{ id: 1 }] }, meta: null,
  });
  await extractPhaseD300(run);
  // URL 编码 → searchParams 解码后逐字还原（旧适配器只在 data/params 找 ⇒ payload 判 null ⇒ 拖库全空）
  assert.deepEqual(stored, [payload]);
  assert.deepEqual(run.extracted.rows['appdb.users'], [{ id: 1 }]);
  assert.ok(run.report.summary.d300Channels.includes('extended-extract'));
});

test('D300-8 反例：请求不含注入值（无 SELECT）⇒ 适配器诚实失败 {status:0}，不 store 不 trigger', async () => {
  const run = makeRun();
  let touched = 0;
  run.sm.secondOrderDetector._store = async () => { touched += 1; };
  run.sm.secondOrderDetector._trigger = async () => { touched += 1; return ''; };
  run.sm.extractor.enumerateDatabases = async (dumpCtx) => {
    const res = await dumpCtx.httpClient.request({ method: 'GET', url: 'http://x/trigger?id=1', params: {}, data: {} });
    assert.equal(res.status, 0);
    return [];
  };
  await extractPhaseD300(run);
  assert.equal(touched, 0, '无注入值的请求不得触发任何对目标的写/读');
  assert.deepEqual(run.extracted.databases, []);
});

test('D300-9 反例：拖库空结果（无库无行无标量）⇒ 不写 d300Channels（「跑了通道」≠「拖到了数据」）', async () => {
  const run = makeRun();
  run.sm.extractor.enumerateDatabases = async () => [];
  run.sm.extractor.dumpAllDatabases = async () => ({ databases: [], tables: {}, columns: {}, rows: {}, meta: null });
  await extractPhaseD300(run);
  assert.equal(run.report.summary.d300Channels, undefined);
  assert.deepEqual(run.extracted.databases, []);
});

test('D300-10 盲注只提回 banner（方言仅版本串可用）也算有效提取，标记通道', async () => {
  const run = makeRun({ blindDump: true, vulns: [{ id: 'v', pointId: 'p-bool', technique: 'boolean', dbms: 'MySQL' }] });
  run.sm.extractor.extractBoolean = async (_ctx, expr) => (/version/i.test(String(expr)) ? '8.0.32' : null);
  await extractPhaseD300(run);
  assert.equal(run.extracted.banner, '8.0.32');
  assert.equal(run.extracted.currentUser, undefined, 'null 结果不得写成字段');
  assert.deepEqual(run.report.summary.d300Channels, ['extended-extract']);
});

test('D300-11 REST 白名单：blindDump 可与 mode 叠加、可无 mode 单传；非布尔 true 不收', () => {
  assert.deepEqual(sanitizeExtractScope({ blindDump: true }), { blindDump: true });
  assert.deepEqual(sanitizeExtractScope({ mode: 'dumpAll', blindDump: true }), { mode: 'dumpAll', blindDump: true });
  assert.deepEqual(sanitizeExtractScope({ mode: 'dbs' }), { mode: 'dbs' }, '不带 blindDump 不写该键（零行为变化）');
  assert.equal(sanitizeExtractScope({ mode: 'nope', blindDump: 'yes' }), undefined, '字符串 "yes" 不是 true');
  assert.equal(sanitizeExtractScope({ mode: 'nope' }), undefined);
  assert.equal(sanitizeExtractScope({}), undefined, 'mode 缺失且无 blindDump = 不启用（既有口径不变）');
});

test('D300-12 dbms 兜底链：二阶命中无 vuln.dbms ⇒ 依次回落 run.dbms（真机实证：二阶指纹常不出来）', async () => {
  const run = makeRun({
    vulns: [{ id: 'v-so', pointId: 'p-so', technique: 'second_order', _d300: { pointId: 'p-so', triggerUrl: 'http://x/trigger', param: 'id' } }],
  });
  run.dbms = 'PostgreSQL';
  let seenDbms = 'sentinel';
  run.sm.extractor.enumerateDatabases = async (dumpCtx) => { seenDbms = dumpCtx.dbms; return []; };
  await extractPhaseD300(run);
  assert.equal(seenDbms, 'PostgreSQL');
});

test('D300-13 dbms 兜底链：盲注标量提取回落 config.dbms（用户 --dbms 强制）', async () => {
  const run = makeRun({
    blindDump: true,
    vulns: [{ id: 'v', pointId: 'p-bool', technique: 'boolean', dbms: null }],
  });
  run.target.config.dbms = 'MySQL';
  let seenDbms = 'sentinel';
  run.sm.extractor.extractBoolean = async (ctx, expr) => { seenDbms = ctx.dbms; return `v(${expr})`; };
  await extractPhaseD300(run);
  assert.equal(seenDbms, 'MySQL');
  assert.equal(run.extracted.currentUser, 'v(current_user())');
});

test('D300-14 伪点原值是不命中哨兵：触发页带 LIMIT 1 时标记行不被原值行截掉（DVWA sqli high 实证）', async () => {
  const run = makeRun();
  const seen = [];
  run.sm.extractor.enumerateDatabases = async (dumpCtx) => {
    seen.push({ orig: dumpCtx.point.originalValue, actionUrl: dumpCtx.point.actionUrl });
    return ['appdb'];
  };
  run.sm.extractor.dumpAllDatabases = async () => ({ databases: ['appdb'], tables: {}, columns: {}, rows: {}, meta: null });
  await extractPhaseD300(run);
  assert.ok(seen.length >= 1, '二阶拖库应当真的跑过枚举');
  assert.notEqual(seen[0].orig, '1', '原值不得是 1——会命中触发页首行，LIMIT 1 截掉标记行');
  assert.equal(seen[0].orig, '999999999');
});
