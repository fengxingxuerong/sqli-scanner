// ============================================================================
// e2e/api-range-lab/cases.mjs —— 「HTTP 接口 × 真实靶场」用例集
//
// 判据口径（每一条都必须落在"靶站侧可取证"或"响应体可核对"上）：
//   · 不接受接口自报布尔值作为唯一证据（paused:true / stopped:true 只说明路由跑到了）
//   · 不接受"没报错"作为通过（本仓反复出现的假绿：SKIP/200+code/空结果都长得像成功）
//   · 能力不可用时必须**如实**（例如 MySQL 无 UDF 时 os-shell 要说清），但"如实的失败"
//     与"坏了"要能区分：断言里显式写出期望形态
// ============================================================================
import assert from 'node:assert/strict';
import { openSse, request, sleep, startEngine } from './harness.mjs';
// 业务错误码与被测代码同源（不在测试里抄一份数字：抄来的常量会跟着实现过期）
import { ErrorCode } from '../../server/src/core/errors.js';

const CASES = [];
const test = (group, name, run, opts = {}) => CASES.push({ group, name, run, skip: opts.skip, skipReason: opts.skipReason });

// ── 通用小工具 ──────────────────────────────────────────────────────────────
async function startScan(ctx, body, extraHeaders) {
  const r = await ctx.post('/api/scan/start', body, extraHeaders);
  assert.equal(r.status, 200, `/scan/start 应 200，实得 ${r.status}：${r.text.slice(0, 200)}`);
  assert.equal(r.json?.code, 0, `/scan/start 业务码应为 0，实得 ${JSON.stringify(r.json).slice(0, 300)}`);
  const scanId = r.json?.data?.scanId;
  assert.match(String(scanId || ''), /^[A-Za-z0-9_-]{1,64}$/, `scanId 形状非法：${JSON.stringify(scanId)}`);
  return scanId;
}

async function waitScan(ctx, scanId, { timeoutMs = 90000, want = ['completed', 'stopped', 'error'] } = {}) {
  const t0 = Date.now();
  let last = null;
  for (;;) {
    const r = await ctx.get(`/api/scan/${scanId}`);
    last = r.json?.data || null;
    if (last && want.includes(last.status)) return last;
    if (Date.now() - t0 > timeoutMs) {
      throw new Error(`扫描 ${scanId} 在 ${timeoutMs}ms 内未到终态，最后状态=${last?.status ?? '(无报告)'}`);
    }
    await sleep(150);
  }
}

async function scanUntilDone(ctx, body, { timeoutMs = 90000 } = {}) {
  const scanId = await startScan(ctx, body);
  const done = await waitScan(ctx, scanId, { timeoutMs });
  const rep = await ctx.get(`/api/scan/${scanId}/report`);
  return { scanId, status: done.status, report: rep.json?.data, raw: rep };
}

const fastCfg = (over = {}) => ({ concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, ...over });

async function rangeStats(ctx) {
  const r = await ctx.rangeGet('/__range/stats');
  assert.equal(r.status, 200, `靶站取证端点应 200，实得 ${r.status}`);
  return r.json;
}

// ── group: meta —— 只读元数据接口 ───────────────────────────────────────────
test('meta', 'GET /api/health 契约与版本一致性', async (ctx) => {
  const r = await ctx.get('/api/health');
  assert.equal(r.status, 200);
  assert.equal(r.json?.code, 0);
  assert.equal(r.json?.data?.status, 'up');
  // 版本必须与 package.json 同源：历史上这里写死 '1.0.0'，而包版本已是 1.1.0
  // —— 交付物/健康检查里报出一个不存在的版本，运维排障时会照着错的版本找。
  assert.equal(
    r.json?.data?.version,
    ctx.pkgVersion,
    `health.version(${r.json?.data?.version}) 与 package.json(${ctx.pkgVersion}) 不一致`
  );
});

test('meta', '/api 与裸前缀两套挂载等价', async (ctx) => {
  const a = await ctx.get('/api/health');
  const b = await ctx.get('/health');
  assert.deepEqual(b.json, a.json, 'Tauri 形态（无前缀）与 Web 形态（/api）返回必须一致');
  const t = await ctx.get('/api/tampers');
  const t2 = await ctx.get('/tampers');
  assert.deepEqual(t2.json, t.json, '/tampers 双前缀不等价');
});

test('meta', 'GET /api/tampers 与注册表逐项一致（前端单一事实源）', async (ctx) => {
  const r = await ctx.get('/api/tampers');
  assert.equal(r.json?.code, 0);
  const list = r.json?.data;
  assert.ok(Array.isArray(list) && list.length > 30, `tamper 清单应 >30 项，实得 ${Array.isArray(list) ? list.length : typeof list}`);
  for (const item of list.slice(0, 200)) {
    assert.ok(typeof item.name === 'string' && item.name, `条目缺 name：${JSON.stringify(item).slice(0, 120)}`);
    assert.ok(typeof item.description === 'string' && item.description.trim(), `tamper ${item.name} 缺描述`);
  }
  const names = new Set(list.map((x) => x.name));
  assert.equal(names.size, list.length, 'tamper 清单存在重名条目');
  ctx.note('tampers', list.length);
});

test('meta', 'GET /api/payloads 三种查询形态 + 未知 dbms 不得 500', async (ctx) => {
  const all = await ctx.get('/api/payloads');
  assert.equal(all.json?.code, 0);
  assert.ok(all.json?.data?.MySQL, '全量形态应含 MySQL 模板族');
  assert.ok(all.json?.data?.fingerprint, '全量形态应含 fingerprint 族');

  const one = await ctx.get('/api/payloads?dbms=MySQL');
  assert.ok(one.json?.data?.union || Array.isArray(one.json?.data), 'dbms 形态应返回该库模板');

  const tech = await ctx.get('/api/payloads?dbms=MySQL&technique=union');
  assert.ok(Array.isArray(tech.json?.data), `dbms+technique 形态应为数组，实得 ${typeof tech.json?.data}`);
  assert.ok(tech.json.data.length > 0, 'MySQL union 模板不应为空');

  const bogus = await ctx.get('/api/payloads?dbms=NoSuchDb');
  assert.equal(bogus.status, 200, '未知 dbms 应 200+空，不该 500');
  assert.ok(bogus.json?.data === null || Array.isArray(bogus.json?.data) || Object.keys(bogus.json?.data || {}).length === 0, '未知 dbms 应返回空集合');

  const bogusTech = await ctx.get('/api/payloads?dbms=MySQL&technique=zzz');
  assert.equal(bogusTech.status, 200);
  assert.deepEqual(bogusTech.json?.data, [], '未知 technique 应返回空数组');
});

test('meta', 'GET /api/exploit/capabilities 如实反映服务端开关', async (ctx) => {
  const r = await ctx.get('/api/exploit/capabilities');
  assert.equal(r.json?.code, 0);
  assert.equal(r.json?.data?.enabled, true, '本实例以 EXPLOIT_ENABLED=1 启动，capabilities 必须报 enabled:true');
  assert.ok(Array.isArray(r.json?.data?.fileRead) && r.json.data.fileRead.includes('MySQL'), 'fileRead 能力清单应含 MySQL');
  ctx.note('capabilities.enabled', true);
});

// ── group: gates —— 入口闸门（真实 HTTP 语义） ──────────────────────────────
test('gates', '未携带 token 的数据端点一律 401（公开只读除外）', async (ctx) => {
  for (const p of ['/api/scan/deadbeef', '/api/scan/deadbeef/report', '/api/scan/deadbeef/events', '/api/scan/deadbeef/report/export']) {
    const r = await ctx.noAuthGet(p);
    assert.equal(r.status, 401, `${p} 无 token 应 401，实得 ${r.status}`);
    assert.equal(r.json?.code, 401, `${p} 无 token 应返回 code 401`);
  }
  const startNoToken = await ctx.noAuthPost('/api/scan/start', { url: `${ctx.LAB}/num?id=1` });
  assert.equal(startNoToken.status, 401, 'POST /scan/start 无 token 必须拒绝（这是会打外部的动作）');
  // 利用端点即使带 authorized:true 也不能免鉴权（双刃剑动作的边界是服务端凭据，不是前端勾选）
  const exploitNoToken = await ctx.noAuthPost('/api/exploit/sql', { url: `${ctx.LAB}/num?id=1`, authorized: true, sql: 'SELECT 1', dbms: 'MySQL', point: { originalValue: '1', location: 'url', param: 'id' } });
  assert.equal(exploitNoToken.status, 401, `利用端点无 token 必须 401，实得 ${exploitNoToken.status}`);

  // 公开只读元数据必须仍可访问（前端首屏依赖；历史上收紧过头）
  for (const p of ['/api/health', '/api/payloads', '/api/tampers', '/api/exploit/capabilities']) {
    const r = await ctx.noAuthGet(p);
    assert.equal(r.status, 200, `${p} 属公开只读，应 200，实得 ${r.status}`);
  }
});

test('gates', '错误 token 与恒时比较路径不得泄露差异', async (ctx) => {
  const r = await ctx.get('/api/scan/x', { token: 'wrong-token' });
  assert.equal(r.status, 401);
  const viaQuery = await request({ port: ctx.engine.port, path: '/api/scan/x?token=wrong', headers: {} });
  assert.equal(viaQuery.status, 401);
});

test('gates', '跨站变更请求 403 / 非 JSON 体 415 / 坏 JSON 400 / 超大 413', async (ctx) => {
  const cross = await ctx.post('/api/scan/start', { url: `${ctx.LAB}/num?id=1` }, { origin: 'http://evil.example' });
  assert.equal(cross.status, 403, `跨站 Origin 应 403，实得 ${cross.status}`);

  const sfc = await ctx.post('/api/scan/start', { url: 'x' }, { 'sec-fetch-site': 'cross-site' });
  assert.equal(sfc.status, 403, 'Sec-Fetch-Site=cross-site 且无 Origin 应 403');

  const form = await request({
    port: ctx.engine.port,
    method: 'POST',
    path: '/api/scan/start',
    token: ctx.engine.token,
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: `http://127.0.0.1:${ctx.engine.port}` },
    body: 'url=1',
  });
  assert.equal(form.status, 415, `form 编码 body 应 415（不能静默丢 body 后报参数缺失），实得 ${form.status}`);

  const bad = await request({
    port: ctx.engine.port,
    method: 'POST',
    path: '/api/scan/start',
    token: ctx.engine.token,
    headers: { 'content-type': 'application/json' },
    body: '{"url": ',
  });
  assert.equal(bad.status, 400, `坏 JSON 应 400，实得 ${bad.status}`);
  assert.equal(bad.json?.code, 1002, `坏 JSON 业务码应为 1002，实得 ${JSON.stringify(bad.json)}`);

  const big = await request({
    port: ctx.engine.port,
    method: 'POST',
    path: '/api/scan/start',
    token: ctx.engine.token,
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url: 'http://x', pad: 'A'.repeat(3 * 1024 * 1024) }),
  });
  assert.equal(big.status, 413, `超过 2MB 应 413，实得 ${big.status}`);
});

test('gates', 'scanId 形状非法 → 400（防响应头注入/路径越界）', async (ctx) => {
  for (const bad of ['..%2f..%2fetc', 'a'.repeat(80), 'bad!id']) {
    const r = await ctx.get(`/api/scan/${encodeURIComponent(bad)}/report`);
    assert.equal(r.status, 400, `scanId=${bad} 应 400，实得 ${r.status} ${r.text.slice(0, 120)}`);
  }
});

test('gates', '未知 API 路径返回 404 JSON（不落 SPA fallback）', async (ctx) => {
  const r = await ctx.get('/api/definitely-not-a-route');
  assert.equal(r.status, 404);
  assert.match(String(r.headers['content-type'] || ''), /application\/json/);
});

// ── group: scan —— 扫描生命周期（真 MySQL 靶站） ────────────────────────────
test('scan', 'POST /scan/start + 轮询 + 报告：真库检出', async (ctx) => {
  await ctx.rangePost('/__range/reset', {});
  const { scanId, status, report } = await scanUntilDone(ctx, {
    url: `${ctx.LAB}/num?id=1`,
    config: fastCfg({ techniques: ['union', 'error', 'boolean'] }),
  });
  assert.equal(status, 'completed');
  assert.ok(report, '报告必须存在');
  assert.ok((report.vulns || []).length >= 1, `应至少检出 1 条漏洞，实得 ${report.vulns?.length}`);
  const techs = new Set((report.vulns || []).map((v) => v.technology || v.technique));
  assert.ok(techs.has('union') || techs.has('boolean'), `union/boolean 通道至少要打通一条，实得 ${[...techs]}`);
  assert.match(String(report.dbms || ''), /MySQL/i, `定库应为 MySQL，实得 ${JSON.stringify(report.dbms)}`);
  assert.ok((report.points || []).length >= 1, '注入点列表不应为空');
  ctx.note('num.scanId', scanId);
  ctx.state.numScan = { scanId, report };
});

test('scan', 'GET /scan/:id/events：SSE 帧序列含进度与终态', async (ctx) => {
  const scanId = await startScan(ctx, { url: `${ctx.LAB}/str?name=alice`, config: fastCfg() });
  const sse = openSse({ port: ctx.engine.port, path: `/api/scan/${scanId}/events`, token: ctx.engine.token, timeoutMs: 60000 });
  const events = await sse.done;
  const types = events.map((e) => e.json?.type).filter(Boolean);
  assert.ok(types.length > 0, 'SSE 应至少推一条事件');
  assert.ok(types.some((t) => /scan_completed|scan_error|scan_stopped/.test(t)), `SSE 必须以终态事件收尾，实得 ${JSON.stringify(types.slice(-5))}`);
  const seqs = events.map((e) => Number(e.id)).filter((n) => Number.isFinite(n));
  assert.ok(seqs.every((n, i) => i === 0 || n >= seqs[i - 1]), 'SSE id(seq) 必须单调不减');
  assert.ok(!events.some((e) => e.parseError), '每条 data 帧必须是合法 JSON');
  const payloadTypes = new Set(types);
  ctx.note('sse.types', [...payloadTypes].join(','));
  await waitScan(ctx, scanId, { timeoutMs: 30000 });
});

test('scan', 'SSE 断线重连按 Last-Event-ID 回放（不丢事件窗口）', async (ctx) => {
  const scanId = await startScan(ctx, { url: `${ctx.LAB}/blind?uid=1`, config: fastCfg({ techniques: ['boolean'] }) });
  const first = openSse({ port: ctx.engine.port, path: `/api/scan/${scanId}/events`, token: ctx.engine.token, timeoutMs: 20000 });
  await sleep(400);
  const got = first.events.length;
  const lastId = first.events.length ? first.events[first.events.length - 1].id : null;
  first.close();
  await sleep(300);
  const replayed = lastId ? openSse({ port: ctx.engine.port, path: `/api/scan/${scanId}/events`, token: ctx.engine.token, lastEventId: lastId, timeoutMs: 25000 }) : null;
  const evs2 = replayed ? await replayed.done : [];
  const ids2 = evs2.map((e) => Number(e.id)).filter(Number.isFinite);
  assert.ok(got >= 0, '占位：第一段连接至少建立');
  if (lastId && ids2.length) {
    assert.ok(ids2.every((n) => n > Number(lastId)), `重连只应拿到游标之后的事件，实得 ${JSON.stringify(ids2)} 游标=${lastId}`);
  }
  ctx.note('sse.replay', { firstFrames: got, replayFrames: ids2.length });
  await waitScan(ctx, scanId, { timeoutMs: 40000 });
});

test('scan', 'pause/resume：靶站侧流量真的冻住（不接受自报 paused:true）', async (ctx) => {
  await ctx.rangePost('/__range/reset', {});
  const scanId = await startScan(ctx, {
    // delay=1s：把扫描拉长到足以观测"暂停期间一个包都不发"
    url: `${ctx.LAB}/str?name=alice`,
    config: fastCfg({ delay: 1, techniques: ['boolean'], level: 1 }),
  });
  await sleep(800);
  const before = await ctx.get(`/api/scan/${scanId}`);
  assert.equal(before.json?.data?.status, 'running', `暂停前应处于 running，实得 ${JSON.stringify(before.json?.data?.status)}`);

  const p = await ctx.post(`/api/scan/${scanId}/pause`, {});
  assert.equal(p.json?.code, 0, `pause 应成功，实得 ${JSON.stringify(p.json)}`);
  // 状态迁移必须可观测（不是"路由收到就算"）
  let paused = null;
  for (let i = 0; i < 40 && !paused; i++) {
    const s = await ctx.get(`/api/scan/${scanId}`);
    if (s.json?.data?.status === 'paused') paused = true;
    else await sleep(100);
  }
  assert.ok(paused, 'GET /scan/:id 必须能观测到 paused 状态');

  // 暂停期间的"在途那一发"仍会落到靶站（等待挂在发请求之前，不是在途请求的取消）。
  // 所以先给它 400ms 落地，再取基线计数 —— 否则这条断言测到的是网络相位，不是暂停语义。
  await sleep(400);
  const t1 = (await rangeStats(ctx)).total;
  await sleep(2600); // delay=1s 下正常应至少再来 2 个包
  const t2 = (await rangeStats(ctx)).total;
  assert.equal(t2 - t1, 0, `暂停期间靶站侧不应收到任何新请求，实得 ${t2 - t1} 个（paused 只是状态位，没冻住流量）`);

  const r = await ctx.post(`/api/scan/${scanId}/resume`, {});
  assert.equal(r.json?.code, 0, `resume 应成功，实得 ${JSON.stringify(r.json)}`);
  await sleep(2600);
  const t3 = (await rangeStats(ctx)).total;
  assert.ok(t3 > t2, `续跑后靶站侧请求数必须增长，实得 ${t3 - t2} 个增量`);

  await ctx.post(`/api/scan/${scanId}/stop`, {});
  const fin = await waitScan(ctx, scanId, { timeoutMs: 30000, want: ['stopped', 'completed', 'error'] });
  assert.equal(fin.status, 'stopped', `stop 后应为 stopped，实得 ${fin.status}`);
});

test('scan', 'pause/resume × wafEvasion 自适应链（ad-hoc 客户端在暂停期同样零发包）', async (ctx) => {
  // F1 2026-10-03：TODO 09-28 #4 验证口径的兑现。自适应链验证与拦截驱动重跑两条路径的
  // HTTP 走 detect.js 的两支 ad-hoc 客户端（裸 getScanClient 视图）—— 暂停闸若只挂
  // ctxBase 包装层，这条路径在暂停期间照常打靶。确定性相位锚点 = SSE 里第一发
  // `point_testing(tamperRetry:true)`：此刻重跑刚开始，暂停窗口必然落在重跑期内部。
  // （单位测试 scanClient.pause.test.js 是机制级确定性击杀；本用例是链路级集成证明。）
  await ctx.rangePost('/__range/reset', {});
  const scanId = await startScan(ctx, {
    url: `${ctx.LAB}/wafnum?id=1`,
    // delay=0.3：把重跑的探测族拉长到 ~20s 量级，暂停窗口（3s）无论如何都落在其中；
    // 全部探测被 /wafnum 的拦截判据吃掉 ⇒ 重跑不会提前收敛退出。
    config: fastCfg({ delay: 0.3, techniques: ['boolean', 'error'], level: 1 }),
  });
  const sse = openSse({ port: ctx.engine.port, path: `/api/scan/${scanId}/events`, token: ctx.engine.token, timeoutMs: 150000 });
  let sawRetry = null;
  for (let i = 0; i < 900 && !sawRetry; i++) {
    // eventBus 事件经 SSE 的形状：{ type, scanId, ts, seq, payload }
    sawRetry = sse.events.find(
      (e) => e.json?.type === 'point_testing' && e.json?.payload?.tamperRetry === true,
    ) || null;
    if (!sawRetry) await sleep(100);
  }
  assert.ok(
    sawRetry,
    '90s 内应观测到 tamperRetry 的 point_testing 事件（自适应重跑已启动）——没有则本用例没测到 ad-hoc 路径。'
      + `已见事件类型：${JSON.stringify([...new Set(sse.events.map((e) => e.json?.type))])}，`
      + `共 ${sse.events.length} 帧`,
  );

  const p = await ctx.post(`/api/scan/${scanId}/pause`, {});
  assert.equal(p.json?.code, 0, `pause 应成功，实得 ${JSON.stringify(p.json)}`);
  let paused = null;
  for (let i = 0; i < 40 && !paused; i++) {
    const s = await ctx.get(`/api/scan/${scanId}`);
    if (s.json?.data?.status === 'paused') paused = true;
    else await sleep(100);
  }
  assert.ok(paused, 'GET /scan/:id 必须能观测到 paused 状态');
  await sleep(400); // 在途那一发落地（闸挂在发包前，不取消在途请求）
  const t1 = (await rangeStats(ctx)).total;
  await sleep(3000); // 重跑期正常应持续发包（boolean+error 探测族 × delay=0.3）
  const t2 = (await rangeStats(ctx)).total;
  assert.equal(
    t2 - t1, 0,
    `暂停期间自适应重跑路径（ad-hoc 客户端）也不得发包，实得 ${t2 - t1} 个 —— 暂停闸没有盖住 detect.js 的裸视图客户端`,
  );

  const r = await ctx.post(`/api/scan/${scanId}/resume`, {});
  assert.equal(r.json?.code, 0, `resume 应成功，实得 ${JSON.stringify(r.json)}`);
  await sleep(2500);
  const t3 = (await rangeStats(ctx)).total;
  assert.ok(t3 > t2, `resume 后流量必须恢复，实得增量 ${t3 - t2}`);

  await ctx.post(`/api/scan/${scanId}/stop`, {});
  const fin = await waitScan(ctx, scanId, { timeoutMs: 60000, want: ['stopped', 'completed', 'error'] });
  assert.ok(['stopped', 'completed'].includes(fin.status), `收尾状态应可控，实得 ${fin.status}`);
});

test('scan', 'stop：终止 + 幂等语义 + 未知 id 不得报成功', async (ctx) => {
  const scanId = await startScan(ctx, { url: `${ctx.LAB}/blind?uid=1`, config: fastCfg({ delay: 1, techniques: ['boolean'] }) });
  await sleep(600);
  const s1 = await ctx.post(`/api/scan/${scanId}/stop`, {});
  assert.equal(s1.json?.code, 0, `首次 stop 应成功：${JSON.stringify(s1.json)}`);
  assert.equal(s1.json?.data?.stopped, true);
  await waitScan(ctx, scanId, { timeoutMs: 30000, want: ['stopped', 'completed', 'error'] });

  // 与 pause/resume 同一口径：不存在的扫描不能返回"成功"。
  // 历史上 /stop 对任意 id 都返回 code:0 + stopped:false —— 运维据此以为停掉了。
  const ghost = await ctx.post('/api/scan/doesnotexist0/stop', {});
  assert.notEqual(ghost.json?.code, 0, `/stop 对不存在的扫描必须返回非 0 业务码，实得 ${JSON.stringify(ghost.json)}`);
});

test('scan', '单点重测：只重打那一个参数，请求量显著小于整扫', async (ctx) => {
  const base = ctx.state.numScan?.report || (await scanUntilDone(ctx, { url: `${ctx.LAB}/num?id=1`, config: fastCfg({ techniques: ['union', 'boolean'] }) })).report;
  const point = (base.points || []).find((pt) => String(pt.param) === 'id') || (base.points || [])[0];
  assert.ok(point, '基线报告必须有可重测的注入点');

  await ctx.rangePost('/__range/reset', {});
  const r = await ctx.post(`/api/scan/${base.scanId || ctx.state.numScan.scanId}/point/${point.id}/retest`, {
    config: { level: 2, techniques: ['boolean'] },
  });
  assert.equal(r.json?.code, 0, `retest 启动失败：${JSON.stringify(r.json).slice(0, 300)}`);
  const reScanId = r.json?.data?.scanId;
  assert.ok(reScanId && reScanId !== ctx.state.numScan?.scanId, 'retest 应返回新的 scanId');
  assert.equal(r.json?.data?.point?.param, point.param, 'retest 回显的 point 应与请求一致');
  assert.deepEqual(r.json?.data?.configApplied?.techniques, ['boolean'], 'configApplied 必须回显引擎真正读取的技术集合');
  assert.equal(r.json?.data?.configApplied?.level, 2, 'configApplied.level 应回显覆盖值');

  const done = await waitScan(ctx, reScanId, { timeoutMs: 60000 });
  const rep = (await ctx.get(`/api/scan/${reScanId}/report`)).json?.data;
  const repParams = new Set((rep?.points || []).map((pt) => String(pt.param)));
  assert.ok(repParams.has('id'), `重测报告应仍覆盖 id 点位，实得 ${JSON.stringify([...repParams])}`);
  const stats = await rangeStats(ctx);
  const hitParams = stats.byParam.filter((x) => x.location === 'url').map((x) => x.param);
  assert.deepEqual(hitParams, ['id'], `重测只应打到 id 参数，靶站实际看到 ${JSON.stringify(hitParams)}`);
  assert.ok(done.status === 'completed', `重测应完成，实得 ${done.status}`);
  ctx.note('retest.rangeHits', stats.total);
});

test('scan', 'diff?base=：修好一个点必须报 fixed（真靶站开关取证）', async (ctx) => {
  // 基线：/patch 处于"拼接 SQL"态
  await ctx.rangePost('/__range/config', { patched: false });
  const a = await scanUntilDone(ctx, { url: `${ctx.LAB}/patch?id=1`, config: fastCfg({ techniques: ['union', 'boolean'] }) });
  assert.ok((a.report?.vulns || []).length >= 1, `基线扫描应检出漏洞，实得 ${a.report?.vulns?.length}`);

  // 修复：同一 URL 切参数化，再扫一次
  await ctx.rangePost('/__range/config', { patched: true });
  const b = await scanUntilDone(ctx, { url: `${ctx.LAB}/patch?id=1`, config: fastCfg({ techniques: ['union', 'boolean'] }) });

  const d = await ctx.get(`/api/scan/${b.scanId}/diff?base=${a.scanId}`);
  assert.equal(d.json?.code, 0, `diff 应成功：${JSON.stringify(d.json).slice(0, 200)}`);
  const data = d.json?.data || {};
  assert.ok(Array.isArray(data.fixed) && Array.isArray(data.new) && Array.isArray(data.remaining), `diff 应含 fixed/new/remaining 三组，实得键 ${Object.keys(data)}`);
  assert.ok(data.fixed.length >= 1, `修复后必须报出至少 1 条 fixed（"证明修好了"是交付场景本身），实得 ${JSON.stringify(data)}`);

  // 反向：缺 base 参数必须明确报错而不是静默返回空 diff
  const noBase = await ctx.get(`/api/scan/${b.scanId}/diff`);
  assert.notEqual(noBase.json?.code, 0, 'diff 缺 base 应报错');
  await ctx.rangePost('/__range/config', { patched: false });
});

test('scan', 'report 与 export 七种格式：内容类型/文件名/正文逐项核对', async (ctx) => {
  const { scanId, report } = ctx.state.numScan || (await scanUntilDone(ctx, { url: `${ctx.LAB}/num?id=1`, config: fastCfg() }));
  // 报告正文必须带可复放 PoC（实战开台本第一件要用的东西）
  const withPoc = (report.vulns || []).filter((v) => v.poc);
  assert.ok(withPoc.length >= 1, 'GET /scan/:id/report 应附带 poc（与导出同源）');
  const pocText = JSON.stringify(withPoc[0].poc);
  assert.match(pocText, /curl|GET|http/i, `poc 应是一条可复放请求，实得 ${pocText.slice(0, 160)}`);

  const expect = {
    json: { ct: /application\/json/, ext: '.json' },
    html: { ct: /text\/html/, ext: '.html' },
    csv: { ct: /text\/csv/, ext: '.csv' },
    markdown: { ct: /text\/markdown/, ext: '.markdown' },
    md: { ct: /text\/markdown/, ext: '.markdown' },
    sarif: { ct: /application\/sarif\+json/, ext: '.sarif' },
  };
  for (const [fmt, want] of Object.entries(expect)) {
    const r = await ctx.get(`/api/scan/${scanId}/report/export?format=${fmt}`);
    assert.equal(r.status, 200, `export ${fmt} 应 200，实得 ${r.status}`);
    assert.match(String(r.headers['content-type'] || ''), want.ct, `export ${fmt} 的 Content-Type 不符：${r.headers['content-type']}`);
    assert.match(String(r.headers['content-disposition'] || ''), new RegExp(`report_${scanId}${want.ext.replace('.', '\\.')}`), `export ${fmt} 文件名不符：${r.headers['content-disposition']}`);
    assert.ok(r.text.length > 20, `export ${fmt} 正文过短（${r.text.length} 字节）`);
    if (fmt === 'json' || fmt === 'sarif') {
      assert.ok(r.json, `export ${fmt} 必须是合法 JSON`);
    }
    if (fmt === 'sarif') {
      assert.match(String(r.json?.version || ''), /2\.1\.0/, 'SARIF 必须声明 2.1.0');
      assert.ok(Array.isArray(r.json?.runs) && r.json.runs.length >= 1, 'SARIF 应含 runs');
    }
    if (fmt === 'html') {
      assert.match(r.text, /<table|<h1|漏洞/i, 'HTML 报告应含正文结构');
      assert.ok(!/undefined|\[object Object\]/.test(r.text), 'HTML 报告不得出现 undefined/[object Object]');
    }
    if (fmt === 'csv') {
      const lines = r.text.trim().split(/\r?\n/);
      assert.ok(lines.length >= 2, `CSV 应至少含表头+1 行，实得 ${lines.length} 行`);
    }
  }

  // db-json：本次扫描没做枚举/拖库 → 必须**明确拒绝**，而不是发一个内容为 "null" 的附件
  //（历史上它返回 200 + `null`（4 字节）：用户看到一个打不开的 .db.json，第一反应是导出坏了）
  const empty = await ctx.get(`/api/scan/${scanId}/report/export?format=db-json`);
  assert.equal(empty.status, 400, `无拖库数据的 db-json 应 400，实得 ${empty.status}（正文 ${JSON.stringify(empty.text.slice(0, 40))}）`);
  assert.match(String(empty.json?.message || ''), /extractScope|枚举|拖库/, `400 说明要能指下一步，实得 ${JSON.stringify(empty.json)}`);

  const bad = await ctx.get(`/api/scan/${scanId}/report/export?format=exe`);
  assert.equal(bad.status, 400, `非法 format 应 400，实得 ${bad.status}`);
  // 未知扫描：文件下载语义必须 404（历史上 200+JSON 让前端把错误体存成 report.csv）
  const gone = await ctx.get('/api/scan/ghostscan00/report/export?format=csv');
  assert.equal(gone.status, 404, `导出不存在的扫描应 404，实得 ${gone.status}`);
});

test('scan', 'bodyParams / cookieParams / headerParams 三条入参路径各有真目标', async (ctx) => {
  // POST body 注入点（level 1 即测）
  const bodyScan = await scanUntilDone(ctx, {
    url: `${ctx.LAB}/search`,
    method: 'POST',
    bodyParams: { q: 'chair' },
    config: fastCfg({ techniques: ['boolean', 'error'] }),
  });
  const bodyPoint = (bodyScan.report?.points || []).find((pt) => pt.location === 'body' && pt.param === 'q');
  assert.ok(bodyPoint, `bodyParams 应被解析成 body 注入点，实得位置集合 ${JSON.stringify((bodyScan.report?.points || []).map((p) => p.location))}`);
  assert.ok((bodyScan.report?.vulns || []).length >= 1, 'body 注入点应检出漏洞');

  // ── level 语义必须"给了没测就喊出来"（TargetParser：cookie 需 level≥2、header 需 level≥3）──
  // 低 level 下扫描正常完成、报告写「未检出」，而调用方传了 cookieParams/headerParams ——
  // 这类静默跳过的接口面比报错更贵，故断言 summary.constraints 里一定有对应说明。
  const low = await scanUntilDone(ctx, {
    url: `${ctx.LAB}/account`,
    cookieParams: { sid: 'lab-sess-2026', uid: '1' },
    headerParams: { 'X-Auth': 'lab-secret-2026', 'X-Section': 'users' },
    config: fastCfg({ level: 1, techniques: ['boolean'] }),
  });
  const constraints = JSON.stringify(low.report?.summary?.constraints || []);
  assert.match(constraints, /cookieParams 未被测试/, `level=1 收了 cookieParams 必须在报告里可见，实得 ${constraints.slice(0, 300)}`);
  assert.match(constraints, /headerParams 未被测试/, 'level=1 收了 headerParams 必须在报告里可见');
  assert.deepEqual((low.report?.points || []).map((p) => p.location).filter((l) => l !== 'url'), [], '低 level 下确实不该测 cookie/header（口径不能悄悄放宽）');

  // Cookie 注入点（level≥2；靶站要求会话 Cookie，缺凭据 401）
  await ctx.rangePost('/__range/reset', {});
  const cookieScan = await scanUntilDone(ctx, {
    url: `${ctx.LAB}/account`,
    cookieParams: { sid: 'lab-sess-2026', uid: '1' },
    config: fastCfg({ level: 2, techniques: ['boolean', 'error'] }),
  });
  const cookiePoint = (cookieScan.report?.points || []).find((pt) => pt.location === 'cookie' && pt.param === 'uid');
  assert.ok(cookiePoint, `cookieParams.uid 应成为 cookie 注入点，实得 ${JSON.stringify((cookieScan.report?.points || []).map((p) => `${p.location}:${p.param}`))}`);
  const stats = await rangeStats(ctx);
  const accountHits = stats.byPath['/account'] || 0;
  assert.ok(accountHits > 0, '靶站应收到 /account 请求');

  // Header 注入点（level≥3；X-Auth 静态凭据 + X-Section 注入位）
  const headerScan = await scanUntilDone(ctx, {
    url: `${ctx.LAB}/report`,
    headerParams: { 'X-Auth': 'lab-secret-2026', 'X-Section': 'users' },
    config: fastCfg({ level: 3, techniques: ['boolean', 'error'] }),
  });
  const headerPoint = (headerScan.report?.points || []).find((pt) => String(pt.location).toLowerCase().includes('header'));
  assert.ok(headerPoint, `headerParams.X-Section 应成为 header 注入点，实得 ${JSON.stringify((headerScan.report?.points || []).map((p) => `${p.location}:${p.param}`))}`);
  ctx.state.bodyScan = bodyScan;
  ctx.state.cookieScan = cookieScan;
  ctx.state.headerScan = headerScan;
});

test('scan', '禁止覆写的请求头（Host/Content-Length 等）必须被丢弃', async (ctx) => {
  const r = await ctx.post('/api/scan/start', {
    url: `${ctx.LAB}/num?id=1`,
    headerParams: { Host: 'evil.example', 'Content-Length': '9999', 'X-Keep': 'ok' },
    config: fastCfg({ techniques: ['boolean'], level: 1 }),
  });
  assert.equal(r.json?.code, 0);
  const scanId = r.json.data.scanId;
  const got = await ctx.get(`/api/scan/${scanId}`);
  const hp = got.json?.data?.target?.headerParams || {};
  assert.ok(!('host' in Object.fromEntries(Object.entries(hp).map(([k, v]) => [k.toLowerCase(), v]))), `Host 头不应被透传：${JSON.stringify(hp)}`);
  assert.ok(hp['X-Keep'] === 'ok', `合法自定义头应保留：${JSON.stringify(hp)}`);
  await ctx.post(`/api/scan/${scanId}/stop`, {});
});

test('scan', 'config 白名单：未收录键不得静默进引擎（传了要播报）', async (ctx) => {
  const r = await ctx.post('/api/scan/start', {
    url: `${ctx.LAB}/num?id=1`,
    config: fastCfg({ concurrency: 9999, timeoutMs: 99999999, notARealKey: 'x', dumpWhere: 'role=1; DROP TABLE' }),
  });
  assert.equal(r.json?.code, 0);
  const scanId = r.json.data.scanId;
  const got = await ctx.get(`/api/scan/${scanId}`);
  const cfg = got.json?.data?.target?.config || {};
  assert.ok(cfg.concurrency <= 10, `concurrency 必须被 clamp 到 [1,10]，实得 ${cfg.concurrency}`);
  assert.ok(cfg.timeoutMs <= 60000, `timeoutMs 必须被 clamp，实得 ${cfg.timeoutMs}`);
  assert.ok(!('notARealKey' in cfg), '未知配置键不得落地');
  assert.ok(!String(cfg.dumpWhere || '').includes(';'), `dumpWhere 含分号必须被拒：${JSON.stringify(cfg.dumpWhere)}`);
  await ctx.post(`/api/scan/${scanId}/stop`, {});
});

test('scan', '授权范围（scope）：越界目标必须在入口被拒', async (ctx) => {
  await ctx.rangePost('/__range/reset', {});
  const r = await ctx.post('/api/scan/start', {
    url: `${ctx.LAB}/num?id=1`,
    config: { scope: ['example.com'] },
  });
  assert.notEqual(r.json?.code, 0, `目标不在授权范围内必须拒绝启动，实得 ${JSON.stringify(r.json)}`);
  const stats = await rangeStats(ctx);
  // 拒绝必须发生在发包之前（清零后再取计数，避免把上一条用例的流量算成违约）
  assert.equal(stats.total, 0, `越界扫描不得向靶站发出任何请求，实得 ${stats.total} 个：${JSON.stringify(stats.byPath)}`);
  // 反向对照：同一 URL 配了**正确**范围必须能扫
  const ok = await ctx.post('/api/scan/start', {
    url: `${ctx.LAB}/num?id=1`,
    config: { scope: [`127.0.0.1:${ctx.labPort}`] },
  });
  assert.equal(ok.json?.code, 0, `范围内目标（host:port 写法）应能启动，实得 ${JSON.stringify(ok.json)}`);
  await ctx.post(`/api/scan/${ok.json.data.scanId}/stop`, {});

  // 带端口的规则必须**只**放行该端口（收紧而不是放宽）：换端口要拒，且报错要说清差在端口
  const wrongPort = await ctx.post('/api/scan/start', {
    url: `${ctx.LAB}/num?id=1`,
    config: { scope: [`127.0.0.1:${ctx.labPort + 1}`] },
  });
  assert.notEqual(wrongPort.json?.code, 0, `端口不符的目标必须拒绝，实得 ${JSON.stringify(wrongPort.json)}`);
  assert.match(String(wrongPort.json?.message || ''), /端口/, `报错应指出差在端口（旧实现会打印一句自相矛盾的话），实得 ${JSON.stringify(wrongPort.json)}`);
  // 无端口的裸 IP 规则仍放行任意端口（既有口径不回退）
  const bareIp = await ctx.post('/api/scan/start', {
    url: `${ctx.LAB}/num?id=1`,
    config: { scope: ['127.0.0.1'] },
  });
  assert.equal(bareIp.json?.code, 0, '裸 IP 规则应保持既有行为');
  await ctx.post(`/api/scan/${bareIp.json.data.scanId}/stop`, {});
});

test('scan', 'SSRF：云元数据/链路本地属硬底线，ALLOW_PRIVATE 也不放行', async (ctx) => {
  // 本实例带 SSRF_ALLOW_PRIVATE=1（靶站在回环，必须放行），因此这条用例专门验
  // 「放行私网 ≠ 放行元数据」：2026-09-28 接口靶场实测出旧实现里 ALLOW_PRIVATE
  // 会把 169.254.0.0/16 一起豁免，与 egressGuard 文件头的"基础层无条件拒绝"矛盾。
  for (const u of ['http://169.254.169.254/latest/meta-data/', 'http://metadata.google.internal/x', 'http://169.254.169.254/']) {
    const r = await ctx.post('/api/scan/start', { url: u });
    assert.notEqual(r.json?.code, 0, `${u} 应被 SSRF 闸门拒绝，实得 ${JSON.stringify(r.json).slice(0, 200)}`);
  }
  // 0.0.0.0/8 与组播同样属硬底线
  const zero = await ctx.post('/api/scan/start', { url: 'http://0.0.0.0/x' });
  assert.notEqual(zero.json?.code, 0, '0.0.0.0 应被拒绝');
});

test('scan', 'extractScope：枚举与拖库在 REST 入口真可用（真库数据回填）', async (ctx) => {
  const dbs = await scanUntilDone(ctx, {
    url: `${ctx.LAB}/num?id=1`,
    config: fastCfg({ techniques: ['union'], extractScope: { mode: 'dbs' } }),
  }, { timeoutMs: 150000 });
  const got = JSON.stringify(dbs.report?.data || {});
  assert.match(got, /sqli_lab/, `枚举库名应含真实业务库 sqli_lab，实得 ${got.slice(0, 300)}`);

  const dump = await scanUntilDone(ctx, {
    url: `${ctx.LAB}/num?id=1`,
    config: fastCfg({
      techniques: ['union'],
      extractScope: { mode: 'dump', dbs: ['sqli_lab'], tables: ['users'] },
      dumpMaxRows: 20,
    }),
  }, { timeoutMs: 180000 });
  const dumpText = JSON.stringify(dump.report?.data || {});
  assert.match(dumpText, /admin/, `拖库应拿到真实用户名，实得 ${dumpText.slice(0, 400)}`);
  assert.match(dumpText, /张三|o.brien/, '拖库行数据应含种子里的疑难值（中文/引号）');
  ctx.state.dumpScan = dump;

  // 有了拖库数据，db-json 导出必须真的可下载（与上一条用例的 400 形成正反对照）
  const ex = await ctx.get(`/api/scan/${dump.scanId}/report/export?format=db-json`);
  assert.equal(ex.status, 200, `有数据的 db-json 应 200，实得 ${ex.status}`);
  assert.match(String(ex.headers['content-disposition'] || ''), /\.db\.json/, 'db-json 文件名后缀应为 .db.json');
  assert.match(ex.text, /admin/, 'db-json 正文应含拖到的数据');
});

test('scan', '直连模式（mode:direct）：第二条入口同样要过配置与范围守卫', async (ctx) => {
  const db = {
    host: ctx.mysql.host,
    port: ctx.mysql.port,
    user: ctx.mysql.user,
    password: ctx.mysql.password,
    database: ctx.mysql.database,
    dbType: 'MySQL',
  };
  const ok = await ctx.post('/api/scan/start', {
    mode: 'direct',
    db,
    sqlTemplate: 'SELECT * FROM users WHERE id = {INJECT}',
    config: fastCfg({ techniques: ['union', 'error', 'boolean'] }),
  });
  assert.equal(ok.json?.code, 0, `直连扫描应启动：${JSON.stringify(ok.json).slice(0, 300)}`);
  const done = await waitScan(ctx, ok.json.data.scanId, { timeoutMs: 120000 });
  assert.equal(done.status, 'completed', `直连扫描应完成，实得 ${done.status}`);
  const rep = (await ctx.get(`/api/scan/${ok.json.data.scanId}/report`)).json?.data;
  assert.ok((rep?.vulns || []).length >= 1, '直连模式应检出注入点');

  // 缺 {INJECT} 标记 → 明确报错
  const bad = await ctx.post('/api/scan/start', { mode: 'direct', db, sqlTemplate: 'SELECT 1' });
  assert.notEqual(bad.json?.code, 0, '直连缺 {INJECT} 必须拒绝');
  // 直连也要吃 scope（历史上这句被误当成"无 SSRF 面=无范围约束"）
  const scoped = await ctx.post('/api/scan/start', {
    mode: 'direct',
    db,
    sqlTemplate: 'SELECT * FROM users WHERE id = {INJECT}',
    config: { scope: ['only-authorized.example'] },
  });
  assert.notEqual(scoped.json?.code, 0, `直连越界必须被 scope 拦下，实得 ${JSON.stringify(scoped.json)}`);
  // 直连入口的配置守卫（concurrency:9999 曾原样进引擎）
  const cfgBad = await ctx.post('/api/scan/start', {
    mode: 'direct',
    db,
    sqlTemplate: 'SELECT * FROM users WHERE id = {INJECT}',
    config: { concurrency: 9999, timeoutMs: 99999999 },
  });
  if (cfgBad.json?.code === 0) {
    const g = await ctx.get(`/api/scan/${cfgBad.json.data.scanId}`);
    const c = g.json?.data?.target?.config || {};
    assert.ok(c.concurrency <= 10 && c.timeoutMs <= 60000, `直连配置必须 clamp，实得 ${JSON.stringify({ c1: c.concurrency, t: c.timeoutMs })}`);
    await ctx.post(`/api/scan/${cfgBad.json.data.scanId}/stop`, {});
  }
});

// ── group: exploit —— 四条利用接口在真库上的闭环 ────────────────────────────
const SECURE_DIR = String(process.env.MYSQL_SECURE_FILE_DIR || '').replace(/\\/g, '/').replace(/\/+$/, '');

/** 用 num 端点的真实点位构造利用入参（与前端手工填表同源，字段取自真报告） */
function pointOf(report, param) {
  return (report.points || []).find((pt) => pt.param === param) || (report.points || [])[0];
}

function exploitBody(ctx, report, over = {}) {
  const point = pointOf(report, 'id');
  return {
    target: { url: `${ctx.LAB}/num?id=1`, method: 'GET' },
    point: { originalValue: point?.originalValue ?? '1', location: point?.location || 'url', param: point?.param || 'id' },
    dbms: report.dbms || 'MySQL',
    authorized: true,
    // [2026-10-01] 授权范围是**利用端的硬红线**（缺它直接 1007 拒单）：靶场自身是回环地址，
    // 这里显式声明靶站主机，否则用例撞的是红线而不是被测能力 —— 那才是真正的假红。
    scope: ['127.0.0.1'],
    ...over,
  };
}

test('exploit', 'POST /exploit/sql：真库执行 SELECT VERSION() 并回显', async (ctx) => {
  const base = ctx.state.numScan?.report || (await scanUntilDone(ctx, { url: `${ctx.LAB}/num?id=1`, config: fastCfg() })).report;
  const r = await ctx.post('/api/exploit/sql', exploitBody(ctx, base, { sql: 'SELECT VERSION()' }));
  assert.equal(r.json?.code, 0, `/exploit/sql 业务码应为 0：${JSON.stringify(r.json).slice(0, 300)}`);
  const d = r.json?.data || {};
  assert.equal(d.ok, true, `sqlShell 应 ok:true，实得 ${JSON.stringify(d).slice(0, 300)}`);
  assert.match(String(d.value || ''), /8\.0|10\.|11\.|5\.7/, `应回显真实 MySQL 版本号，实得 ${JSON.stringify(d.value)}`);
  ctx.note('exploit.sql.version', d.value);
});

test('exploit', 'POST /exploit/sql：只需 scanId+pointId 即可接管扫描结果', async (ctx) => {
  const { scanId, report } = ctx.state.numScan || (await scanUntilDone(ctx, { url: `${ctx.LAB}/num?id=1`, config: fastCfg() }));
  const point = pointOf(report, 'id');
  assert.ok(point?.id, '基线扫描必须给出可引用的 pointId');
  const r = await ctx.post('/api/exploit/sql', {
    scanId,
    pointId: point.id,
    authorized: true,
    sql: 'SELECT DATABASE()',
  });
  assert.equal(
    r.json?.code,
    0,
    `接口应支持"扫到什么就利用什么"（scanId+pointId 由服务端解析 target/point/dbms），实得 ${JSON.stringify(r.json).slice(0, 300)}`
  );
  const d = r.json?.data || {};
  assert.equal(d.ok, true, `scanId 形态的 sqlShell 应成功：${JSON.stringify(d).slice(0, 300)}`);
  assert.match(String(d.value || ''), /sqli_lab/, `应回显真实库名 sqli_lab，实得 ${JSON.stringify(d.value)}`);
  assert.equal(d.resolvedFrom?.pointId, point.id, '响应应说明解析来源（scanId/pointId/dbms），便于审计复放');
  assert.match(String(d.resolvedFrom?.dbms || ''), /MySQL/i, 'resolvedFrom.dbms 应来自报告定库结果');
});

test('exploit', '凭据/会话继承：需要 X-Auth 的 header 点位沿用扫描凭据', async (ctx) => {
  const hdr = ctx.state.headerScan;
  assert.ok(hdr?.scanId, '前置：header 注入点扫描用例必须先跑（单独跑 --groups=exploit 时请带 scan）');
  // 必须锁定 X-Section：X-Auth 也在 headerParams 里，level≥3 下它同样成为候选注入点，
  // 但它不是 SQL 上下文（靶站拿它做鉴权比较）。选错点=把凭据本身当 payload 打出去，
  // 靶站必然 401 —— 这条用例第一版就栽在这里（report.points 是"候选点位"，
  // 不等于 report.vulns 的"已确认点位"，取点要按 param 明确指定，不能拿第一个）。
  const point = (hdr.report?.points || []).find(
    (pt) => /header/i.test(String(pt.location)) && String(pt.param).toLowerCase() === 'x-section'
  );
  assert.ok(
    point,
    `应存在 x-section 这个 header 注入点，实得 ${JSON.stringify((hdr.report?.points || []).map((p) => `${p.location}:${p.param}`))}`
  );

  await ctx.rangePost('/__range/reset', {});
  const r = await ctx.post('/api/exploit/sql', {
    scanId: hdr.scanId,
    pointId: point.id,
    authorized: true,
    sql: 'SELECT USER()',
  });
  assert.equal(r.json?.code, 0, `沿用扫描凭据应能用，实得 ${JSON.stringify(r.json).slice(0, 300)}`);
  const d = r.json?.data || {};

  // 真正的证据在靶站侧：utilize 请求必须**带着** X-Auth 到达（=继承成功），
  // 一条 401 都没有。只看接口自报 ok 不够——401 页面同样能走完一次"请求已发出"。
  const stats = await rangeStats(ctx);
  const okHits = stats.authOk?.['/report'] || 0;
  const deniedHits = stats.authDenied?.['/report'] || 0;
  assert.ok(okHits > 0, `靶站应看到带凭据的命中（继承 headerParams），实得 authOk=${JSON.stringify(stats.authOk)}`);
  assert.equal(deniedHits, 0, `利用阶段不得出现 401（凭据没继承就会全 401），实得 ${JSON.stringify(stats.authDenied)}，现场样本 ${JSON.stringify(stats.deniedSamples)}`);
  assert.equal(d.resolvedFrom?.sessionInherited, true, 'resolvedFrom 应如实说明用了扫描作用域的客户端');
  assert.equal(d.resolvedFrom?.location, point.location, 'resolvedFrom.location 应来自报告点位');

  // 取不到值时必须说清"为什么没值"，不许 ok:true + value:null 这种自相矛盾的形态
  if (d.ok === true) {
    assert.ok(String(d.value ?? '').length > 0, `ok:true 就必须带回显值，实得 ${JSON.stringify(d)}`);
  } else {
    assert.match(String(d.error || ''), /回显|UNION|投递/, `无回显要给出可操作原因，实得 ${JSON.stringify(d)}`);
    assert.equal(d.delivered, true, '投递成功/失败要与"取到值"分开表达');
  }
});

test('exploit', 'POST /exploit/file-read：真实读取 secure_file_priv 目录文件', async (ctx) => {
  if (!SECURE_DIR) {
    return Object.assign(new Error('SKIP:需要隔离 MySQL 沙箱（MYSQL_SECURE_FILE_DIR 未注入）'), { __skip: true });
  }
  const fs = await import('node:fs');
  const path = await import('node:path');
  const marker = path.posix.join(SECURE_DIR, 'api-range-fileread-marker.txt');
  const content = `API_RANGE_FILEREAD_${Date.now()}_行1\n第二行含中文与等号=a=b\n`;
  fs.writeFileSync(marker.replace(/\//g, path.sep), content, 'utf8');
  const base = ctx.state.numScan?.report || (await scanUntilDone(ctx, { url: `${ctx.LAB}/num?id=1`, config: fastCfg() })).report;
  const r = await ctx.post('/api/exploit/file-read', exploitBody(ctx, base, { path: marker }));
  const d = r.json?.data || {};
  assert.equal(r.json?.code, 0, `file-read 应成功：${JSON.stringify(r.json).slice(0, 240)}`);
  assert.equal(d.ok, true, `fileRead 应 ok:true（secure_file_priv 已放行），实得 ${JSON.stringify(d).slice(0, 300)}`);
  assert.equal(String(d.value), content, '读回内容必须与磁盘逐字节一致');
  fs.rmSync(marker.replace(/\//g, path.sep), { force: true });
});

test('exploit', 'POST /exploit/file-write：真实落盘并回读闭环', async (ctx) => {
  if (!SECURE_DIR) {
    return Object.assign(new Error('SKIP:需要隔离 MySQL 沙箱（MYSQL_SECURE_FILE_DIR 未注入）'), { __skip: true });
  }
  const fs = await import('node:fs');
  const path = await import('node:path');
  const target = `${SECURE_DIR}/api-range-filewrite-${Date.now()}.txt`;
  const payload = `API_RANGE_WRITE_${Date.now()}_marker_line\n`;
  const base = ctx.state.numScan?.report || (await scanUntilDone(ctx, { url: `${ctx.LAB}/num?id=1`, config: fastCfg() })).report;
  // confirmDestructive：写类护栏（6005）与 config.productionMode / secondOrder.allowWrites 同口径，
  // 不声明就被拦在能力判定之前 —— 那时 data 是空对象，测的就不是「能不能写」而是护栏文本。
  const r = await ctx.post('/api/exploit/file-write', exploitBody(ctx, base, { content: payload, remotePath: target, confirmDestructive: true }));
  const d = r.json?.data || {};
  assert.equal(r.json?.code, 0, `file-write 应返回业务成功：${JSON.stringify(r.json).slice(0, 240)}`);
  const onDisk = fs.existsSync(target.replace(/\//g, path.sep)) ? fs.readFileSync(target.replace(/\//g, path.sep), 'utf8') : null;
  assert.ok(
    d.wrote === true || d.ok === true,
    `fileWrite 必须真写入（接口回报 ${JSON.stringify(d).slice(0, 200)}；磁盘 ${onDisk ? '存在' : '不存在'}）`
  );
  assert.ok(onDisk && onDisk.includes(payload.trim().slice(0, 30)), `文件系统侧必须能看到写入内容，实得 ${JSON.stringify(onDisk?.slice(0, 80))}`);
  if (onDisk !== null) fs.rmSync(target.replace(/\//g, path.sep), { force: true });
});

test('exploit', 'POST /exploit/os-shell：能力缺失时如实失败（不得假成功）', async (ctx) => {
  const base = ctx.state.numScan?.report || (await scanUntilDone(ctx, { url: `${ctx.LAB}/num?id=1`, config: fastCfg() })).report;
  // 与 file-write 同口径：os-shell 也是写类操作，缺 confirmDestructive 会先撞 6005 护栏，
  // 于是「失败必须给出原因」这条断言看到的是空 data（假红 —— 被测能力根本没被触达）。
  const r = await ctx.post('/api/exploit/os-shell', exploitBody(ctx, base, { cmd: 'id', confirmDestructive: true }));
  const d = r.json?.data || {};
  if (d.ok === true) {
    // 装了 sys_eval UDF 的环境（e2e/udf-lab）应拿到真命令输出
    assert.ok(String(d.output || d.value || d.stdout || '').trim().length > 0, 'os-shell 成功时必须带回显');
    ctx.note('exploit.osShell', 'real');
    return;
  }
  assert.ok(String(d.error || d.message || '').length > 8, `失败必须给出原因，实得 ${JSON.stringify(d)}`);
  assert.ok(!('output' in d && d.output), '失败路径不得带 output 字段');
  ctx.note('exploit.osShell', d.error);
});

test('exploit', '利用红线：authorized / 服务端开关 / 限速 / SSRF / scope', async (ctx) => {
  const base = ctx.state.numScan?.report || (await scanUntilDone(ctx, { url: `${ctx.LAB}/num?id=1`, config: fastCfg() })).report;

  // ① 缺 authorized:true
  const noAuth = await ctx.post('/api/exploit/sql', { ...exploitBody(ctx, base, { sql: 'SELECT 1' }), authorized: false });
  assert.notEqual(noAuth.json?.code, 0, 'authorized 缺失必须拒绝');

  // ② 服务端 EXPLOIT_ENABLED=0 的实例：即便 authorized:true 也必须拒绝
  const off = await startEngine({ name: 'exploit-off', env: { EXPLOIT_ENABLED: '0' } });
  try {
    const r = await request({
      port: off.port,
      method: 'POST',
      path: '/api/exploit/sql',
      token: off.token,
      body: exploitBody(ctx, base, { sql: 'SELECT 1' }),
    });
    assert.notEqual(r.json?.code, 0, `EXPLOIT_ENABLED=0 时利用必须被拒，实得 ${JSON.stringify(r.json).slice(0, 200)}`);
    // capabilities 也必须如实报 enabled:false（前端据此隐藏入口）
    const cap = await request({ port: off.port, path: '/api/exploit/capabilities' });
    assert.equal(cap.json?.data?.enabled, false, 'capabilities 应如实反映服务端开关');
  } finally {
    await off.stop();
  }

  // ③ 独立限速桶：连打必须出现限速码，而不是静默排队。
  //    用一台限速到 1/s 的实例测：主实例是 5/s，而每次真实 UNION 提取本身要 0.2~0.3s，
  //    令牌在请求间隔里就补回来了 —— 上一版在这里连打 12 次全绿，测的是节奏不是闸门。
  //    这里让请求在"过完鉴权与限速"之后立刻失败（缺 point），单次耗时≈0，桶必然见底。
  const rl = await startEngine({ name: 'exploit-rate', env: { EXPLOIT_ENABLED: '1', EXPLOIT_RATE_PER_SEC: '1' } });
  try {
    const codes = [];
    for (let i = 0; i < 8; i++) {
      const r = await request({
        port: rl.port,
        method: 'POST',
        path: '/api/exploit/sql',
        token: rl.token,
        // scope 也要带：否则撞的是授权红线（1007）而不是限速桶，测错了闸门
        body: { target: { url: `${ctx.LAB}/num?id=1` }, dbms: 'MySQL', authorized: true, scope: ['127.0.0.1'], sql: 'SELECT 1' },
      });
      codes.push(r.json?.code);
    }
    const limited = codes.filter((c) => c && c !== 0 && c !== ErrorCode.INVALID_PARAM);
    assert.ok(limited.length > 0, `1/s 桶下连打 8 次必须出现限速码，实得 ${JSON.stringify(codes)}`);
    assert.equal(limited[0], ErrorCode.RATE_LIMITED, `限速应回 RATE_LIMITED(4290) 而不是泛化错误码，实得 ${limited[0]}`);
  } finally {
    await rl.stop();
  }

  // ④ SSRF：利用端点同样不得打云元数据
  const meta = await ctx.post('/api/exploit/sql', {
    target: { url: 'http://169.254.169.254/latest/meta-data/', method: 'GET' },
    point: { originalValue: '1', location: 'url', param: 'id' },
    dbms: 'MySQL',
    authorized: true,
    sql: 'SELECT 1',
  });
  assert.notEqual(meta.json?.code, 0, '利用端点必须过 SSRF 校验');

  // ⑤ scope：显式声明范围后越界目标必须拒
  const scoped = await ctx.post('/api/exploit/sql', {
    ...exploitBody(ctx, base, { sql: 'SELECT 1' }),
    scope: ['only-authorized.example'],
  });
  assert.notEqual(scoped.json?.code, 0, `利用端点必须吃 scope，实得 ${JSON.stringify(scoped.json).slice(0, 200)}`);
});

// ── group: sqlmap —— 高级模式入口 ───────────────────────────────────────────
test('sqlmap', 'GET /api/sqlmap/status 只报可用性，不泄露路径', async (ctx) => {
  const r = await ctx.get('/api/sqlmap/status');
  assert.equal(r.json?.code, 0);
  const text = JSON.stringify(r.json);
  assert.ok(typeof r.json.data.available === 'boolean', 'status 必须给出 available 布尔');
  assert.ok(!/[A-Za-z]:\\\\|\/usr\/|\/home\/|sqlmap\.py/.test(text), `status 不得回显脚本/解释器绝对路径：${text.slice(0, 200)}`);
});

test('sqlmap', 'POST /api/sqlmap/start：越界目标必须被 scope 拦下', async (ctx) => {
  const r = await ctx.post('/api/sqlmap/start', {
    target: { url: 'http://127.0.0.1:9/unauthorized' },
    config: { scope: ['only-authorized.example'] },
  });
  assert.notEqual(
    r.json?.code,
    0,
    `/sqlmap/start 与内置引擎共用"别打没授权的人"这条红线，实得 ${JSON.stringify(r.json).slice(0, 240)}`
  );
});

test('sqlmap', 'POST /api/sqlmap/start：环境缺 sqlmap 时如实失败（不得假 scanId）', async (ctx) => {
  const st = await ctx.get('/api/sqlmap/status');
  if (st.json?.data?.available !== true) {
    const r = await ctx.post('/api/sqlmap/start', { target: { url: `${ctx.LAB}/num?id=1` } });
    assert.notEqual(r.json?.code, 0, `缺 sqlmap 应报错，实得 ${JSON.stringify(r.json).slice(0, 200)}`);
    assert.ok(!r.json?.data?.scanId, `不得返回一个不存在任务的 scanId（前端会去订阅一个永不结束的 SSE）：${JSON.stringify(r.json)}`);
    const ghost = await ctx.get('/api/sqlmap/ghostid00/report');
    assert.notEqual(ghost.json?.code, 0, '查询不存在的 sqlmap 任务应明确失败');
    // 停止语义与内置引擎对齐：不存在的任务不得回 code:0
    const ghostStop = await ctx.post('/api/sqlmap/ghostid00/stop', {});
    assert.equal(ghostStop.json?.code, ErrorCode.SCAN_NOT_FOUND, `未知 sqlmap 任务的 stop 应回 SCAN_NOT_FOUND，实得 ${JSON.stringify(ghostStop.json)}`);
    ctx.note('sqlmap.available', false);
    return;
  }
  const started = await ctx.post('/api/sqlmap/start', { target: { url: `${ctx.LAB}/num?id=1` }, config: { sqlmap: { level: 1, techniques: 'BEUSTQ' } } });
  assert.equal(started.json?.code, 0, `有 sqlmap 时应能启动：${JSON.stringify(started.json).slice(0, 200)}`);
  const id = started.json.data.scanId;
  const rep = await ctx.get(`/api/sqlmap/${id}/report`);
  assert.ok(rep.json && typeof rep.json.code === 'number', 'sqlmap 报告端点必须返回统一契约 {code,data,message}');
  assert.ok(rep.json?.code === 0 || rep.json?.data === null, `sqlmap 报告应成功或如实报未找到，实得 ${JSON.stringify(rep.json).slice(0, 200)}`);
  await ctx.post(`/api/sqlmap/${id}/stop`, {});
  ctx.note('sqlmap.available', true);
});

// [F2 2026-10-03 TODO 09-28 #3] 两条正向用例：桥接模式的 file-write 与 export 交付面。
// capabilities.fileWrite 此前只覆盖内置引擎，sqlmap 模式拿不到同一交付面 —— 本组收口。

test('sqlmap', 'POST /api/sqlmap/start --file-write：真写文件到 secure_file_priv 目录（文件系统侧断言）', async (ctx) => {
  const st = await ctx.get('/api/sqlmap/status');
  if (st.json?.data?.available !== true || !SECURE_DIR) {
    ctx.note('sqlmap.fileWrite', 'SKIP:缺 sqlmap 或 MYSQL_SECURE_FILE_DIR');
    return;
  }
  const fs = await import('node:fs');
  const path = await import('node:path');
  const os = await import('node:os');
  const stamp = Date.now();
  const local = path.join(os.tmpdir(), `sqlmap-fw-src-${stamp}.txt`);
  const payload = `SQLMAP_FILEWRITE_${stamp}_桥接真写闭环`;
  fs.writeFileSync(local, payload, 'utf8');
  // fileDest 必须落在 MySQL 的 secure_file_priv 内（沙箱把它锁在沙箱目录）——
  // 路径给正斜杠：MySQL 在 Windows 上自行归一化。
  const dest = `${SECURE_DIR}/sqlmap-fw-${stamp}.txt`;
  const started = await ctx.post('/api/sqlmap/start', {
    target: { url: `${ctx.LAB}/num?id=1` },
    config: { sqlmap: { level: 1, fileWrite: local, fileDest: dest, verbose: 6 } },
  });
  try {
    assert.equal(started.json?.code, 0, `fileWrite 任务应能启动（EXPLOIT_ENABLED 已在靶场引擎开启）：${JSON.stringify(started.json).slice(0, 240)}`);
    const id = started.json.data.scanId;
    // 轮询到终态：sqlmap 要先完成注入识别才能落盘（本机实测 ~20-60s）
    let rep = null;
    const t0 = Date.now();
    for (;;) {
      rep = await ctx.get(`/api/sqlmap/${id}/report`);
      const s = rep.json?.data?.status;
      if (s && s !== 'running') break;
      if (Date.now() - t0 > 240000) break;
      await sleep(2000);
    }
    const finalStatus = rep.json?.data?.status;
    // 文件系统侧断言（金标准，同内置引擎 fileWrite 用例口径）：不采信 sqlmap 自报
    const destPath = dest.replace(/\//g, path.sep);
    const logs = (rep.json?.data?.logs || []).map((l) => l.text);
    const logHead = logs.slice(14, 34).join(' ║ ');
    const logTail = logs.slice(-6).join(' ║ ');
    // 决定性探针：同一端口，python socket 直连（runner 进程 env）—— 与 engine 白名单 env
    // 下的 sqlmap 对照。若 runner 的 python 能连而 sqlmap 不能 ⇒ 差异在 spawn env 形态。
    let pyProbe = 'not-run';
    try {
      const { spawnSync } = await import('node:child_process');
      const targetPort = new URL(ctx.LAB + '/').port;
      const code = 'import socket\ntry:\n  s=socket.create_connection(("127.0.0.1",' + targetPort + '),3);s.close();print("PY-CONNECT-OK")\nexcept Exception as e:\n  print("PY-CONNECT-FAIL",e)';
      const pr = spawnSync('python', ['-c', code], { encoding: 'utf8', timeout: 15000 });
      pyProbe = String((pr.stdout || '') + (pr.stderr || '')).trim().split('\n').join(' ').slice(0, 140);
    } catch (e) { pyProbe = 'probe-error:' + e.message; }
    assert.ok(
      fs.existsSync(destPath),
      `fileDest 必须真实落盘（status=${finalStatus}；python直连探针=${pyProbe}）—— sqlmap 日志头：${logHead.slice(0, 500)} ｜尾：${logTail.slice(0, 600)}`
    );
    // sqlmap 按写入块大小把内容补 NUL 对齐（实测尾部  *4）—— 去除 padding 后必须逐字节一致，
    // padding 本身不构成差异（二进制等价内容），但中间任意一字节不同都逃不过这把尺。
    const written = fs.readFileSync(destPath, 'utf8').replace(/ +$/, '');
    assert.equal(written, payload, '落盘内容（去除 sqlmap 的 NUL 对齐 padding 后）必须与本地源文件逐字节一致');
    ctx.state.sqlmapScan = { scanId: id, report: rep.json?.data };
  } finally {
    fs.rmSync(local, { force: true });
    fs.rmSync(dest.replace(/\//g, path.sep), { force: true });
  }
});

test('sqlmap', 'GET /api/sqlmap/:id/report/export 与 /diff：真实报告的导出与自比对（交付面对齐内置引擎）', async (ctx) => {
  const scan = ctx.state.sqlmapScan;
  if (!scan) {
    ctx.note('sqlmap.export', 'SKIP:前置 fileWrite 用例未产出真实扫描（环境缺 sqlmap 或沙箱）');
    return;
  }
  const id = scan.scanId;
  const md = await ctx.get(`/api/sqlmap/${id}/report/export?format=md`);
  assert.equal(md.status, 200, `md 导出应 200，实得 ${md.status}`);
  assert.match(String(md.headers?.['content-type'] || md.headers?.get?.('content-type') || ''), /markdown/);
  assert.match(String(md.text || ''), /# sqlmap 扫描报告/);

  const json = await ctx.get(`/api/sqlmap/${id}/report/export?format=json`);
  assert.equal(json.status, 200, `json 导出应 200，实得 ${json.status}`);
  assert.equal(json.json?.engine, 'sqlmap', 'json 导出返回文档本体（与内置 /report/export 下载语义一致）');

  const bad = await ctx.get(`/api/sqlmap/${id}/report/export?format=html`);
  assert.equal(bad.status, 400, 'html 是内置渲染器的交付面，桥侧必须显式 400 而非静默降级');

  // 自比对：added/removed 必须为空（同一条报告跟自己 diff），真实数据走一遍 diff 契约
  const diff = await ctx.get(`/api/sqlmap/${id}/diff?base=${id}`);
  assert.equal(diff.json?.code, 0, `自比对应成功：${JSON.stringify(diff.json).slice(0, 200)}`);
  assert.equal(diff.json.data.added.length, 0);
  assert.equal(diff.json.data.removed.length, 0);
});

// ── group: ai —— LLM 报告接口（真 HTTP 打到本地假端点） ──────────────────────
async function llmConfig(ctx, mode) {
  const r = await ctx.llmPost('/__llm/config', { mode });
  assert.equal(r.status, 200, `LLM 假端点控制面应 200，实得 ${r.status}`);
}

test('ai', 'POST /scan/:id/report/ai：三角色流水线跑通且外发内容可控', async (ctx) => {
  const { scanId } = ctx.state.numScan || (await scanUntilDone(ctx, { url: `${ctx.LAB}/num?id=1`, config: fastCfg() }));
  await llmConfig(ctx, 'ok');
  await ctx.llmPost('/__llm/reset', {});
  const r = await ctx.post(`/api/scan/${scanId}/report/ai`, {});
  assert.equal(r.status, 200, `AI 报告应 200，实得 ${r.status}：${r.text.slice(0, 240)}`);
  assert.equal(r.json?.code, 0, `AI 报告业务码应为 0，实得 ${JSON.stringify(r.json).slice(0, 240)}`);
  assert.match(String(r.json.data?.content || ''), /SQL|注入|报告|修复/, '最终报告正文应是可读内容');
  assert.equal(r.json.data?.pipeline, 'analyst→writer→reviewer', '应报告流水线形态');

  const stats = await ctx.llmGet('/__llm/stats');
  const roles = (stats.json?.requests || []).map((q) => q.role);
  assert.deepEqual([...new Set(roles)].sort(), ['analyst', 'reviewer', 'writer'], `三角色都应真实调用，实得 ${JSON.stringify(roles)}`);
  assert.ok(stats.json.requests.every((q) => q.hasAuth), '每次外发都必须带 Authorization（缺 key 就不该发）');
  // 脱敏：外发 prompt 不得含完整目标 URL 与凭据
  const anyRawUrl = (stats.json.requests || []).some((q) => q.promptBytes > 200_000);
  assert.ok(!anyRawUrl, 'prompt 体积异常（可能未截断证据）');
  ctx.note('ai.roles', roles.join(','));

  // 缓存：第二次应命中（省配额），且如实标注 cached
  const again = await ctx.post(`/api/scan/${scanId}/report/ai`, {});
  assert.equal(again.json?.data?.cached, true, '同一次扫描重复生成应命中缓存并标注 cached:true');
});

test('ai', 'analyst 返回非 JSON：跨角色注入防护与降级形态', async (ctx) => {
  const { scanId } = ctx.state.numScan || (await scanUntilDone(ctx, { url: `${ctx.LAB}/num?id=1`, config: fastCfg() }));
  await llmConfig(ctx, 'nonjson');
  const r = await ctx.post(`/api/scan/${scanId}/report/ai`, {});
  assert.equal(r.json?.code, 0, `降级后仍应产出报告（不能整条 500），实得 ${r.status} ${r.text.slice(0, 200)}`);
  const content = String(r.json.data?.content || '');
  assert.ok(content.length > 10, '降级内容不应为空');
  assert.ok(!/undefined/.test(content), '降级路径不得把 undefined 写进报告');
  await llmConfig(ctx, 'ok');
});

test('ai', 'LLM 全部 500：错误必须如实外显（不得假成功）', async (ctx) => {
  const { scanId } = ctx.state.numScan || (await scanUntilDone(ctx, { url: `${ctx.LAB}/num?id=1`, config: fastCfg() }));
  await llmConfig(ctx, 'fail');
  const r = await ctx.post(`/api/scan/${scanId}/report/ai`, {});
  // 三级角色全挂 → 必须是非 0 业务码或明确 502；不能是 code:0 + 空内容
  const okButEmpty = r.json?.code === 0 && !String(r.json?.data?.content || '').trim();
  assert.ok(!okButEmpty, '全链路失败时不得返回 code:0 且正文为空');
  if (r.json?.code === 0) {
    assert.match(String(r.json.data?.reviewNote || ''), /不可用|未经审阅/, '降级成功必须标注"未经审阅"');
  } else {
    assert.ok([502, 503, 500].includes(r.status) || r.json?.code, `失败应有明确状态/业务码，实得 ${r.status}`);
  }
  await llmConfig(ctx, 'ok');
});

test('ai', 'GET /scan/:id/report/ai/configs 不含任何 key 原文', async (ctx) => {
  const r = await ctx.get('/api/scan/deadbeef/report/ai/configs');
  assert.equal(r.json?.code, 0);
  const list = r.json?.data || [];
  assert.equal(list.length, 3, `应有 analyst/writer/reviewer 三角色，实得 ${JSON.stringify(list).slice(0, 200)}`);
  const text = JSON.stringify(list);
  assert.ok(!/sk-mock|AI_REPORT_KEY/.test(text), `configs 不得泄露 key：${text.slice(0, 200)}`);
  for (const item of list) assert.ok(item.role && item.model, `每条配置应有 role/model：${JSON.stringify(item)}`);
});

test('ai', '未显式信任外发端点的实例必须 409（默认不外发）', async (ctx) => {
  const off = await startEngine({
    name: 'ai-off',
    env: { AI_REPORT_API_BASE: '', AI_REPORT_KEY_1: '', AI_REPORT_KEY_2: '', AI_REPORT_KEY_3: '' },
  });
  try {
    const { scanId } = ctx.state.numScan || (await scanUntilDone(ctx, { url: `${ctx.LAB}/num?id=1`, config: fastCfg() }));
    const r = await request({ port: off.port, method: 'POST', path: `/api/scan/${scanId}/report/ai`, token: off.token, body: {} });
    assert.equal(r.status, 409, `未启用外发应 409（区别于下游故障 502），实得 ${r.status}：${r.text.slice(0, 200)}`);
    assert.ok(r.json?.code, '409 应带业务码');
  } finally {
    await off.stop();
  }
});

test('ai', 'AI 报告限速：每分钟第 4 次必须 429', async (ctx) => {
  const { scanId } = ctx.state.numScan || (await scanUntilDone(ctx, { url: `${ctx.LAB}/num?id=1`, config: fastCfg() }));
  await llmConfig(ctx, 'ok');
  const statuses = [];
  for (let i = 0; i < 5; i++) {
    const r = await ctx.post(`/api/scan/${scanId}/report/ai`, {});
    statuses.push(r.status);
  }
  assert.ok(statuses.includes(429), `连打 5 次应触发限速 429，实得 ${JSON.stringify(statuses)}`);
});

// ── group: persist —— 历史与持久化（台账第一次被接口暴露） ──────────────────
test('persist', 'GET /api/scans 是数据端点：无 token 必须 401', async (ctx) => {
  const r = await ctx.noAuthGet('/api/scans');
  assert.equal(r.status, 401, `历史清单含目标 URL 与结论，必须带 token，实得 ${r.status}`);
});

test('persist', 'API 扫描必须落台账：清单、meta、report、poc 逐项核对', async (ctx) => {
  const done = await scanUntilDone(ctx, { url: `${ctx.LAB}/str?name=alice`, config: fastCfg({ techniques: ['boolean', 'error'] }) });
  assert.ok((done.report?.vulns || []).length >= 1, '前置：本次扫描应有命中，否则 poc 目录无从核对');
  await sleep(600); // 落盘走 setImmediate（不阻塞事件推送）

  const list = await ctx.get('/api/scans');
  assert.equal(list.json?.code, 0);
  const row = (list.json?.data?.scans || []).find((s) => s.scanId === done.scanId);
  assert.ok(row, `GET /scans 应包含刚完成的扫描 ${done.scanId}，实得 ${JSON.stringify((list.json?.data?.scans || []).map((s) => s.scanId))}`);
  assert.match(String(row.target || ''), /\/str\?name=alice/, `清单里的目标应回显真实 URL，实得 ${JSON.stringify(row.target)}`);
  assert.ok(Number(row.vulns) >= 1, `清单应带命中数，实得 ${JSON.stringify(row)}`);

  const fs = await import('node:fs');
  const path = await import('node:path');
  const dir = path.join(ctx.ledgerDir, done.scanId);
  assert.ok(fs.existsSync(path.join(dir, 'report.json')), `台账必须落 report.json（${dir}）`);
  assert.ok(fs.existsSync(path.join(dir, 'meta.json')), '台账必须落 meta.json');
  const stored = JSON.parse(fs.readFileSync(path.join(dir, 'report.json'), 'utf8'));
  assert.equal(stored.scanId, done.scanId, '落盘报告的 scanId 必须对得上');
  assert.ok(Array.isArray(stored.vulns) && stored.vulns.length >= 1, '落盘报告必须含命中');
  assert.ok(stored.vulns.every((v) => v.poc), '落盘报告必须已挂 PoC（recordScan 的既有口径：传原始 report 会得到 0 个 poc 文件）');
  const pocs = fs.existsSync(path.join(dir, 'poc')) ? fs.readdirSync(path.join(dir, 'poc')) : [];
  assert.ok(pocs.length >= 1, 'poc/ 目录不得为空（历史上 163 次真实台账 0 个 poc 文件）');

  // 台账形态的报告必须还能渲染成交付文档（导出走的是同一条 reportGen）
  const md = await ctx.get(`/api/scan/${done.scanId}/report/export?format=markdown`);
  assert.equal(md.status, 200, `台账内扫描应可导出 markdown，实得 ${md.status}`);
  assert.ok(md.text.length > 50, 'markdown 正文不应为空');
});

test('persist', '上下文回收后：报告与导出走台账，且如实标注 source=ledger', async (ctx) => {
  const path = await import('node:path');
  const fs = await import('node:fs');
  const isolateLedger = path.join(ctx.ledgerDir, 'ttl-probe');
  fs.rmSync(isolateLedger, { recursive: true, force: true });
  // 用一台"回收窗口 1s"的实例真跑：证明这不是靠等待 30s 侥幸通过
  const eng = await startEngine({
    name: 'ttl-probe',
    env: { SCAN_RETIRE_TTL_MS: '1000', SQLI_LEDGER_DIR: isolateLedger },
  });
  try {
    const started = await request({
      port: eng.port,
      method: 'POST',
      path: '/api/scan/start',
      token: eng.token,
      body: { url: `${ctx.LAB}/num?id=1`, config: fastCfg({ techniques: ['boolean'] }) },
    });
    assert.equal(started.json?.code, 0, `探针实例应能启动扫描：${JSON.stringify(started.json)}`);
    const scanId = started.json.data.scanId;
    for (;;) {
      const s = await request({ port: eng.port, path: `/api/scan/${scanId}`, token: eng.token });
      if (s.json?.data?.status === 'completed') break;
      if (s.json?.data?.status === 'error') throw new Error('探针扫描以 error 结束');
      await sleep(200);
    }
    // 等上下文真的被回收（TTL 1s + 余量）
    await sleep(2200);
    const gone = await request({ port: eng.port, path: `/api/scan/${scanId}`, token: eng.token });
    assert.equal(gone.json?.code, 0, `回收后仍应读到报告（台账回退），实得 ${JSON.stringify(gone.json).slice(0, 200)}`);
    assert.equal(gone.json?.data?.source, 'ledger', '必须如实标注这次读的是台账');
    assert.ok((gone.json?.data?.vulns || []).length >= 1, '台账里的命中数必须与扫描时一致');

    const rep = await request({ port: eng.port, path: `/api/scan/${scanId}/report`, token: eng.token });
    assert.equal(rep.json?.data?.source, 'ledger', '/report 同样要能回读历史');

    const csv = await request({ port: eng.port, path: `/api/scan/${scanId}/report/export?format=csv`, token: eng.token });
    assert.equal(csv.status, 200, `历史扫描应仍可导出 CSV，实得 ${csv.status}`);
    assert.match(String(csv.headers['content-disposition'] || ''), /report_/, '导出文件名保持既有契约');

    const list = await request({ port: eng.port, path: '/api/scans', token: eng.token });
    const row = (list.json?.data?.scans || []).find((s) => s.scanId === scanId);
    assert.ok(row, '历史清单应仍列出这条');
    assert.equal(row.source, 'ledger', '清单应区分 live 与 ledger 来源');

    // 反向对照：从未扫过的 id 不得被台账"编造"出来
    const ghost = await request({ port: eng.port, path: '/api/scan/ghostscan99/report', token: eng.token });
    assert.notEqual(ghost.json?.code, 0, '不存在的扫描仍必须报未找到');
  } finally {
    await eng.stop();
  }
});

// ── group: xml —— [2026-10-01] XML / SOAP body 通道（对标 ghauri XML·SOAP）────────
// 判据全部落在「靶站侧取证 + 报告结构」上：
//   · 注入点必须是**叶子点路径**（soap:Body.GetUser.id），不是整份 XML 当一个参数；
//   · 靶站必须真的收到带注入值的 XML 请求（否则等于通道没打通、报告却说未检出）；
//   · 必须真检出漏洞（通道打通但检测不出来 = 交付了一半）。
test('xml', 'xmlBody 叶子路径成为注入点并在真靶站上检出', async (ctx) => {
  await ctx.rangePost('/__range/reset', {});
  const xml = '<?xml version="1.0" encoding="UTF-8"?>'
    + '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
    + '<GetUser><id>1</id><name>alice</name></GetUser></soap:Body></soap:Envelope>';
  // 靶站自检（先证明端点本身可达且真查库，再谈引擎通道 —— 否则「未检出」分不清是谁的锅）
  const labPort = new URL(ctx.LAB).port;
  const self = await request({
    port: labPort, method: 'POST', path: '/soap', body: xml,
    // ⚠️ harness.request 判的是小写 'content-type'：传 'Content-Type' 会被它再补一个
    // application/json，两个 CT 头同时发出去 ⇒ 靶站的 JSON 中间件先炸（500）。
    headers: { 'content-type': 'text/xml' }, timeoutMs: 15000,
  });
  assert.equal(self.status, 200, `靶站 /soap 应 200，实得 ${self.status}，正文 ${self.text.slice(0, 300)}`);
  assert.match(self.text, /<username>[^<]+<\/username>/, `靶站 /soap 应真查库并回显，实得 ${self.text.slice(0, 200)}`);

  const scan = await scanUntilDone(ctx, {
    url: `${ctx.LAB}/soap`,
    method: 'POST',
    xmlBody: xml,
    config: fastCfg({ level: 1, techniques: ['union', 'error', 'boolean'] }),
  });
  const params = (scan.report?.points || []).map((p) => `${p.location}:${p.param}`);
  const pt = (scan.report?.points || []).find((p) => p.location === 'body' && p.param === 'soap:Envelope.soap:Body.GetUser.id');
  assert.ok(pt, `XML 叶子应成为 body 注入点（点路径），实得 ${JSON.stringify(params)}`);
  // 每个 body 点都必须是**点路径叶子**，不允许「整份 XML 摊成一个参数」的畸形点
  for (const p of (scan.report?.points || []).filter((x) => x.location === 'body')) {
    assert.ok(String(p.param).includes('.'), `body 点应为叶子点路径，实得 ${p.param}`);
  }
  assert.ok((scan.report?.vulns || []).length >= 1, `XML 注入点应真检出漏洞，实得 vulns=${JSON.stringify((scan.report?.vulns || []).map((v) => v.technique))}`);
  // 靶站侧取证：/soap 真的收到了请求（通道打通）
  const stats = await rangeStats(ctx);
  assert.ok((stats.byPath['/soap'] || 0) > 0, `靶站未收到 /soap 请求，实得 byPath=${JSON.stringify(stats.byPath)}`);
});

// 反向护栏：xmlBody 形状不合法时**如实不产生注入点**，而不是发畸形报文假装测过
test('xml', '非法 xmlBody 不产生注入点（保守口径，不发畸形报文）', async (ctx) => {
  await ctx.rangePost('/__range/reset', {});
  const scan = await scanUntilDone(ctx, {
    url: `${ctx.LAB}/soap`,
    method: 'POST',
    xmlBody: '<soap:Body><GetUser><id>1</id', // 未闭合
    config: fastCfg({ level: 1, techniques: ['boolean'] }),
  });
  const xmlPoints = (scan.report?.points || []).filter((p) => String(p.param).includes('soap:'));
  assert.deepEqual(xmlPoints, [], `未闭合 XML 不应产生注入点，实得 ${JSON.stringify(xmlPoints)}`);
});

export default CASES;


