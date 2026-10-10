// ============================================================================
// bearerKeeper.wiring.test.js —— 续期这条链必须**六方都在**（批次 D36，实战 P0-2）
// ============================================================================
// 本仓纪律：一处能力 = 判据 + 生产调用点 + 白名单 + CLI 登记 + 前端类型 + 回收。
// 单测（bearerKeeper.test.js）验的是模块语义，本文件验的是"这些语义有没有真的接进产品"：
//   ① ScanManager.start 真的登记（且非法形状当场抛错、扫描不启动）
//   ② getScanClient 真的挂了 withBearerRefresh（未登记时零行为变化）
//   ③ 包装位置：续期层在**最外**，所以 401 一定被它看见（挂在 loginFlow 之内就永远不触发）
//   ④ 端到端：扫描中途令牌过期 ⇒ 检测器无感（照样跑完），且 refresh 请求本身吃到变换层
//   ⑤ scanRunner 的观察器真的接进可信度守卫 ⇒ 报告里的 reason 指向续期端点（不是"重新登录"）
//   ⑥ 回收：_disposeScan 里 releaseScanRefresh（那是持有 token 的条目，不是缓存）
//   ⑦ 白名单 / CLI / 前端类型三处入口（缺一处 = 能力在库里、用户到不了）
// ============================================================================
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { tmpdir } from 'node:os';

import { ScanManager } from '../src/engine/ScanManager.js';
import { TECHNIQUE_TYPES } from '../src/engine/payloads.js';
import {
  registerScanRefresh,
  releaseScanRefresh,
} from '../src/core/bearerKeeper.js';
import { ensureScanTransform, releaseScanTransform } from '../src/core/requestTransform.js';
import { mergeAuthHeaders } from '../src/core/http/requestContext.js';
import { ErrorCode } from '../src/core/errors.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const read = (rel) => readFileSync(path.join(REPO, rel), 'utf8');

// 变换脚本的白名单根（有一条测试要验"续期请求也过变换层"，需要一个真实可加载的脚本）
const ScriptDir = { dir: mkdtempSync(path.join(tmpdir(), 'sqli-refresh-wire-')) };
process.env.REQUEST_SCRIPT_DIR = ScriptDir.dir;

let seq = 0;
const sid = () => `wire-${Date.now()}-${seq++}`;

after(() => {
  delete process.env.REQUEST_SCRIPT_DIR;
  try { rmSync(ScriptDir.dir, { recursive: true, force: true }); } catch { /* 清理失败不影响结论 */ }
});

// ── ⑥/⑦ 源码文本级接线（把整条链跑起来代价太大，这些位点用文本判据钉） ──
describe('接线：源码里的六个位点', () => {
  test('ScanManager.start 真的登记续期（并把"本次启用了续期"写进 constraints）', () => {
    const src = read('server/src/engine/ScanManager.js');
    assert.match(src, /core\/bearerKeeper\.js/, 'ScanManager 没 import bearerKeeper');
    assert.match(src, /normalizeRefreshConfig\(br\)/, 'start 没做入口归一（非法形状会静默继续）');
    assert.match(src, /registerScanRefresh\(scanId, norm\)/, 'start 没登记');
    assert.match(src, /本次启用 Bearer 自动续期/, 'constraints 少了这条：复测/报告读者看不到会话是怎么维持的');
  });

  test('scanClient 把 withBearerRefresh 挂在 loginFlow 之后（包装链最外）', () => {
    const src = read('server/src/engine/scan/scanClient.js');
    assert.match(src, /core\/bearerKeeper\.js/);
    const iLogin = src.indexOf('withLoginFlow(view, cfg.login)');
    const iRefresh = src.indexOf('withBearerRefresh(view, scanId)');
    assert.ok(iLogin > 0 && iRefresh > 0, '两处包装至少要都在');
    assert.ok(iRefresh > iLogin, '续期层必须在登录层之外：401 先要经过它，否则永远不触发');
    assert.match(src, /refreshActiveForScan\(scanId\)/, '门必须查登记表（未登记时零行为变化）');
  });

  test('scanRunner 把续期结果接进可信度守卫（不是写完 observeRefresh 没人调）', () => {
    const src = read('server/src/engine/scanRunner.js');
    assert.match(src, /setRefreshObserver\(scanId/, '没挂观察器');
    assert.match(src, /validity\.observeRefresh\(ev\)/, '观察器没接到守卫');
    assert.match(src, /refreshActive: refreshOn/, '守卫没被告知"本次配了续期"（文案分支会走错）');
    const guard = read('server/src/core/scanValidityGuard.js');
    assert.match(guard, /if \(!this\.refreshActive\) return;/, 'observeRefresh 必须对未配置目标短路');
  });

  test('回收挂在 lifecycle._disposeScan（与 scope/变换/Cookie Jar 同一张清单）', () => {
    const src = read('server/src/engine/scan/lifecycle.js');
    assert.match(src, /import \{ releaseScanRefresh \} from '..\/..\/core\/bearerKeeper\.js'/);
    assert.match(src, /_disposeScan[\s\S]{0,600}releaseScanRefresh\(scanId\)/, 'dispose 里没回收续期登记');
  });

  test('三处入口：REST 白名单 / CLI 开关 / 前端类型表', () => {
    assert.match(read('server/src/api/scanRoutes.js'), /'bearerRefresh',/, "KNOWN_CFG_KEYS 缺 'bearerRefresh'");
    assert.match(read('server/src/api/scanConfigGuard.js'), /guardBearerRefresh/, 'guard 没进链');
    const args = read('server/bin/cli/args.js');
    for (const f of ['--refresh-url', '--refresh-token', '--refresh-field']) {
      assert.match(args, new RegExp(`a === '${f}'`), `${f} 没在 args.js 登记（会被记成 unknownFlag）`);
    }
    assert.match(read('server/bin/cli/config.js'), /config\.bearerRefresh = br/, 'CLI 没写入 config');
    const constants = read('src/shared/constants.ts');
    assert.match(constants, /'bearerRefresh',/, 'SCAN_CONFIG_KEYS 缺 bearerRefresh');
    assert.match(constants, /bearerRefresh: 'object',/, 'SCAN_CONFIG_VALUE_TYPES 缺 bearerRefresh');
    assert.match(read('server/src/config/defaults.js'), /bearerRefresh: null/, 'defaults 缺关闭态');
  });
});

// ── ①②③④ 行为级：真的跑一遍登记 + 视图 + 发包 ─────────────────────────────
function stubHttp(responder) {
  const sent = [];
  return {
    sent,
    forScan() {
      return {
        request: async (opts) => {
          sent.push({ kind: 'request', opts });
          return responder(opts, sent.length);
        },
        headRequest: async (url, opts) => {
          sent.push({ kind: 'head', url, opts });
          return { status: 200, data: '', headers: {} };
        },
      };
    },
    removeBucket() {},
    releaseGroupBucket() {},
    removeRequestCount() {},
    clearJar() {},
  };
}

function manager(config, responder) {
  const stub = stubHttp(responder);
  const sm = new ScanManager();
  sm.httpClient = stub;
  return { sm, stub };
}

const REFRESH_URL = 'http://target.test/oauth/token';
const okJson = (o) => ({ status: 200, data: JSON.stringify(o), headers: {} });

describe('接线：登记与视图', () => {
  test('未配 bearerRefresh ⇒ 视图上没有续期层（零配置零行为变化）', async () => {
    const id = sid();
    const { sm, stub } = manager({}, () => okJson({ ok: 1 }));
    const view = sm.getScanClient(id, { url: 'http://target.test/p?id=1', config: {} });
    await view.request({ url: 'http://target.test/p?id=1', method: 'GET', headers: {} });
    assert.equal(stub.sent.length, 1);
    assert.equal(stub.sent[0].opts.headers?.Authorization, undefined);
    releaseScanRefresh(id);
  });

  test('登记后 401 ⇒ 视图自动续期并重试，检测层拿到的是 200（它不需要知道发生过续期）', async () => {
    const id = sid();
    registerScanRefresh(id, { url: REFRESH_URL, tokenField: 'access_token' });
    let refreshHits = 0;
    const { sm, stub } = manager({}, (opts, n) => {
      if (String(opts.url).includes('/oauth/token')) {
        refreshHits += 1;
        return okJson({ access_token: 'T2' });
      }
      return n === 1 ? { status: 401, data: 'expired', headers: {} } : okJson({ rows: 1 });
    });
    const view = sm.getScanClient(id, { url: 'http://target.test/p?id=1', config: { bearerRefresh: { url: REFRESH_URL } } });
    const res = await view.request({ url: 'http://target.test/p?id=1', method: 'GET', headers: {} });
    assert.equal(res.status, 200, '续期对检测器必须透明');
    assert.equal(refreshHits, 1);
    const retried = stub.sent.filter((s) => /p\?id=1/.test(String(s.opts?.url || '')));
    assert.equal(retried.at(-1).opts.headers.Authorization, 'Bearer T2');
    releaseScanRefresh(id);
  });

  test('HEAD（--null-connection）也在续期层之内：包装层不得把 headRequest 丢掉', async () => {
    const id = sid();
    registerScanRefresh(id, { url: REFRESH_URL, tokenField: 'access_token' });
    const { sm, stub } = manager({}, () => okJson({ access_token: 'T3' }));
    const view = sm.getScanClient(id, { url: 'http://target.test/p?id=1', config: {} });
    assert.equal(typeof view.headRequest, 'function', 'TODO §10 那三个包装丢 headRequest 的缺陷不得再复制一次');
    await view.headRequest('http://target.test/p?id=1', {});
    assert.ok(stub.sent.some((s) => s.kind === 'head'));
    releaseScanRefresh(id);
  });

  test('抓包令牌走 config.auth.headers 时，续期后**出口**必须真的换成新令牌', async () => {
    // D36 由 e2e/bearer-lab B 场景实测抓到（不是推演）：出口层的合并语义是
    //   mergeAuthHeaders(opts.headers, opts.auth) —— **auth.headers 最后覆盖** per-request 头。
    // 而抓包重建（--header / -r 原始包）带来的 Authorization 走的正是 config.auth.headers 这条路，
    // 于是续期只写 opts.headers 的话：日志说"已取到新 token"、靶站收到的还是旧令牌，整轮继续 401。
    // 这条测试把真 mergeAuthHeaders 接进假客户端，断的是**合完之后线上的那一个值**。
    const id = sid();
    registerScanRefresh(id, { url: REFRESH_URL, tokenField: 'access_token' });
    const captured = { headers: { Authorization: 'Bearer CAPTURED-OLD' } };
    const { sm, stub } = manager({}, (opts) => {
      const wire = mergeAuthHeaders(opts.headers || {}, opts.auth ?? null);
      if (String(opts.url).includes(REFRESH_URL)) return okJson({ access_token: 'NEW' });
      return wire.Authorization === 'Bearer NEW' ? okJson({ rows: 1 }) : { status: 401, data: 'expired', headers: {} };
    });
    const view = sm.getScanClient(id, {
      url: 'http://target.test/p?id=1',
      config: { bearerRefresh: { url: REFRESH_URL, tokenField: 'access_token' } },
    });
    const res = await view.request({
      url: 'http://target.test/p?id=1', method: 'GET', headers: {}, auth: captured,
    });
    assert.equal(res.status, 200, '换不到新令牌 ⇒ auth.headers 把续期结果盖回去了（该缺陷曾实测存在）');
    const targetReqs = stub.sent.filter((s) => !String(s.opts?.url || '').includes(REFRESH_URL));
    const first = mergeAuthHeaders(targetReqs[0].opts.headers, targetReqs[0].opts.auth);
    const last = mergeAuthHeaders(
      targetReqs[targetReqs.length - 1].opts.headers,
      targetReqs[targetReqs.length - 1].opts.auth,
    );
    assert.equal(first.Authorization, 'Bearer CAPTURED-OLD', '口径①：拿到新令牌之前不动用户带来的那枚');
    assert.equal(last.Authorization, 'Bearer NEW');
    assert.equal(captured.headers.Authorization, 'Bearer CAPTURED-OLD', '共享的 config.auth 不得被原地修改');
    releaseScanRefresh(id);
  });

  test('续期请求本身经过变换层（整包加密目标：refresh 明文出去会被拒）', async () => {
    const id = sid();
    const f = path.join(ScriptDir.dir, `wire-refresh-${id}.mjs`);
    writeFileSync(f, 'export function transform(r){ r.url = r.url + (r.url.includes("?") ? "&" : "?") + "sign=SIG"; return r }\n', 'utf8');
    await ensureScanTransform(id, { requestScript: f });
    registerScanRefresh(id, { url: REFRESH_URL, tokenField: 'access_token' });
    let refreshSigned = null;
    const { sm } = manager({}, (opts) => {
      if (String(opts.url).includes('/oauth/token')) {
        refreshSigned = String(opts.url);
        return okJson({ access_token: 'T4' });
      }
      return { status: 401, data: 'x', headers: {} };
    });
    const view = sm.getScanClient(id, {
      url: 'http://target.test/p?id=1',
      config: { bearerRefresh: { url: REFRESH_URL, tokenField: 'access_token' } },
    });
    await view.request({ url: 'http://target.test/p?id=1', method: 'GET', headers: {} });
    assert.ok(refreshSigned, '续期请求应当发出（config.bearerRefresh 是挂载门，登记表只说明"配过"）');
    assert.match(refreshSigned, /sign=SIG/, '续期请求必须同样过变换层（挂在变换之内 ⇒ 自动生效）');
    releaseScanRefresh(id);
    releaseScanTransform(id);
  });
});

// ── ⑤ 端到端：扫描中途过期 + 续期端点坏掉 ⇒ 结论层必须区分开 ────────────────
function makeManager(points, httpClient) {
  const sm = new ScanManager();
  sm.httpClient = httpClient;
  sm.detectors = TECHNIQUE_TYPES.map((t) => ({
    technique: t,
    async detect(ctx) {
      for (let i = 0; i < 4; i++) {
        await ctx.httpClient.request({ url: `${ctx.target.url}&i=${i}${encodeURIComponent("' or '1'='1")}` });
      }
      return { pointId: ctx.point.id, technique: t, vulnerable: false, dbms: null, evidence: '', payloads: [] };
    },
  }));
  sm.fp = { async fingerprint() { return { dbms: null, baseline: { status: 200, headers: {}, body: '' } }; } };
  sm.extractor = { extractProof: async () => null };
  sm._extract = async () => ({});
  sm.parser = { async discover() { return points; } };
  return sm;
}

async function runScan(sm, config) {
  const id = await sm.start({
    url: 'http://mock.test/?v=1',
    config: { concurrency: 1, ratePerSec: 200, prefilter: false, validationSkip: false, ...config },
  });
  for (let i = 0; i < 800; i++) {
    const s = sm.scans.get(id);
    if (s && ['completed', 'error', 'stopped'].includes(s.status)) break;
    await new Promise((r) => setTimeout(r, 5));
  }
  return id;
}

const POINTS = [{ id: 'p1', location: 'url', param: 'v', originalValue: '1' }];

describe('端到端：会话维持进结论层', () => {
  test('配了续期且成功 ⇒ 扫描跑完、verdict 正常、constraints 写明启用（不降级）', async () => {
    let refresh = 0;
    let targetSeq = 0;
    const http = stubHttp((opts) => {
      if (String(opts.url).includes('/oauth/token')) {
        refresh += 1;
        return okJson({ access_token: 'FRESH' });
      }
      targetSeq += 1;
      // 第 8 条起"过期"：只带新 token 才回业务页
      if (targetSeq < 8) return { status: 200, data: `<h1>Item ${targetSeq}</h1>`, headers: {} };
      const auth = String(opts?.headers?.Authorization || '');
      return auth === 'Bearer FRESH'
        ? { status: 200, data: `<h1>Item ${targetSeq}</h1>`, headers: {} }
        : { status: 401, data: 'expired', headers: {} };
    });
    const sm = makeManager(POINTS, http);
    const id = await runScan(sm, { bearerRefresh: { url: REFRESH_URL, tokenField: 'access_token' } });
    const rep = sm.getReport(id);
    assert.ok(refresh >= 1, '令牌过期后必须真的调用过续期端点');
    assert.ok(refresh <= 3, `一次挑战只续一次：实测打了 ${refresh} 次，去重/上限失效`);
    assert.equal(refresh, 1, `只该在过期后打一次续期端点，实测 ${refresh}`);
    assert.equal((sm.scans.get(id)?.status ?? rep.status), 'completed');
    assert.equal(rep.summary.verdict, 'no_vulnerability_detected', '会话被维持住了 ⇒ 阴性结论成立');
    assert.equal(rep.validity.status, 'ok');
    assert.ok(rep.validity.counts.refresh.attempts >= 1);
    assert.equal(rep.validity.counts.refresh.failures, 0);
    assert.match((rep.summary.constraints || []).join('\n'), /本次启用 Bearer 自动续期/);
    releaseScanRefresh(id);
  });

  test('配了续期但端点是坏的 ⇒ verdict=inconclusive 且 reason 指向续期端点本身', async () => {
    let refresh = 0;
    let targetSeq = 0;
    const http = stubHttp((opts) => {
      if (String(opts.url).includes('/oauth/token')) {
        refresh += 1;
        return { status: 500, data: '{"error":"refresh_token_invalid"}', headers: {} };
      }
      targetSeq += 1;
      // 第 8 条起全 401（续期救不回来）
      return targetSeq < 8
        ? { status: 200, data: `<h1>Item ${targetSeq}</h1>`, headers: {} }
        : { status: 401, data: 'expired', headers: {} };
    });
    const sm = makeManager(POINTS, http);
    const id = await runScan(sm, { bearerRefresh: { url: REFRESH_URL, tokenField: 'access_token' } });
    const rep = sm.getReport(id);
    assert.ok(refresh >= 1);
    // ⚠ 报告里的 refresh 计数是**状态锁定那一刻**的快照（与 failStreak/blockHits 同一口径，
    //   见 validity.refresh.test.js 的粘滞语义测试）：session_expired 在连续 3 次 401 时成立，
    //   此后扫描继续跑的续期失败不再追认进 reason —— 所以这里断"至少把失败说出来了"，
    //   而不是断等于总次数（后者会把快照语义改成事后追认，那是另一种失真）。
    const rf = rep.validity.counts.refresh;
    assert.ok(rf.failures >= 1, `可信度里必须带续期失败次数，实测 ${JSON.stringify(rf)}`);
    assert.equal(rf.attempts, rf.failures, '这个场景里每一次续期都失败了：successes 必须为 0');
    assert.equal(rf.successes, 0);
    assert.equal(String(rf.lastWhy).includes('500'), true, `最后一次原因要可见，实测：${rf.lastWhy}`);
    // 会话过期由既有 authLost 判出；本批改的是它给出的**方向**
    assert.equal(rep.validity.status, 'session_expired');
    assert.match(rep.validity.reason, /已配 Bearer 自动续期/);
    assert.match(rep.validity.advice, /bearerRefresh\.url/);
    assert.equal(rep.summary.verdict, 'inconclusive', '0 漏洞 + 不可信 ⇒ 绝不能写成"没有洞"');
    assert.match(rep.summary.verdictNote, /未检出漏洞 ≠ 无漏洞/);
    releaseScanRefresh(id);
  });

  test('未配续期的同一场景 ⇒ 沿用既有文案（不得凭空说"配过续期"）', async () => {
    let targetSeq = 0;
    const http = stubHttp(() => {
      targetSeq += 1;
      return targetSeq < 8
        ? { status: 200, data: `<h1>Item ${targetSeq}</h1>`, headers: {} }
        : { status: 401, data: 'expired', headers: {} };
    });
    const sm = makeManager(POINTS, http);
    const id = await runScan(sm, {});
    const rep = sm.getReport(id);
    assert.equal(rep.validity.status, 'session_expired');
    assert.doesNotMatch(rep.validity.reason, /已配 Bearer 自动续期/);
    assert.equal(rep.validity.counts.refresh.attempts, 0);
    assert.equal(rep.summary.verdict, 'inconclusive');
    releaseScanRefresh(id);
  });

  test('bearerRefresh 形状非法 ⇒ start 当场抛错，扫描不启动（不静默跑一整轮 401）', async () => {
    const http = stubHttp(() => okJson({ ok: 1 }));
    const sm = makeManager(POINTS, http);
    await assert.rejects(
      sm.start({ url: 'http://mock.test/?v=1', config: { bearerRefresh: { url: 'ftp://mock.test/token' } } }),
      (e) => e.code === ErrorCode.INVALID_PARAM,
    );
    assert.equal(http.sent.length, 0, '非法续期配置不得产生任何发包');
  });
});
