// ============================================================================
// e2e/real-world-lab/verify.mjs —— 拟真靶场全面验证驱动
// 用法：node e2e/real-world-lab/verify.mjs [--waf] [--sqlmap]
//
// 流程：
//   1. 启动真实 PG（PGlite）业务靶场，登录 admin 获取会话
//   2. 逐场景扫描（ScanManager 全技术 / dbms 自动指纹）：
//      注入点：items / s(LIKE) / u / api(JSON body) / order(需认证) / reviews
//      安全点：blog / login（期望 0 检出，防误报）
//      二阶：先写入含 SQL 片段的评论 → level=5 爬取首页表单 + /panel 触发
//   3. 可选 --sqlmap：sqlmap CLI 对拍（真实 PG 指纹，不加 --dbms）
//   4. 产出 results/real-world-report.{md,json}
// 判定：注入点检中技术 ⊇ must → PASS；安全点检出 0 → PASS；否则 FAIL。
// ============================================================================
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRealLabApp } from './lab-app.js';
import { ScanManager } from '../../server/src/engine/ScanManager.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const RESULTS_DIR = resolve(HERE, 'results');
const PORT = Number(process.env.REAL_LAB_PORT) || 8130;
const BASE = `http://127.0.0.1:${PORT}`;
const SCENARIO_TIMEOUT_MS = 120_000;

const baseConfig = {
  concurrency: 4,
  ratePerSec: 0,
  retry: 0,
  timeoutMs: 15_000,
  enableExtract: false,
};

function fmtMs(ms) {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

async function runScan(sm, target) {
  const t0 = Date.now();
  const scanId = await sm.start(target);
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > SCENARIO_TIMEOUT_MS) {
      sm.stop(scanId).catch(() => {});
      return { status: 'timeout', vulns: [], points: [], elapsedMs: Date.now() - t0 };
    }
    await new Promise((r) => setTimeout(r, 30));
  }
  const report = sm.getReport(scanId) || { vulns: [] };
  return {
    status: sm.scans.get(scanId)?.status || 'unknown',
    vulns: report.vulns || [],
    points: report.points || [],
    elapsedMs: Date.now() - t0,
  };
}

// —— sqlmap 对拍（真实 PG 指纹，不加 --dbms）——
function runSqlmap(url) {
  const t0 = Date.now();
  try {
    const out = execFileSync(
      'sqlmap',
      [
        '-u', url, '--batch', '--flush-session',
        '--technique=BEUSTQ', '--time-sec=2', '--level=1', '--risk=1', '--threads=4',
        '--output-dir', resolve(HERE, '.sqlmap-rw'),
      ],
      { encoding: 'utf8', timeout: 300_000, windowsHide: true, maxBuffer: 64 * 1024 * 1024 }
    );
    const found = new Set();
    for (const line of out.split(/\r?\n/)) {
      const m = line.match(/^\s*Type:\s*(.+)$/);
      if (!m) continue;
      const l = m[1].toLowerCase();
      if (l.includes('boolean')) found.add('boolean');
      else if (l.includes('error')) found.add('error');
      else if (l.includes('union')) found.add('union');
      else if (l.includes('stacked')) found.add('stacked');
      else if (l.includes('time-based')) found.add('time');
      else if (l.includes('inline')) found.add('inline');
    }
    return { found: [...found], elapsedMs: Date.now() - t0, err: null };
  } catch (e) {
    return { found: [], elapsedMs: Date.now() - t0, err: String(e.message).slice(0, 300) };
  }
}

async function login() {
  const resp = await fetch(`${BASE}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'admin@market' }),
    redirect: 'manual',
  });
  const setCookie = resp.headers.get('set-cookie') || '';
  const sid = setCookie.match(/sid=([^;]+)/)?.[1];
  if (!sid) throw new Error(`登录失败，未取得 sid (status=${resp.status})`);
  return sid;
}

function techs(vulns) {
  return [...new Set((vulns || []).map((v) => v.technique))];
}
const SCENARIOS = [
  { name: 'items_cat', desc: 'GET /items?cat= 类别筛选（数值拼接）', target: () => ({ url: `${BASE}/items?cat=1` }), must: ['boolean'], nice: ['union', 'error'] },
  { name: 'search_like', desc: 'GET /s?q= 商品搜索（LIKE 拼接）', target: () => ({ url: `${BASE}/s?q=键盘` }), must: ['boolean'], nice: [] },
  { name: 'user_id', desc: 'GET /u?id= 用户资料（数值回显）', target: () => ({ url: `${BASE}/u?id=1` }), must: ['boolean'], nice: ['union'] },
  { name: 'api_json', desc: 'POST /api/item JSON body 数值拼接', target: () => ({ url: `${BASE}/api/item`, method: 'POST', bodyParams: { id: '1' } }), must: ['boolean'], nice: ['union', 'error'] },
  { name: 'order_auth', desc: 'GET /order?id= 订单详情（需登录会话）', target: (sid) => ({ url: `${BASE}/order?id=1`, cookieParams: { sid } }), must: ['boolean'], nice: ['union'] },
  { name: 'reviews', desc: 'GET /reviews?id= 评论列表（报错直出）', target: () => ({ url: `${BASE}/reviews?id=1` }), must: ['boolean'], nice: ['error'] },
  { name: 'blog_safe', desc: 'GET /blog?id= 参数化（安全，期望 0 检出）', target: () => ({ url: `${BASE}/blog?id=1` }), must: [], nice: [], expectSafe: true },
  { name: 'login_safe', desc: 'POST /api/login 参数化登录（安全，期望 0 检出）', target: () => ({ url: `${BASE}/login`, method: 'POST', bodyParams: { username: 'admin', password: 'admin@market' } }), must: [], nice: [], expectSafe: true },
];

async function main() {
  const withWaf = process.argv.includes('--waf');
  const withSqlmap = process.argv.includes('--sqlmap');
  const app = await createRealLabApp({ waf: withWaf ? 'modsecurity_crs' : undefined });
  const server = app.listen(PORT, '127.0.0.1');
  await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  // [P0-FIX 2026-09-14] listen 失败硬退出：端口被占/权限问题时静默继续 = 扫错目标出废报告
  server.once('error', (e) => reject(new Error(`靶场监听失败（端口被占？先杀残留进程）: ${e.message}`)));
});

  const sm = new ScanManager();
  const rows = [];
  const sid = await login();
  console.log(`[verify] 靶场就绪：${app._stats.ver}  waf=${withWaf ? 'modsecurity_crs' : 'off'}  sid=${sid.slice(0, 8)}…`);

  try {
    for (const sc of SCENARIOS) {
      const before = app._stats.total;
      const out = await runScan(sm, { ...sc.target(sid), config: { ...baseConfig } });
      const found = techs(out.vulns);
      const requests = app._stats.total - before;
      const mustMiss = sc.must.filter((t) => !found.includes(t));
      const ok = out.status === 'completed' && mustMiss.length === 0 && (sc.expectSafe ? found.length === 0 : true);
      const dbmses = [...new Set((out.vulns || []).map((v) => v.dbms).filter(Boolean))];
      rows.push({ name: sc.name, desc: sc.desc, found, dbmses, must: sc.must, mustMiss, requests, elapsedMs: out.elapsedMs, status: out.status, ok, expectSafe: sc.expectSafe });
      console.log(
        `[${ok ? 'PASS' : 'FAIL'}] ${sc.name}（${sc.desc}）检出=[${found.join(',') || '-'}] ` +
        `mustMiss=[${mustMiss.join(',') || '-'}] 请求=${requests} 耗时=${fmtMs(out.elapsedMs)} dbms=${dbmses.join(',') || '?'}`
      );
      for (const v of out.vulns || []) {
        console.log(`       ↳ ${v.technique}${v.dbms ? ' [' + v.dbms + ']' : ''} ${(v.evidence || '').slice(0, 90)}`);
      }
    }
// —— 二阶注入验证：写入含 SQL 片段的评论 → level=5 爬取 + /panel 触发 ——
    console.log('\n[verify] 二阶注入链路：写入 payload 评论 → 爬取 → /panel 触发');
    const injectBody = "alice's'); SELECT 1; -- ";
    // [P0-FIX 2026-09-06] 自检用 item_id=2（独立商品）：若把爆炸 payload 写进被测的
    // item 1，二阶扫描时 /panel?id=1 的基线本就 500（baselineErr=true）→ 引擎保守跳过
    // 二阶判定 → 永远检不出。基线必须干净，被测通道留给引擎自己的探针。
    await fetch(`${BASE}/comment`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `sid=${sid}` },
      body: JSON.stringify({ item_id: 2, body: injectBody }),
    });
    const panelResp = await fetch(`${BASE}/panel?id=2`, { headers: { cookie: `sid=${sid}` } });
    const panelText = await panelResp.text();
    const panelExplodes = panelResp.status === 500 && /syntax error/i.test(panelText);
    console.log(`[verify] 靶场自检：/panel 对 payload=${JSON.stringify(injectBody)} → ${panelExplodes ? '真实引爆 ✅' : '未引爆 ❌'} (status=${panelResp.status})`);

    const before = app._stats.total;
    const soOut = await runScan(sm, {
      url: `${BASE}/`,
      cookieParams: { sid },
      config: {
        ...baseConfig,
        level: 5,
        crawlForms: true,
        techniques: ['error', 'boolean'],
        // [P1-FIX 2026-09-07] triggerUrl 必须是完整可用 URL（/panel?id=1）：空 id（/panel?id=）
        // 在靶场产生与存储值无关的恒定语法错误（WHERE id =  AND），任何判定路径都会被堵死。
        // 对标 sqlmap --second-url（完整 URL 语义）。同时开启阴性对照提升判定置信。
        secondOrder: { enabled: true, triggerUrls: [`${BASE}/panel?id=1`], negativeControl: true },
      },
    });
    const soReq = app._stats.total - before;
    const soFound = techs(soOut.vulns);
    // [P1-FIX 2026-09-07] 判定口径修正：SecondOrderDetector 命中时报 technique='second_order'，
    // 不会同时报一阶的 'error'（原 must 含 'error' 导致检出也判 FAIL）。
    const soMiss = ['second_order'].filter((t) => !soFound.includes(t));
    const soOk = soOut.status === 'completed' && soMiss.length === 0;
    rows.push({ name: 'second_order', desc: '评论存储 → /panel 触发页二阶注入', found: soFound, dbmses: [], must: ['second_order'], mustMiss: soMiss, requests: soReq, elapsedMs: soOut.elapsedMs, status: soOut.status, ok: soOk, expectSafe: false });
    console.log(`[${soOk ? 'PASS' : 'FAIL'}] second_order 检出=[${soFound.join(',') || '-'}] miss=[${soMiss.join(',') || '-'}] 请求=${soReq} 耗时=${fmtMs(soOut.elapsedMs)}`);

    // —— sqlmap 对拍 ——
    if (withSqlmap) {
      console.log('\n[verify] sqlmap 对拍（真实 PG 指纹，不加 --dbms）…');
      const sq = runSqlmap(`${BASE}/items?cat=1`);
      console.log(`[sqlmap] 检出=[${sq.found.join(',') || '-'}] 耗时=${fmtMs(sq.elapsedMs)}${sq.err ? ` err=${sq.err}` : ''}`);
      rows.push({ name: 'sqlmap_items', desc: 'sqlmap 对拍 /items?cat=1', found: sq.found, dbmses: [], must: [], mustMiss: [], requests: 0, elapsedMs: sq.elapsedMs, status: 'sqlmap', ok: true, expectSafe: false, isSqlmap: true });
    }
  } finally {
    server.close();
  }

  mkdirSync(RESULTS_DIR, { recursive: true });
  const md = [
    '# 真实世界靶场全面验证报告（real-world-lab）',
    '',
    `> 生成时间：${new Date().toISOString()}`,
    `> 靶场：二手集市 Web 应用（Express + **真实 PostgreSQL 18.3 / PGlite**）　WAF=${withWaf ? 'modsecurity_crs' : '无'}　登录会话✔`,
    '> 引擎：ScanManager（全技术，dbms 自动指纹）　sqlmap 对拍：`--technique=BEUSTQ --level=1 --risk=1`',
    '',
    '| 场景 | 类型 | 检出技术 | must | DBMS 识别 | 请求 | 耗时 | 结果 |',
    '|---|---|---|---|---|---|---|---|',
    ...rows.map((r) => `| ${r.name} | ${r.expectSafe ? '安全对照' : r.isSqlmap ? 'sqlmap 对拍' : '注入点'} | ${r.found.join(',') || '-'} | ${r.must.join('+') || '0(安全)'} | ${r.dbmses.join(',') || '-'} | ${r.requests} | ${fmtMs(r.elapsedMs)} | ${r.ok ? '✅' : '❌'} |`),
    '',
    `**注入点召回**：${rows.filter((r) => !r.expectSafe && !r.isSqlmap).filter((r) => r.ok).length}/${rows.filter((r) => !r.expectSafe && !r.isSqlmap).length}`,
    `**误报**：${rows.filter((r) => r.expectSafe && r.found.length > 0).length}`,
    `**总请求**：${rows.reduce((a, r) => a + (r.requests || 0), 0)}`,
    '',
  ].join('\n');
  writeFileSync(resolve(RESULTS_DIR, 'real-world-report.md'), md, 'utf8');
  writeFileSync(resolve(RESULTS_DIR, 'real-world-report.json'), JSON.stringify({ generatedAt: new Date().toISOString(), rows }, null, 2), 'utf8');
  console.log(`\n[verify] 报告：${resolve(RESULTS_DIR, 'real-world-report.md')}`);
  const failed = rows.some((r) => !r.ok);
  process.exitCode = failed ? 1 : 0;
  console.log(failed ? '\n[verify] 存在失败场景' : '\n[verify] 全部通过');
}

main().catch((e) => {
  console.error('[verify] 运行异常：', e);
  process.exitCode = 1;
});