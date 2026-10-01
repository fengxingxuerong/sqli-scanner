// ============================================================================
// e2e/fullchain-lab/run.mjs —— E2 全链路验收套件：UI → REST → 引擎 → 真实拖库
// ============================================================================
// [2026-10-01] 09-29 批次（f142233）用真浏览器手工走通了一次全链路；本套件把那条链
// 固化为可重复验收。三段各自成链早已存在（UI 侧组件断言 / REST 侧 api-range-lab /
// 引擎侧 real-mysql-lab），唯独三段串起来的这条链没有自动化——本文件补的就是它。
//
// 链路（一条命令跑完，退出码即验收结论）：
//   ① UI   ：真浏览器驱动真实构建的生产包（dist + server/index.js 单端口托管）
//            走 使用须知 → 填目标 → 高级面板配 extractScope{dump, sqli_lab.users}
//            → 拖库合规二次确认 → 开始扫描
//   ② REST ：POST /api/scan/start 的响应给出 scanId；GET /api/scan/:id 轮询终态
//   ③ 引擎 ：内置引擎对靶站真实注入（pentest 系靶站 mysql2 直连真 MySQL）
//   ④ 拖库 ：extractScope dump 真实读取 sqli_lab.users 全部种子行
//   验收 = 报告页渲染「提取数据 (1 库)」+ 种子行可见（含中文名与单引号名，
//   只能来自真库——同时证明引擎/解析/渲染三段没有各自造假）+ REST 报告
//   verdict=vulnerability_detected + REST 报告里拖库行数与 UI 一致。
//
// 用法：python e2e/run-with-sandbox.py e2e/fullchain-lab/run.mjs
//   （沙箱连接信息经环境变量注入；无需宿主 3306，datadir 用后即弃）
//
// SKIP 口径（与其它靶场一致，零断言、不计通过）：
//   · 找不到可用浏览器（按 msedge → chrome → playwright 自带 chromium 探测）；
//   · dist 不存在且构建失败。
// 环境变量：FULLCHAIN_SERVER_PORT(4577) / MYSQL_LAB_PORT(8141) / FULLCHAIN_HEADLESS(1)
// ============================================================================

import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const ROOT = join(HERE, '..', '..');
const SERVER_PORT = Number(process.env.FULLCHAIN_SERVER_PORT) || 4577;
const LAB_PORT = Number(process.env.MYSQL_LAB_PORT) || 8141;
const HEADLESS = process.env.FULLCHAIN_HEADLESS !== '0';
const ORIGIN = `http://127.0.0.1:${SERVER_PORT}`;

const log = (m) => console.log(`[fullchain] ${m}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function die(msg, code = 1) {
  console.error(`[fullchain] ❌ ${msg}`);
  process.exit(code);
}

// ── 浏览器探测：msedge → chrome → playwright 自带 chromium ─────────────────────
async function resolveLauncher() {
  let chromium;
  try {
    ({ chromium } = await import('playwright'));
  } catch {
    return null; // devDep 未安装（如 CI 未装 playwright）
  }
  for (const channel of ['msedge', 'chrome']) {
    try {
      const b = await chromium.launch({ channel, headless: HEADLESS });
      const v = b.version();
      await b.close();
      log(`浏览器：${channel}（${v}）`);
      return { channel };
    } catch { /* 本机无该渠道，试下一个 */ }
  }
  try {
    const b = await chromium.launch({ headless: HEADLESS });
    const v = b.version();
    await b.close();
    log(`浏览器：playwright 自带 chromium（${v}）`);
    return {};
  } catch { /* 未执行 playwright install */ }
  return null;
}

const children = [];
const spawnNode = (script, args, env) => {
  const c = spawn(process.execPath, [script, ...args], {
    cwd: ROOT,
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  c.stdout.on('data', (d) => process.stdout.write(`  │ ${d}`));
  c.stderr.on('data', (d) => process.stderr.write(`  │ ${d}`));
  children.push(c);
  return c;
};
const waitHttp = async (url, ok = 200, timeoutMs = 30000) => {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.status === ok) return;
    } catch { /* 尚未就绪 */ }
    await sleep(300);
  }
  die(`等待 ${url} 超时（${timeoutMs}ms）`);
};

let pageRef = null;

async function main() {
  // ── 0. 前置 ────────────────────────────────────────────────────────────────
  const launcher = await resolveLauncher();
  if (!launcher) {
    log('SKIP：找不到可用浏览器（需 Edge/Chrome，或先 npx playwright install chromium）。零断言，不计通过。');
    return;
  }
  if (!process.env.MYSQL_HOST && !process.env.MYSQL_PORT) {
    log('提示：未检测到沙箱环境变量——建议用 python e2e/run-with-sandbox.py e2e/fullchain-lab/run.mjs 运行');
  }

  // dist：真实生产构建（套件的可信前提是「浏览器里跑的就是交付物」）；缺失则现场构建
  if (!existsSync(join(ROOT, 'dist', 'index.html'))) {
    log('dist 不存在，现场构建（npx vite build）…');
    const r = spawnSync('npx', ['vite', 'build'], { cwd: ROOT, shell: true, stdio: 'inherit' });
    if (r.status !== 0) die('前端构建失败');
  }

  // ── 1. 真库初始化（复用 real-mysql-lab/init-db.mjs：缺库建库、种子含中文/单引号/跳号）──
  const init = spawnSync(process.execPath, [join(ROOT, 'e2e', 'real-mysql-lab', 'init-db.mjs')], {
    cwd: ROOT,
    env: { ...process.env, MYSQL_DATABASE: process.env.MYSQL_DATABASE || 'sqli_lab' },
    encoding: 'utf8',
  });
  if (init.status !== 0) die(`init-db 失败（exit ${init.status}）：${init.stderr?.slice(-400)}`);
  log('真库初始化完成（sqli_lab.users 含中文/单引号/跳号种子）');

  // ── 2. 靶站（真 MySQL 直连的注入靶场）+ 3. 服务端（dist 托管 + 引擎同进程）────────
  spawnNode(join(HERE, 'target-server.mjs'), [], { MYSQL_LAB_PORT: String(LAB_PORT) });
  await waitHttp(`${ORIGIN.replace(String(SERVER_PORT), LAB_PORT)}/num?id=1`);
  log(`靶站就绪：http://127.0.0.1:${LAB_PORT}/num?id=1`);

  spawnNode(join(ROOT, 'server', 'index.js'), [], {
    PORT: String(SERVER_PORT),
    HOST: '127.0.0.1',
    SSRF_ALLOW_PRIVATE: '1', // 靶站是 127.0.0.1（回环目标），本地验收必开
    ALLOWED_ORIGINS: ORIGIN, // 同源本不需 CORS 头，显式登记免噪音告警
  });
  await waitHttp(`${ORIGIN}/api/health`);
  log(`服务端就绪：${ORIGIN}（托管 dist，单端口）`);

  // ── 4. UI 全链路（真浏览器）────────────────────────────────────────────────
  const { chromium } = await import('playwright');
  const browser = await chromium.launch({ ...launcher, headless: HEADLESS });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  pageRef = page;
  page.setDefaultTimeout(20000);

  let scanId = null;
  // REST 段断言的第一现场：拦截 start 响应拿 scanId（UI 点「开始检测」必经之路上）
  page.on('response', async (res) => {
    if (scanId === null && res.url().includes('/api/scan/start') && res.request().method() === 'POST') {
      try {
        const j = await res.json();
        scanId = j?.scanId || j?.data?.scanId || null;
        if (scanId) log(`REST 段：/api/scan/start → scanId=${scanId}`);
      } catch { /* 非 JSON 响应忽略 */ }
    }
  });

  await page.goto(ORIGIN);
  await page.waitForLoadState('domcontentloaded');

  // ① 使用须知（首次进入弹出；勾选 + 进入）
  const agree = page.getByRole('checkbox', { name: /我已阅读并知晓/ }).first();
  if (await agree.count()) {
    await agree.check();
    await page.getByRole('button', { name: '进入应用' }).click();
    log('UI 段：使用须知已确认');
  }

  // ② 扫描页 + 填目标
  await page.goto(`${ORIGIN}/scan`);
  await page.waitForLoadState('domcontentloaded');
  const urlInput = page.getByPlaceholder('http://example.com/item.php?id=1').first();
  await urlInput.fill(`http://127.0.0.1:${LAB_PORT}/num?id=1`);
  log(`UI 段：目标已填 http://127.0.0.1:${LAB_PORT}/num?id=1`);

  // ③ 高级面板 → 枚举与拖库：选「拖取表数据 (--dump)」+ 指定 sqli_lab.users
  // 两级展开：ScanWizard 的「高级设置」按钮显示面板（button:has-text 只匹配原生 button，
  // 不会撞上面板自己那个 div[role=button] 的折叠头），再点面板折叠头展开分段。
  await page.locator('button:has-text("高级设置")').click();
  await page.locator('div[role="button"]:has-text("高级设置")').click();
  // MUI Select 触发器不是 role=combobox，而是 [aria-haspopup=listbox]（与 bindings 测试同款定位）
  const scopeSelect = page
    .locator('.MuiFormControl-root', { hasText: '枚举 / 拖库动作' })
    .locator('[aria-haspopup="listbox"]');
  await scopeSelect.click();
  await page.getByRole('option', { name: '拖取表数据 (--dump)' }).click();
  await page.getByLabel('目标数据库（逗号分隔，留空=自动枚举）').fill('sqli_lab');
  await page.getByLabel('目标表（逗号分隔，留空=自动枚举）').fill('users');
  log('UI 段：extractScope{dump, sqli_lab.users} 已配置');

  // ④ 开始扫描 + 拖库合规二次确认
  await page.getByRole('button', { name: '开始扫描' }).first().click();
  await page.getByRole('button', { name: '我已知晓，继续' }).click();
  log('UI 段：扫描已启动（拖库二次确认已通过）');
  // 响应到达与断言之间有竞态：轮询等待拦截器拿到 scanId
  const idDeadline = Date.now() + 15_000;
  while (!scanId && Date.now() < idDeadline) await sleep(300);
  if (!scanId) die('15s 内未拦截到 /api/scan/start 响应——UI 段断链或启动失败');

  // ── 5. REST 段：轮询终态（GET /api/scan/:id 的 data.status）──────────────────
  let report = null;
  const startedAt = Date.now();
  const deadline = startedAt + 240_000;
  while (Date.now() < deadline) {
    const res = await fetch(`${ORIGIN}/api/scan/${scanId}`);
    const j = await res.json().catch(() => null);
    const st = j?.data?.status;
    if (st === 'completed' || st === 'error' || st === 'stopped') {
      report = j.data;
      log(`REST 段：终态 ${st}（耗时 ${Math.round((Date.now() - startedAt) / 1000)}s）`);
      break;
    }
    await sleep(1500);
  }
  if (!report) die('240s 内扫描未到终态');
  if (report.status !== 'completed') die(`扫描终态异常：${report.status}（报告 ${JSON.stringify(report.summary || {}).slice(0, 200)}）`);

  // REST 报告断言：verdict 必须是「有洞」三态之一（09-29 缺陷 1 的回归钉），且拖库数据在报告里
  const verdict = report.summary?.verdict;
  if (verdict !== 'vulnerability_detected') {
    die(`REST 报告 verdict=${verdict}，期望 vulnerability_detected（检出为空/不可信）`);
  }
  const collectRows = (data) => {
    // 实测三种形态（与 09-29 修复纪要同源）：scoped dump 的 databases[*].tables[*].rows、
    // 直拖的 data.rows 为「"db.table" → 行数组」键值表、以及数组形态兜底
    const fromDbs = (data?.databases || []).flatMap((d) => (d.tables || []).flatMap((t) => t.rows || []));
    if (fromDbs.length) return fromDbs;
    const r = data?.rows;
    if (Array.isArray(r)) return r;
    if (r && typeof r === 'object') return Object.values(r).flat();
    return [];
  };
  const rows = collectRows(report.data);
  if (rows.length < 5) die(`REST 报告拖库行数 ${rows.length} < 5（种子 users ≥5 行，真库拖库未生效？）`);
  const rowText = JSON.stringify(rows);
  if (!rowText.includes("o'brien") || !rowText.includes('张三')) {
    die('REST 报告拖库数据缺少种子特征行（o\'brien / 张三）——数据可能不是来自真库');
  }
  log(`REST 段：verdict=vulnerability_detected，拖库 ${rows.length} 行（含中文名/单引号名特征行）`);

  // ── 6. UI 报告页渲染断言（提取数据 tab + 种子行可见）────────────────────────
  await page.goto(`${ORIGIN}/report/${scanId}`);
  await page.waitForLoadState('domcontentloaded');
  const tab = page.getByText(/提取数据 \(1 库\)/).first();
  await tab.waitFor({ timeout: 20000 });
  log('UI 段：报告页「提取数据 (1 库)」tab 出现');
  // 点开提取数据 tab（若未默认激活），断言种子行在页面上可见
  await tab.click().catch(() => {}); // 已激活时 click 可选
  // 拖库树默认三层折叠（库/表/数据预览）；搜索框一输入即 queryActive → 全部节点
  // defaultOpen，一次交互让 DataTable 渲染全部行——比逐层点开稳定。
  await page.getByLabel('搜索数据库 / 表名...').fill('users');
  // 数据预览子节点不随 queryActive 展开（Node 无 defaultOpen）——补一次点击渲染 DataTable
  await page.getByText('数据预览').first().click();
  await page.getByText("o'brien").first().waitFor({ timeout: 15000 });
  log('UI 段：报告页渲染出真库种子行（o\'brien）');

  await browser.close();
  log('✅ E2 全链路通过：UI → REST → 引擎 → 真实拖库 → 报告渲染，一条链验收完成');
}

main()
  .catch(async (e) => {
    console.error(`[fullchain] ❌ ${e?.stack || e?.message || e}`);
    if (pageRef) {
      try {
        await pageRef.screenshot({ path: '.box-agent-scratch/fullchain-fail.png', fullPage: true });
        console.error('[fullchain] 失败现场截图：.box-agent-scratch/fullchain-fail.png');
      } catch { /* 页面已不可用 */ }
    }
    process.exitCode = 1;
  })
  .finally(async () => {
    for (const c of children) {
      try { c.kill(); } catch { /* 已退出 */ }
    }
  });
