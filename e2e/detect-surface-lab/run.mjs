// 检测面探针跑批（D154）
//
// 逐条跑 CLI（一键扫描形态），读 report.json 判「这条载体到底测没测到」。
// 判据刻意只有两种结果，不做加权：
//   · vuln 用例：必须检出，漏检 ⇒ exit 1（漏检就是本靶场存在的理由）
//   · safe 用例：必须 0 检出，误报 ⇒ exit 1
//
// 用法：node e2e/detect-surface-lab/run.mjs [--only=id1,id2] [--keep]
// 前置：MySQL 3306 可用（root/root 或 LAB_DB_PASSWORD）；无库 ⇒ exit 2（BLOCKED，不冒充结论）
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const PORT = Number(process.env.DS_LAB_PORT || 8234);
const BASE = `http://127.0.0.1:${PORT}`;
const RESULTS = path.join(HERE, 'results');

const CASES = [
  // 多段路径：id 在中间段（需要 --test-path 才会生成路径点）
  { id: 'multi-seg', path: '/api/users/1/orders', vuln: true, carrier: '多段路径中间段', testPath: true },
  { id: 'multi-seg-safe', path: '/safe/users/1/orders', vuln: false, carrier: '多段路径（安全对照）', testPath: true },
  // .json 后缀段
  { id: 'json-suffix', path: '/api/item/1.json', vuln: true, carrier: '.json 后缀段', testPath: true },
  { id: 'json-suffix-safe', path: '/safe/item/1.json', vuln: false, carrier: '.json 后缀（安全对照）', testPath: true },
  // 矩阵参数（注入点在 path 段内，同样需要 --test-path）
  { id: 'matrix', path: '/api/matrix;cat=1', vuln: true, carrier: '矩阵参数 ;cat=', testPath: true },
  { id: 'matrix-safe', path: '/safe/matrix;cat=1', vuln: false, carrier: '矩阵参数（安全对照）', testPath: true },
  // 重复 query 键
  { id: 'dup-key', path: '/dup?a=1&a=2', vuln: true, carrier: '重复 query 键' },
  { id: 'dup-key-safe', path: '/safe/dup?a=1&a=2', vuln: false, carrier: '重复键（安全对照）' },
  // 基准对照：普通单值 query（应稳定检出，用来证明靶场/链路本身没问题）
  { id: 'plain-query', path: '/dup?a=1', vuln: true, carrier: '普通 query（基准）' },
  { id: 'plain-query-safe', path: '/safe/dup?a=1', vuln: false, carrier: '普通 query（安全对照）' },
  // [D155] 扁平 JSON body + 显式 application/json：目标只吃 JSON，CT 不对直接 415
  {
    id: 'json-body', path: '/api/json', vuln: true, carrier: '扁平 JSON body（声明 CT=json）',
    method: 'POST', body: '{"id":1}', headers: { 'Content-Type': 'application/json' },
  },
  {
    id: 'json-body-safe', path: '/safe/json', vuln: false, carrier: 'JSON body（安全对照）',
    method: 'POST', body: '{"id":1}', headers: { 'Content-Type': 'application/json' },
  },
  // [D159] `-r` 抓包导入的 multipart 上传表单：注入面在文件字段的 filename 上。
  // 旧实现：-r 把 multipart 降级成 urlencoded（目标 415）+ 文件字段当文本发（filename 丢失）
  // ⇒ 0 检出。现在保留 multipart 并按 filename 注入。
  {
    id: 'multipart-file', vuln: true, carrier: 'multipart 文件字段 filename',
    multipart: { path: '/api/upload', filename: 'alice', title: 'report' },
  },
  {
    id: 'multipart-file-safe', vuln: false, carrier: 'multipart 文件字段（安全对照）',
    multipart: { path: '/safe/upload', filename: 'alice', title: 'report' },
  },
  // [D166] `-r` 抓包导入的 multipart 排序表单：注入面在文本字段的**名**上
  // （后端把字段名当 ORDER BY 列名，值被忽略）——`--test-param-names` 的第五个宿主。
  // 旧实现：form carrier 点落到 body 分支产出 data:{} + 继承 multipart CT ⇒ axios
  // 自造另一个 boundary ⇒ 目标等数据到超时（整轮指纹挂死，报告无结论）。
  {
    id: 'multipart-form-name', vuln: true, carrier: 'multipart 字段名（序数差分）',
    formSort: { path: '/api/form-sort' }, paramNames: true,
  },
  {
    id: 'multipart-form-name-safe', vuln: false, carrier: 'multipart 字段名（安全对照）',
    formSort: { path: '/safe/form-sort' }, paramNames: true,
  },
  // [D168] 页面表单 enctype=multipart：`--forms` 路径发现的表单必须按 multipart 提交。
  // 旧实现：-r/表单路径都没有请求头可读 ⇒ 一律 urlencoded ⇒ 只认 multipart 的上传端点 415。
  {
    id: 'form-enctype', vuln: true, carrier: '页面表单 enctype=multipart',
    path: '/form-upload', forms: true,
  },
  {
    id: 'form-enctype-safe', vuln: false, carrier: '页面表单 enctype（安全对照）',
    path: '/safe-form-upload', forms: true,
  },
  // [D169] 多键拼接：字段名进 WHERE 的布尔位置（值已转义）。序数差分在这里只会语法错误，
  // 需要「把键名换成恒真/恒假布尔式」的探针。
  {
    id: 'form-key-bool', vuln: true, carrier: '多键拼接（字段名进 WHERE）',
    formFilter: { path: '/api/form-filter' }, paramNames: true,
  },
  {
    id: 'form-key-bool-safe', vuln: false, carrier: '多键拼接（安全对照）',
    formFilter: { path: '/safe/form-filter' }, paramNames: true,
  },
  // 盲档：SQL 错误被吞成「没查到」⇒ 通用布尔通道的 `{k} AND 1=1-- -` 因 varchar 列名
  // 被当 0 而恒无分化；只有「自洽布尔式 + 行注释」的探针才有信号（D169 实测）
  {
    id: 'form-key-bool-blind', vuln: true, carrier: '多键拼接·盲档（错误被吞）',
    formFilter: { path: '/api/form-filter-blind' }, paramNames: true,
  },
  {
    id: 'form-key-bool-blind-safe', vuln: false, carrier: '多键拼接·盲档（安全对照）',
    formFilter: { path: '/safe/form-filter-blind' }, paramNames: true,
  },
  // [D174] JSON 键名进 WHERE 的布尔位置（盲档：错误被吞成 0 行）
  {
    id: 'json-key-bool-blind', vuln: true, carrier: 'JSON 键名（多键·盲档）',
    jsonFilter: { path: '/api/json-filter-blind' }, paramNames: true,
  },
  {
    id: 'json-key-bool-blind-safe', vuln: false, carrier: 'JSON 键名（多键·安全对照）',
    jsonFilter: { path: '/safe/json-filter-blind' }, paramNames: true,
  },
  // [D170] 爬取到的 REST 链接（无 query 参数）也要按 --test-path 建路径点。
  // 旧行为：爬取只从链接抽 query 键 ⇒ 这类链接 0 个注入点 ⇒ 路径面在爬取路径上缺失。
  {
    id: 'crawl-path', vuln: true, carrier: '爬取链接的路径段',
    path: '/path-links', crawl: 1, testPath: true,
  },
  {
    id: 'crawl-path-safe', vuln: false, carrier: '爬取链接的路径段（安全对照）',
    path: '/safe-path-links', crawl: 1, testPath: true,
  },
  // [D171] 下拉筛选表单的选项值（`<select>` 此前整体不采集 ⇒ 表单只剩按钮字段 ⇒ 0 点）
  {
    id: 'form-select', vuln: true, carrier: '表单 <select> 选项值',
    path: '/select-filter-page', forms: true,
  },
  {
    id: 'form-select-safe', vuln: false, carrier: '表单 <select>（安全对照）',
    path: '/safe-select-filter-page', forms: true,
  },
  // [D172] SPA 的 XHR 端点（REST 形态、无 query）：浏览器爬取发现后按 --test-path 建路径点
  {
    id: 'spa-endpoint-path', vuln: true, carrier: 'SPA XHR 端点的路径段',
    path: '/spa', crawlBrowser: true, testPath: true,
  },
  {
    id: 'spa-endpoint-path-safe', vuln: false, carrier: 'SPA XHR 端点（安全对照）',
    path: '/safe-spa', crawlBrowser: true, testPath: true,
  },
  // [D173] query 参数名进 WHERE 的布尔位置（盲档：错误被吞成 0 行）
  {
    id: 'query-key-bool-blind', vuln: true, carrier: 'query 参数名（多键·盲档）',
    path: '/api/query-filter-blind?name=alice&go=1', paramNames: true,
  },
  {
    id: 'query-key-bool-blind-safe', vuln: false, carrier: 'query 参数名（多键·安全对照）',
    path: '/safe/query-filter-blind?name=alice&go=1', paramNames: true,
  },
];

/**
 * 造一份 Burp 形态的 multipart 抓包（`-r` 的输入）。
 * @param {{path:string, filename:string, title:string}} spec
 * @returns {string} 请求原文
 */
function buildMultipartRequest(spec) {
  const B = '----DSLabFormBoundary7MA4';
  return [
    `POST ${spec.path} HTTP/1.1`,
    `Host: 127.0.0.1:${PORT}`,
    `Content-Type: multipart/form-data; boundary=${B}`,
    '',
    `--${B}`,
    'Content-Disposition: form-data; name="title"',
    '',
    spec.title,
    `--${B}`,
    `Content-Disposition: form-data; name="avatar"; filename="${spec.filename}"`,
    'Content-Type: image/png',
    '',
    'PNGDATA',
    `--${B}--`,
    '',
  ].join('\r\n');
}

/**
 * [D166] 造一份 Burp 形态的 multipart 排序表单抓包：一个文本字段 `id`（值 1）
 * + 一个文件字段 `avatar`。靶场把第一个**文本字段的名**当 ORDER BY 列名 ——
 * 注入面在 name 上，值被忽略（这正是只有改名能打的形态）。
 * @param {{path:string}} spec
 * @returns {string} 请求原文
 */
function buildFormSortRequest(spec) {
  const B = '----DSLabFormBoundary7MA4';
  return [
    `POST ${spec.path} HTTP/1.1`,
    `Host: 127.0.0.1:${PORT}`,
    `Content-Type: multipart/form-data; boundary=${B}`,
    '',
    `--${B}`,
    'Content-Disposition: form-data; name="id"',
    '',
    '1',
    `--${B}`,
    'Content-Disposition: form-data; name="avatar"; filename="cat.png"',
    'Content-Type: image/png',
    '',
    'PNGDATA',
    `--${B}--`,
    '',
  ].join('\r\n');
}

/**
 * [D169] 造一份「多键筛选」表单的抓包：字段 `name=alice` + 按钮 `go=1`。
 * 后端把**字段名**拼成 WHERE 条件（值已转义），所以注入面是字段名。
 * @param {{path:string}} spec
 * @returns {string} 请求原文
 */
function buildFormFilterRequest(spec) {
  const B = '----DSLabFormBoundary7MA4';
  return [
    `POST ${spec.path} HTTP/1.1`,
    `Host: 127.0.0.1:${PORT}`,
    `Content-Type: multipart/form-data; boundary=${B}`,
    '',
    `--${B}`,
    'Content-Disposition: form-data; name="name"',
    '',
    'alice',
    `--${B}`,
    'Content-Disposition: form-data; name="go"',
    '',
    '1',
    `--${B}--`,
    '',
  ].join('\r\n');
}

/**
 * [D174] 造一份「JSON 多键筛选」的抓包：`{"name":"alice","go":"1"}` + `Content-Type: application/json`。
 * 后端把 **JSON 键名**拼进 WHERE（值转义），注入面是键名。
 * @param {{path:string}} spec
 * @returns {string} 请求原文
 */
function buildJsonFilterRequest(spec) {
  return [
    `POST ${spec.path} HTTP/1.1`,
    `Host: 127.0.0.1:${PORT}`,
    'Content-Type: application/json',
    '',
    '{"name":"alice","go":"1"}',
    '',
  ].join('\r\n');
}

/**
 * 解析 --only=a,b
 * @param {string[]} argv
 * @returns {Set<string>|null}
 */
function parseOnly(argv) {
  const hit = argv.find((a) => a.startsWith('--only='));
  if (!hit) return null;
  return new Set(hit.slice('--only='.length).split(',').filter(Boolean));
}

/**
 * 等端口起来（最多 15s）
 * @returns {Promise<void>}
 */
async function waitReady() {
  for (let i = 0; i < 60; i += 1) {
    try {
      const r = await fetch(`${BASE}/healthz`);
      if (r.ok) return;
    } catch { /* 还没起来 */ }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('靶场 15s 内没起来');
}

/**
 * 跑一条用例，返回 {hit, vulnCount, verdict, ms}
 * @param {{id:string,path?:string,vuln:boolean,method?:string,body?:string,headers?:Record<string,string>,multipart?:{path:string,filename:string,title:string}}} c
 * @returns {{hit:boolean, vulns:number, verdict:string, ms:number, exit:number, tail:string}}
 */
function scanCase(c) {
  const outDir = path.join(RESULTS, c.id);
  fs.rmSync(outDir, { recursive: true, force: true });
  const extra = [];
  let targetArgs;
  if (c.multipart) {
    // [D159] 走真实入口 -r：multipart 的字段/文件结构只有抓包导入这条路上有
    const reqPath = path.join(RESULTS, `${c.id}.req.txt`);
    fs.writeFileSync(reqPath, buildMultipartRequest(c.multipart));
    targetArgs = ['-r', reqPath];
  } else if (c.formSort) {
    // [D166] 同上：字段名注入点只有 -r 导入的 multipart 目标上才建
    const reqPath = path.join(RESULTS, `${c.id}.req.txt`);
    fs.writeFileSync(reqPath, buildFormSortRequest(c.formSort));
    targetArgs = ['-r', reqPath];
  } else if (c.formFilter) {
    // [D169] 多键拼接：字段名进 WHERE（布尔位置）
    const reqPath = path.join(RESULTS, `${c.id}.req.txt`);
    fs.writeFileSync(reqPath, buildFormFilterRequest(c.formFilter));
    targetArgs = ['-r', reqPath];
  } else if (c.jsonFilter) {
    // [D174] 多键拼接：JSON body 键名进 WHERE（布尔位置）
    const reqPath = path.join(RESULTS, `${c.id}.req.txt`);
    fs.writeFileSync(reqPath, buildJsonFilterRequest(c.jsonFilter));
    targetArgs = ['-r', reqPath];
  } else {
    targetArgs = ['-u', BASE + c.path];
  }
  if (c.method) extra.push('--method', c.method);
  if (c.body) extra.push('--body', c.body);
  // [D166] --test-param-names 按用例开启（默认关闭，零回归）
  if (c.paramNames) extra.push('--test-param-names');
  // [D168] --forms：页面表单发现（需配 level 5；本靶场用例显式开启）
  if (c.forms) extra.push('--forms', '--level', '5');
  // [D170] --crawl：站内链接爬取（爬到的 REST 链接按 --test-path 建路径点）
  if (c.crawl) extra.push('--crawl', String(c.crawl));
  // [D172] --crawl-browser：headless 渲染 + 捕获 XHR/fetch 端点（端点路径段按 --test-path 建点）
  if (c.crawlBrowser) extra.push('--crawl-browser');
  // [D159] --test-path 按用例开启：路径点对 multipart 目标没有意义，
  //   而且会给只认 /api/upload 的靶场塞一条 404 请求（实测把整场拖到 --timeout）
  if (c.testPath) extra.push('--test-path');
  for (const [k, v] of Object.entries(c.headers || {})) extra.push('--header', `${k}: ${v}`);
  const t0 = Date.now();
  const r = spawnSync(process.execPath, [
    path.join(ROOT, 'scripts/one-click-scan.mjs'),
    ...targetArgs,
    '--level', '3',
    '--technique', 'union,error,boolean',
    '--formats', 'json',
    '-o', outDir,
    '--no-ledger', '--quiet',
    '--retries', '1', '--http-timeout', '8000', '--timeout', '120000',
    ...extra,
  ], {
    cwd: ROOT,
    encoding: 'utf8',
    env: { ...process.env, SSRF_ALLOW_PRIVATE: '1', NO_PROXY: '127.0.0.1,localhost' },
  });
  const ms = Date.now() - t0;
  const reportPath = path.join(outDir, 'report.json');
  let vulns = 0;
  let verdict = 'no-report';
  if (fs.existsSync(reportPath)) {
    const j = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
    vulns = Array.isArray(j.vulns) ? j.vulns.length : 0;
    verdict = j.summary?.verdict || 'unknown';
  }
  // exit 2 = 发现 High/Critical；以报告为准，exit 只做兜底
  return { hit: vulns > 0 || r.status === 2, vulns, verdict, ms, exit: r.status, tail: (r.stderr || '').slice(-400) };
}

/**
 * 靶场是否还活着。
 *
 * [D166] 带两次重试 + 首错落日志：本机密集跑批下 fetch 会偶发**瞬断**（靶场进程
 * 实证存活——任务管理的靶场在 BLOCKED 时仍在服务 curl 正常），单次失败即判
 * 「靶场没了」会把「一次瞬断」误报成整场 BLOCKED（真漏检/误报数字全作废）。
 * 真死的靶场三次全败，BLOCKED 语义不变；首错打码是为留证据（哪个瞬断成因）。
 * @returns {Promise<boolean>}
 */
async function alive() {
  for (let i = 0; i < 3; i += 1) {
    try {
      const r = await fetch(`${BASE}/healthz`);
      if (r.ok) return true;
    } catch (e) {
      if (i === 0) console.error(`[alive] 探活瞬断（重试中）：${e.cause ? e.cause.code || e.cause.message : e.message}`);
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
}

const only = parseOnly(process.argv.slice(2));
const cases = only ? CASES.filter((c) => only.has(c.id)) : CASES;
if (!cases.length) {
  console.error('--only 没匹配到任何用例');
  process.exit(2);
}

fs.mkdirSync(RESULTS, { recursive: true });
const child = spawn(process.execPath, [path.join(HERE, 'server.mjs')], {
  cwd: ROOT,
  stdio: ['ignore', 'pipe', 'pipe'],
  env: { ...process.env },
});
let serverLog = '';
child.stdout.on('data', (d) => { serverLog += d.toString(); });
child.stderr.on('data', (d) => { serverLog += d.toString(); });

let exitCode = 0;
try {
  await waitReady();
  console.log('═══ 检测面探针（D154/D155/D159/D166）═══');
  const rows = [];
  for (const c of cases) {
    // 每条用例前先探活：靶场挂掉必须 BLOCKED，不能把「靶场没了」记成「引擎漏检」
    if (!(await alive())) {
      console.error(`BLOCKED: 扫描 ${c.id} 前靶场已不可达（见 results/server.log）`);
      exitCode = 2;
      break;
    }
    const r = scanCase(c);
    const ok = c.vuln ? r.hit : !r.hit;
    if (!ok) exitCode = 1;
    rows.push({ ...c, ...r, ok });
    console.log(
      `${ok ? '✅' : '❌'} ${c.id.padEnd(16)} ${c.carrier.padEnd(22)} 检出=${r.vulns} verdict=${r.verdict} exit=${r.exit} ${r.ms}ms`
    );
    if (!ok && r.tail) console.log(`   ↳ ${r.tail.replace(/\n/g, ' | ')}`);
  }
  fs.writeFileSync(path.join(RESULTS, 'summary.json'), JSON.stringify({ at: new Date().toISOString(), rows }, null, 2));
  const missed = rows.filter((r) => r.vuln && !r.hit);
  const fps = rows.filter((r) => !r.vuln && r.hit);
  console.log(`\n真值漏检 ${missed.length} / 安全误报 ${fps.length}`);
  if (missed.length) console.log('漏检：' + missed.map((m) => m.id).join(', '));
  if (fps.length) console.log('误报：' + fps.map((m) => m.id).join(', '));
} catch (e) {
  console.error('BLOCKED:', e.message);
  if (serverLog) console.error(serverLog.slice(0, 2000));
  exitCode = 2;
} finally {
  child.kill();
  fs.writeFileSync(path.join(RESULTS, 'server.log'), serverLog);
}
process.exit(exitCode);
