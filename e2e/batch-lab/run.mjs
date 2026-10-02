// ============================================================================
// e2e/batch-lab/run.mjs —— 批量扫描（-m）的两条真机验收：故障隔离 + 集合目标生成
//
// 场景 A（故障隔离）：**100 个目标里混进一个不通的，剩下 99 个还能不能扫完、结果在不在**。
//   原实现（两处粘贴的并发池）在任一目标抛错时 Promise.all 直接 reject ⇒ 整批中断、
//   已完成的报告全丢、顶层无 catch ⇒ unhandled rejection，且看不出是哪个目标坏的。
//
// 场景 B（集合目标生成）：`-m` 给一份 **OpenAPI / HAR** 时，能不能展开成 N 个目标逐个扫。
//   对标 sqlmap 2.0 的 OpenAPI 目标生成；ghauri 的 `-m`(experimental) 仍只吃文本 URL。
//   本仓此前 `-r` 能吃集合但**只取第 1 条**、`-m` 只吃文本 URL ⇒ 这条入口是断的。
//
// 真实性取舍（先说清楚边界）：
//   · 目标用**真 SQL 引擎**（sql.js / SQLite WASM）+ 真 HTTP 靶站 + 真 CLI 进程（spawn）。
//     不是 mock：注入是真的拼进 SQL、真的被执行。
//   · 本套件验的是**编排与目标来源**（故障隔离 / 结果落盘 / 摘要点名 / 集合展开），
//     不是检出能力 —— 检出能力由 real-mysql-lab / api-range-lab 那两套真 MySQL 套件背书。
//   · 单独的 SQLite 检出数字不作为对外口径（方言与真 MySQL 不同源）。
// ============================================================================
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');

/** 起一个真 SQLite 后端的靶站（数值型 / 字符串型 / POST 表单 三个注入点） */
async function startSqliteTarget() {
  // ⚠️ Windows ESM：绝对路径必须转成 file:// URL，否则 `import('D:\\...')` 抛
  // ERR_UNSUPPORTED_ESM_URL_SCHEME（protocol 'd:'）
  const { loadSqlJs } = await import(pathToFileURL(path.join(ROOT, 'server', 'src', 'core', 'sqlJsLoader.js')).href);
  const initSqlJs = await loadSqlJs();
  const SQL = await (typeof initSqlJs === 'function' ? initSqlJs({}) : initSqlJs);
  const db = new SQL.Database();
  db.run('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT)');
  db.run("INSERT INTO users VALUES (1,'admin','admin@lab.local'),(2,'alice','alice@lab.local')");

  const run = (sql) => {
    try {
      const res = db.exec(sql);
      if (!res.length) return [];
      const cols = res[0].columns;
      return res[0].values.map((row) => Object.fromEntries(cols.map((c, i) => [c, row[i]])));
    } catch {
      return null; // SQL 错误 → 无行（布尔/报错型目标行为）
    }
  };

  // 每个请求的时间戳（限速测量用：全局平均速率 / 单目标峰值窗口）
  const hits = [];
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://127.0.0.1');
    hits.push({ t: Date.now(), p: u.pathname });
    const reply = (r) => {
      const bodyHtml = r === null
        ? '<html><body><div class="card">error</div></body></html>'
        : `<html><body><table>${r.map((x) => `<tr><td>${x.id}</td><td>${x.username}</td><td>${x.email}</td></tr>`).join('')}</table></body></html>`;
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end(`<html><body>${bodyHtml}</body></html>`);
    };
    if (u.pathname === '/num') {
      reply(run(`SELECT id, username, email FROM users WHERE id = ${u.searchParams.get('id') ?? '1'}`));
    } else if (u.pathname === '/str') {
      reply(run(`SELECT id, username, email FROM users WHERE username = '${u.searchParams.get('name') ?? 'alice'}'`));
    } else if (u.pathname === '/form' && req.method === 'POST') {
      // POST 表单：body 里的 name 直接拼进 SQL（验「集合条目的 body 有没有保住」）
      let body = '';
      req.on('data', (d) => (body += d));
      req.on('end', () => {
        const nm = new URLSearchParams(body).get('name') || 'alice';
        reply(run(`SELECT id, username, email FROM users WHERE username = '${nm}'`));
      });
    } else if (u.pathname === '/empty') {
      // 无参数的"立刻结束"端点：0 注入点 ⇒ 几乎不发请求。
      // 场景 C3 用它把并发位占掉再迅速腾空，逼出「排空后剩下的目标能否吃满预算」。
      hits.push({ t: Date.now(), p: '/empty' });
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' }).end('<html><body>no params here</body></html>');
    } else {
      res.writeHead(404).end('not found');
    }
  });
  const port = await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
  return { port, hits, resetHits: () => (hits.length = 0), stop: () => new Promise((r) => server.close(r)) };
}

/** spawn 真 CLI 进程，收集 stdout/stderr 与退出码 */
async function runCli(args) {
  const p = spawn(process.execPath, [path.join(ROOT, 'server', 'bin', 'cli.js'), ...args], {
    cwd: ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  p.stdout.on('data', (d) => (stdout += d));
  p.stderr.on('data', (d) => (stderr += d));
  const code = await new Promise((resolve) => p.once('exit', resolve));
  return { code, stdout, stderr };
}

const target = await startSqliteTarget();
const outDir = path.join(ROOT, 'logs', 'batch-lab-out');
fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });

// 靶站基址（单一真值源）。
// ⚠️ 此前 `base` 只定义在「场景 B」的块作用域里，而场景 C1/C3 也引用它 —— ESLint no-undef
// 早已报出（运行到那两个场景就是 ReferenceError，整套件崩）。
// 修法不是在两个块里各抄一份，而是上提到此处，让所有场景共用同一个定义。
const base = `http://127.0.0.1:${target.port}`;

const fails = [];
const check = (cond, msg) => { if (!cond) fails.push(msg); };
const note = (s) => console.log(`   ${s}`);

// ============================================================================
// 场景 A：URL 列表 + 死目标 —— 故障隔离
// ============================================================================
{
  const urls = [
    `http://127.0.0.1:${target.port}/num?id=1`,
    `http://127.0.0.1:1/dead`,
    `http://127.0.0.1:${target.port}/str?name=alice`,
  ];
  const listFile = path.join(outDir, 'urls.txt');
  fs.writeFileSync(listFile, urls.join('\n') + '\n', 'utf8');
  const aOut = path.join(outDir, 'A');

  const { code, stderr } = await runCli([
    '-m', listFile, '--out', aOut, '--format', 'json', '--concurrency', '2',
    '--level', '2', '--risk', '2',
    // 参数名以 bin/cli/help.js 为准（CLI 对未知参数**硬失败**，写错会直接拒启动）
    '--rate', '0', '--req-rate', '0', '--timeout', '60000',
  ]);

  // ① 进程必须**正常退出**：整批中断时原实现是 unhandled rejection（退出码 1 且无摘要）
  check(code === 0 || code === 2, `A: 批量应正常退出（0 或 2），实得 ${code}`);
  // ② 摘要必须给出成功/失败/需复核三类计数，且**点名**"什么都没测"的目标。
  //    （死目标不会抛错：引擎照样产出一份 points=0 的报告 —— 这才是它最会骗人的地方）
  check(/需复核/.test(stderr), `A: 摘要未点名需复核目标，stderr 尾部：${stderr.slice(-500)}`);
  check(stderr.includes('127.0.0.1:1/dead'), 'A: 需复核清单里没有那个死 URL');
  check(/个需复核/.test(stderr), `A: 摘要缺需复核计数：${stderr.slice(-500)}`);
  // ③ 成功目标的报告必须真的落盘（原实现池一 reject 就全丢）
  const files = fs.existsSync(aOut) ? fs.readdirSync(aOut).filter((f) => f.endsWith('.json')) : [];
  check(files.length >= 3, `A: 3 个目标都应有报告落盘，实得 ${files.length}：${JSON.stringify(fs.existsSync(aOut) ? fs.readdirSync(aOut) : [])}`);
  // ④ 死目标的结论**不得是「无漏洞」** —— 一个检测请求都没发时，阴性结论是假的
  const deadReport = files.find((f) => f.includes('_1_dead'));
  check(!!deadReport, 'A: 未找到死目标的报告文件');
  if (deadReport) {
    const r = JSON.parse(fs.readFileSync(path.join(aOut, deadReport), 'utf8'));
    check((r.points || []).length === 0, `A: 死目标应 0 注入点，实得 ${(r.points || []).length}`);
    check(
      r?.summary?.verdict === 'inconclusive',
      `A: 死目标（不可达）的结论必须是 inconclusive，实得 ${r?.summary?.verdict}`,
    );
  }
  // ⑤ 正常目标必须真检出（证明编排改动没有把检出链路弄坏）
  const numReport = files.find((f) => f.includes('_num_id_1'));
  check(!!numReport, 'A: 未找到 /num 目标的报告文件');
  if (numReport) {
    const r = JSON.parse(fs.readFileSync(path.join(aOut, numReport), 'utf8'));
    check((r.vulns || []).length > 0, `A: 真 SQLite 靶站 /num 应检出注入，实得 ${(r.vulns || []).length} 条`);
  }
  // ⑥ 报告内容是真的（有 points），不是空壳
  for (const f of files) {
    try {
      const r = JSON.parse(fs.readFileSync(path.join(aOut, f), 'utf8'));
      check(Array.isArray(r?.points) || Array.isArray(r?.findings), `A: 报告 ${f} 结构异常（无 points）`);
    } catch (e) {
      fails.push(`A: 报告 ${f} 不是合法 JSON：${e.message}`);
    }
  }
  note(`A 场景：退出码 ${code}，报告 ${files.length} 份，失败点名 ${/127\.0\.0\.1:1\/dead/.test(stderr) ? 'yes' : 'no'}`);
}

// ============================================================================
// 场景 B：`-m` 吃请求集合（OpenAPI / HAR）⇒ 展开成 N 个目标
// ============================================================================
const B = { openapi: null, har: null, yaml: null };
{
  // OpenAPI：两个 GET 端点（对标 sqlmap 2.0 的 OpenAPI 目标生成）
  const openapi = {
    openapi: '3.0.0',
    info: { title: 'batch-lab', version: '1.0.0' },
    servers: [{ url: base }],
    paths: {
      '/num': { get: { parameters: [{ name: 'id', in: 'query', required: true, schema: { type: 'integer' }, example: 1 }] } },
      '/str': { get: { parameters: [{ name: 'name', in: 'query', required: true, schema: { type: 'string' }, example: 'alice' }] } },
    },
  };
  const oaFile = path.join(outDir, 'openapi.json');
  fs.writeFileSync(oaFile, JSON.stringify(openapi, null, 2), 'utf8');

  // HAR：一个 POST 表单请求（验 body / method / headers 有没有保住）
  const har = {
    log: {
      version: '1.2',
      entries: [
        {
          request: {
            method: 'POST',
            url: `${base}/form`,
            headers: [
              { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
              { name: 'X-Lab', value: 'batch' },
            ],
            postData: { mimeType: 'application/x-www-form-urlencoded', text: 'name=alice' },
          },
        },
      ],
    },
  };
  const harFile = path.join(outDir, 'site.har');
  fs.writeFileSync(harFile, JSON.stringify(har, null, 2), 'utf8');

  const bOut = path.join(outDir, 'B');
  const { code, stderr } = await runCli([
    '-m', oaFile, '--out', bOut, '--format', 'json', '--concurrency', '2',
    '--level', '2', '--risk', '2', '--rate', '0', '--req-rate', '0', '--timeout', '60000',
  ]);
  // ① 格式必须**被点名**（静默降级是本仓反复踩的坑）
  check(/请求集合（openapi）/.test(stderr), `B-openapi: 未点名识别出 openapi 集合：${stderr.slice(0, 400)}`);
  check(/展开 2 个目标/.test(stderr), `B-openapi: 未展开出 2 个目标：${stderr.slice(0, 400)}`);
  // ② OpenAPI 的 caveat 必须往传（值是 example/default，不是抓包）
  check(/example|接口定义/.test(stderr), 'B-openapi: 丢了「值是 example/default」的 caveat');
  check(code === 0 || code === 2, `B-openapi: 应正常退出（0 或 2），实得 ${code}`);
  const oaFiles = fs.existsSync(bOut) ? fs.readdirSync(bOut).filter((f) => f.endsWith('.json')) : [];
  check(oaFiles.length >= 2, `B-openapi: 2 个目标都应有报告落盘，实得 ${oaFiles.length}`);
  const oaHit = oaFiles.filter((f) => {
    try { return (JSON.parse(fs.readFileSync(path.join(bOut, f), 'utf8')).vulns || []).length > 0; } catch { return false; }
  });
  check(oaHit.length >= 1, `B-openapi: 展开的目标里应有真检出，实得 ${oaHit.length}/${oaFiles.length}`);
  B.openapi = { code, files: oaFiles.length, hits: oaHit.length };

  // —— HAR（POST + body） ——
  const hOut = path.join(outDir, 'B-har');
  const h = await runCli([
    '-m', harFile, '--out', hOut, '--format', 'json', '--concurrency', '1',
    '--level', '2', '--risk', '2', '--rate', '0', '--req-rate', '0', '--timeout', '60000',
  ]);
  check(/请求集合（har）/.test(h.stderr), `B-har: 未点名识别出 har 集合：${h.stderr.slice(0, 400)}`);
  check(/展开 1 个目标/.test(h.stderr), `B-har: 未展开出 1 个目标：${h.stderr.slice(0, 400)}`);
  check(h.code === 0 || h.code === 2, `B-har: 应正常退出（0 或 2），实得 ${h.code}；stderr 尾部：${h.stderr.slice(-600)}`);
  const harFiles = fs.existsSync(hOut) ? fs.readdirSync(hOut).filter((f) => f.endsWith('.json')) : [];
  check(harFiles.length >= 1, `B-har: POST 目标应有报告落盘，实得 ${harFiles.length}；stderr 尾部：${h.stderr.slice(-600)}`);
  // ★ 关键：POST 的 body 必须保住 —— 保不住就只剩 URL（无 query）⇒ 0 注入点 ⇒ 什么都没测
  let harPoints = -1;
  let harVulns = -1;
  if (harFiles.length) {
    const r = JSON.parse(fs.readFileSync(path.join(hOut, harFiles[0]), 'utf8'));
    harPoints = (r.points || []).length;
    harVulns = (r.vulns || []).length;
    const m = String(r?.target?.method || r?.target?.config?.method || '');
    check(harPoints > 0, `B-har: POST body 未保住 ⇒ 0 注入点（等于这个目标根本没测），实得 ${harPoints}`);
    check(harVulns > 0, `B-har: POST 表单目标应检出注入，实得 ${harVulns} 条`);
    check(!m || m.toUpperCase() === 'POST', `B-har: 报告里的方法应是 POST，实得 ${m || '(无)'}`);
  }
  B.har = { code: h.code, files: harFiles.length, points: harPoints, vulns: harVulns };
  note(`B 场景：openapi ${B.openapi.files} 份报告/${B.openapi.hits} 条检出；har points=${B.har.points} vulns=${B.har.vulns}`);

  // —— OpenAPI **YAML**（零依赖子集解析器）：规范绝大多数以 YAML 流通，这条通不通
  //    直接决定上面那个能力在实战里能不能用 ——
  const yamlText = [
    'openapi: 3.0.0',
    'info:',
    '  title: batch-lab',
    '  version: 1.0.0',
    'servers:',
    `  - url: ${base}`,
    'paths:',
    '  /num:',
    '    get:',
    '      parameters:',
    '        - name: id',
    '          in: query',
    '          required: true',
    '          schema:',
    '            type: integer',
    '          example: 1',
    '  /str:',
    '    get:',
    '      parameters:',
    '        - name: name',
    '          in: query',
    '          schema:',
    '            type: string',
    '          example: alice',
    '',
  ].join('\n');
  const yamlFile = path.join(outDir, 'openapi.yaml');
  fs.writeFileSync(yamlFile, yamlText, 'utf8');
  const yOut = path.join(outDir, 'B-yaml');
  const y = await runCli([
    '-m', yamlFile, '--out', yOut, '--format', 'json', '--concurrency', '2',
    '--level', '2', '--risk', '2', '--rate', '0', '--req-rate', '0', '--timeout', '60000',
  ]);
  check(/请求集合（openapi-yaml）/.test(y.stderr), `B-yaml: 未点名识别出 openapi-yaml：${y.stderr.slice(0, 400)}`);
  check(/展开 2 个目标/.test(y.stderr), `B-yaml: 未展开出 2 个目标：${y.stderr.slice(0, 400)}`);
  check(y.code === 0 || y.code === 2, `B-yaml: 应正常退出（0 或 2），实得 ${y.code}；stderr 尾部：${y.stderr.slice(-600)}`);
  const yamlFiles = fs.existsSync(yOut) ? fs.readdirSync(yOut).filter((f) => f.endsWith('.json')) : [];
  check(yamlFiles.length >= 2, `B-yaml: 2 个目标都应有报告落盘，实得 ${yamlFiles.length}`);
  const yamlHits = yamlFiles.filter((f) => {
    try { return (JSON.parse(fs.readFileSync(path.join(yOut, f), 'utf8')).vulns || []).length > 0; } catch { return false; }
  });
  check(yamlHits.length >= 1, `B-yaml: 展开的目标里应有真检出，实得 ${yamlHits.length}/${yamlFiles.length}`);
  B.yaml = { files: yamlFiles.length, hits: yamlHits.length };
  note(`B 场景（YAML）：${B.yaml.files} 份报告 / ${B.yaml.hits} 条检出`);
}

// ============================================================================
// 场景 C：共享限速桶（2026-10-03）—— 总量上限 + 对照组 + 排空后自动吃满
//   旧方案：启动时按并发度均分（rate/concurrency，算一次不再变）⇒ 队列排空后剩下的
//   目标仍按 1/并发度 跑，预算白白闲着。新方案：整批共用一个令牌桶。
//   三条判据都是**可证伪**的：C2 是 C1 的对照组（证明限制来自限速而非目标本来就慢），
//   C3 用「均分方案下绝不可能达到的速率」来证明动态吃满确实发生。
// ============================================================================
const RATE = 6; // 总速率上限（req/s）
const CONC = 3;
const rateStats = (arr) => {
  if (arr.length < 2) return { n: arr.length, mean: 0, peak: 0 };
  const ts = arr.map((h) => h.t).sort((a, b) => a - b);
  const span = (ts[ts.length - 1] - ts[0]) / 1000;
  // 峰值：任意 1 秒滑窗内的最大请求数
  let peak = 0;
  for (let i = 0; i < ts.length; i++) {
    let j = i;
    while (j + 1 < ts.length && ts[j + 1] - ts[i] <= 1000) j++;
    peak = Math.max(peak, j - i + 1);
  }
  return { n: arr.length, mean: span > 0 ? arr.length / span : 0, peak };
};

// —— C1：限速生效时的总量（3 个真目标）——
{
  target.resetHits();
  const listFile = path.join(outDir, 'C-urls.txt');
  fs.writeFileSync(
    listFile,
    [`${base}/num?id=1`, `${base}/str?name=alice`, `${base}/num?id=2`].join('\n') + '\n',
    'utf8',
  );
  const o = path.join(outDir, 'C1');
  const t0 = Date.now();
  const r = await runCli([
    '-m', listFile, '--out', o, '--format', 'json', '--concurrency', String(CONC),
    '--level', '1', '--risk', '1', '--technique', 'boolean,error',
    '--rate', String(RATE), '--timeout', '60000',
  ]);
  const elapsed = (Date.now() - t0) / 1000;
  const st = rateStats(target.hits);
  check(r.code === 0 || r.code === 2, `C1: 应正常退出（0 或 2），实得 ${r.code}；stderr 尾部：${r.stderr.slice(-400)}`);
  check(st.n >= 20, `C1: 请求样本太少（${st.n}）不足以测速率 —— 套件在空转`);
  // 令牌桶允许突发 capacity=rate，故判**平均**速率；留 25% 余量吸收进程启动与建连耗时
  check(
    st.mean <= RATE * 1.25,
    `C1: 全局平均速率应 ≤ ${RATE} req/s（共享桶的总量保证），实得 ${st.mean.toFixed(2)}`
    + `（${st.n} 个请求 / ${elapsed.toFixed(1)}s）`,
  );
  note(`C1 限速：${st.n} 请求 / ${elapsed.toFixed(1)}s ⇒ 平均 ${st.mean.toFixed(2)} req/s（上限 ${RATE}，均值判据 ≤ ${(RATE * 1.25).toFixed(1)}）`);
}

// —— C2：对照组 —— 同样命令但 --rate 0（不限速）⇒ 平均速率必须**明显高于** C1。
//   没有这条，C1 的"没超标"可能只是因为目标本来就慢，限速根本没参与。
{
  target.resetHits();
  const listFile = path.join(outDir, 'C-urls.txt');
  const o = path.join(outDir, 'C2');
  const t0 = Date.now();
  const r = await runCli([
    '-m', listFile, '--out', o, '--format', 'json', '--concurrency', String(CONC),
    '--level', '1', '--risk', '1', '--technique', 'boolean,error',
    '--rate', '0', '--timeout', '60000',
  ]);
  const elapsed = (Date.now() - t0) / 1000;
  const st = rateStats(target.hits);
  check(r.code === 0 || r.code === 2, `C2: 应正常退出（0 或 2），实得 ${r.code}`);
  check(st.n >= 20, `C2: 请求样本太少（${st.n}）不足以做对照`);
  check(
    st.mean > RATE * 1.5,
    `C2: 不限速时的平均速率应明显高于限速档（证明 C1 的限制来自限速，不是目标本来就慢），`
    + `实得 ${st.mean.toFixed(2)} vs C1 上限 ${RATE}`,
  );
  note(`C2 对照（--rate 0）：${st.n} 请求 / ${elapsed.toFixed(1)}s ⇒ 平均 ${st.mean.toFixed(2)} req/s`);
}

// —— C3：排空后自动吃满 —— 均分方案下**绝不可能**达到的速率 ——
//   3 个并发位里 2 个是「/empty」（无参数 ⇒ 0 注入点 ⇒ 几乎不发请求），
//   均分方案下真目标被钉死在 rate/concurrency = 2 req/s；共享桶下它应能跑到接近 RATE。
{
  target.resetHits();
  const listFile = path.join(outDir, 'C3-urls.txt');
  fs.writeFileSync(listFile, [`${base}/empty`, `${base}/empty`, `${base}/num?id=1`].join('\n') + '\n', 'utf8');
  const o = path.join(outDir, 'C3');
  const r = await runCli([
    '-m', listFile, '--out', o, '--format', 'json', '--concurrency', String(CONC),
    '--level', '2', '--risk', '1', '--technique', 'boolean,error',
    '--rate', String(RATE), '--timeout', '60000',
  ]);
  check(r.code === 0 || r.code === 2, `C3: 应正常退出（0 或 2），实得 ${r.code}`);
  const numHits = target.hits.filter((h) => h.p === '/num');
  const st = rateStats(numHits);
  // 均分方案的硬上界是 RATE/CONC = 2 req/s ⇒ 峰值窗口取 3 即可证伪（>2），
  // 取 4 是为了留出"刚好卡在边界"的争议空间。
  const splitCap = RATE / CONC;
  check(st.n >= 12, `C3: 真目标请求样本太少（${st.n}）不足以测速率`);
  check(
    st.peak > splitCap + 1,
    `C3: 真目标的峰值窗口应超过均分方案的上界 ${splitCap.toFixed(1)} req/s（${splitCap + 1}），`
    + `实得 ${st.peak} —— 未超过说明预算仍被启动时算死的份额钉住`,
  );
  // 总量保证在这条形态下仍要成立
  const all = rateStats(target.hits);
  check(all.mean <= RATE * 1.25, `C3: 总量保证仍须成立（≤ ${RATE}），实得 ${all.mean.toFixed(2)}`);
  note(`C3 动态吃满：真目标峰值 ${st.peak} req/s（均分方案上界 ${splitCap.toFixed(1)}）；全局平均 ${all.mean.toFixed(2)}`);
}

await target.stop();

if (fails.length) {
  console.error(`[FAIL] 批量靶场：\n  - ${fails.join('\n  - ')}`);
  process.exit(1);
}
console.log('[PASS] 批量靶场：A 故障隔离（3 目标 2 成功 1 需复核，死目标结论 inconclusive）+ B 集合展开（openapi JSON/YAML 各 2 目标 + har POST body 保住）');
console.log(`   A 失败点名与 inconclusive：已断言`);
console.log(`   B openapi(JSON)：${B.openapi.files} 份报告 / ${B.openapi.hits} 条检出；B openapi(YAML)：${B.yaml.files} 份 / ${B.yaml.hits} 条；B har：points=${B.har.points} vulns=${B.har.vulns}`);
console.log('   检出数仅记录，不作对外口径（SQLite 与真 MySQL 不同源）');
process.exit(0);
