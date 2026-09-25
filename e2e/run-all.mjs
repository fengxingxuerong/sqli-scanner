// ============================================================================
// e2e/run-all.mjs —— e2e 靶场统一入口
//
// 背景：e2e/ 下有 15+ 个靶场目录，各自有入口脚本、端口与外部依赖（MySQL/PG/MariaDB/Java），
// 想跑一轮回归得逐个记命令、逐个判断环境是否满足。本入口做两件事：
//   ① `--list`：列出全部靶场 + 依赖 + **当前环境是否满足**（端口探测）
//   ② 默认只跑「依赖满足」的靶场，避免"跑一半全挂在缺环境上"的噪音；
//      `--only a,b` 显式指定，`--all` 强制全跑（缺依赖的会失败，但会如实汇总）
//
// 用法：
//   node e2e/run-all.mjs --list
//   node e2e/run-all.mjs                      # 跑依赖满足的全部
//   node e2e/run-all.mjs --only multi-engine-lab,redteam-lab
//   node e2e/run-all.mjs --all
// ============================================================================
import { spawn } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');

// 靶场清单。deps 里的键对应 probe 表；env 为该靶场专有环境变量。
//
// deps 语义（2026-09-18 修订）：
//   'mysql'    —— 需要**宿主** 127.0.0.1:3306 的 MySQL
//   'sandbox'  —— 需要真 MySQL，但**可由隔离沙箱提供**（e2e/udf-lab/mysql_sandbox.py
//                 起在 3308）。宿主 3306 不通时自动改走 e2e/run-with-sandbox.py，
//                 不再标记为「缺依赖」而跳过。
//   其余（mssql/oracle/pg/java）语义不变。
//
// 依赖误标的修正记录（2026-09-18 实测）：
//   · waf-real：原标 deps:['mysql']，但其入口 selftest.mjs 只解析 CRS 规则做纯内存
//     evaluate，**完全不需要 MySQL**（无 MySQL 下实测 exit 0）。目录里 diag-*.mjs
//     确实用 MySQL，但不属入口链路。故改 deps:[]。
//   · redteam-lab：原标 deps:['mysql']，但其入口 run-with-env.mjs 会**自行拉起**
//     env.mjs（含 MySQL+PG+靶场）。实测宿主无 3306 时仍跑出 19/19 hit、0 误报。
//     故改 deps:[]（自起环境），不再因宿主无 3306 被跳过。
// ENGINE_JARS 的解析顺序：**调用方显式给的 > 本机默认路径（且必须真实存在）**。
// 原来这里无条件注入一串 Windows 绝对路径，两个后果（2026-09-25 CI 实测）：
//   ① 它 `...lab.env` 排在 `...process.env` 之后 ⇒ **覆盖** job 侧设好的 ENGINE_JARS，
//      就算 CI 备好了 jar 也会被这串 Windows 路径顶掉；
//   ② Linux 上这串必然不存在 ⇒ 要么 JVM 起不来，要么整个靶场永远只能 SKIP。
// 现在：已继承就不动；默认路径不全就**不注入** —— 让 verify.mjs 的 preflight 明确报
// "未设置 ENGINE_JARS"，而不是拿假路径去试一次再崩。
function multiEngineJarEnv() {
  if (process.env.ENGINE_JARS) return {};
  const def = ['h2', 'hsqldb', 'derby', 'derbyshared'].map((n) => path.join('D:', 'engines', 'jars', n + '.jar'));
  return def.every((q) => fs.existsSync(q)) ? { ENGINE_JARS: def.join(path.delimiter) } : {};
}

const LABS = [
  { name: 'redteam-lab', desc: '红队评测：24 靶点（17 注入 + 7 安全对照，自起环境）', entry: 'e2e/redteam-lab/run-with-env.mjs', args: ['r2'], deps: [] },
  { name: 'retest-lab', desc: '单点重测接口端到端（自起靶场）', entry: 'e2e/retest-lab/verify.mjs', deps: [] },
  { name: 'multi-engine-lab', desc: '多引擎 tamper A/B（真 JDBC：H2/HSQLDB/Derby，挂 CRS）', entry: 'e2e/multi-engine-lab/verify.mjs', deps: ['java'], env: multiEngineJarEnv },
  // [CI-FIX 2026-09-25] 同一份 verify 的 NO_WAF 档必须也注册。为什么两条不能合成一条：
  //   CRS-on 档实测 36 格全空（≈PL3 把探针整档 403，MySQL 上也是这个形状），
  //   所以 CI 上一轮虽然真的下载并校验了 4 个引擎 jar，跑的却是**唯一证不出任何事的那一档** ——
  //   判定行印成 `tamper 收益 on(0) ≥ off(0)=✅`，0≥0 空转。检测/定库类断言只在无 WAF 档成立，
  //   而那档此前只有我手动跑过、产物入库、门禁里没有它。产物文件名按档分开（.no-waf 后缀），不互相覆盖。
  { name: 'multi-engine-lab-no-waf', desc: '多引擎覆盖面（同靶场去掉 CRS：布尔/UNION/回显定库，检测类断言挂这档）', entry: 'e2e/multi-engine-lab/verify.mjs', deps: ['java'], env: () => ({ ...multiEngineJarEnv(), NO_WAF: '1' }) },
  // [CI-FIX 2026-09-25] 第三档：CRS **官方默认部署档 PL1**。这档才是 README 里
  //   "这三库在 CRS 下可被检出"那句的唯一合法来源 —— 本机逐档量过：
  //   PL1 = 三引擎 × 三场景 9/9 检出（布尔通道，h2/derby 另有 error）；PL2/PL3/PL4 = 0/9。
  //   也就是说 PL1→PL2 之间是**断崖**，把 PL3 的 0/9 当成"这三库过不了 WAF"是读错了档。
  //   产物写独立文件名（.pl1），不覆盖 ≈PL3 那份默认基线。
  { name: 'multi-engine-lab-crs-pl1', desc: '多引擎 × CRS 默认部署档 PL1（实测 9/9 检出；"CRS 下可检出"只在这档成立）', entry: 'e2e/multi-engine-lab/verify.mjs', deps: ['java'], env: () => ({ ...multiEngineJarEnv(), CRS_PL: '1' }) },
  // [CI-FIX 2026-09-25] 这个脚本 2026-09-22 起就在文档里写着"退出码 0 = 全通过 / 期望 PASS 16"，
  //   但从来没进过 run-all，也没进过 CI —— 于是"H2/HSQLDB/Derby/MonetDB 的方言模板真机能跑"
  //   这几句结论自那天起没有再被执行过一次。本机实测 1.6s、16 条全绿 ⇒ 挂进去的代价接近零。
  //   它跑的是模板 SQL 在真引擎上的**可执行性 + 反证**（Derby 拒 GROUP_CONCAT、HSQLDB 拒 SEPARATOR CHAR），
  //   与 multi-engine-lab 的检测通道覆盖不重叠。
  { name: 'dialect-templates', desc: '方言模板真机可执行性 + 反证（H2/HSQLDB/Derby/MonetDB，真 JDBC）', entry: 'e2e/multi-engine-lab/verify-dialect-templates.mjs', deps: ['java'], env: multiEngineJarEnv },
  { name: 'tamper-matrix', desc: 'tamper × WAF 规则绕过矩阵', entry: 'e2e/tamper-matrix/tamper-test.mjs', deps: [] },
  { name: 'real-world-lab', desc: '拟真靶场（登录/搜索/上传，PGlite 内置）', entry: 'e2e/real-world-lab/verify.mjs', deps: [] },
  { name: 'real-mysql-lab', desc: '真实 MySQL 驱动靶场验证', entry: 'e2e/real-mysql-lab/verify.mjs', deps: ['sandbox'] },
  { name: 'pentest-lab', desc: '渗透视角刁钻场景实测', entry: 'e2e/pentest-lab/verify.mjs', deps: ['sandbox'] },
  { name: 'waf-real', desc: '真实 CRS v4.1.0 规则验证（纯内存规则引擎，无需 DB）', entry: 'e2e/waf-real/selftest.mjs', deps: [] },
  { name: 'oob-real-lab', desc: 'OOB 带外全链路（PG COPY TO PROGRAM / MySQL UNC）', entry: 'e2e/oob-real-lab/verify.mjs', deps: ['pg', 'sandbox'] },
  { name: 'pg-osshell', desc: 'PG os-shell 真机闭环（COPY FROM PROGRAM 落表 → 回显）', entry: 'e2e/oob-real-lab/pg-osshell.e2e.mjs', deps: ['pg'] },
  { name: 'concurrent-isolation', desc: '并发多扫描隔离性（PG+MySQL 混扫不串扰）', entry: 'e2e/concurrent-isolation/e2e.mjs', deps: ['pg', 'sandbox'] },
  { name: 'csrf-lab', desc: 'CSRF 防护目标闭环（取页 token → 携带 → 检出）', entry: 'e2e/csrf-lab/e2e.mjs', deps: ['sandbox'] },
  { name: 'crawl-lab', desc: '--crawl/--forms 攻击面发现真机闭环（scope 纪律）', entry: 'e2e/crawl-lab/e2e.mjs', deps: ['sandbox'] },
  // 文件读写闭环：宿主 mysqld 默认 secure_file_priv=NULL → 直跑只能 SKIP。
  // 走沙箱就有救：沙箱把 secure_file_priv 指到自己的 plugin 目录，套件把标记文件放进去
  // （MYSQL_SECURE_FILE_DIR 由 run-with-sandbox.py 注入）→ 2026-09-19 实测两套件均真跑 PASS。
  // 「限定一个目录」也正是现实里 DBA 唯一会批准的放行形态，比全局放行更贴近真实。
  { name: 'file-read', desc: 'fileRead 真闭环（UNION → LOAD_FILE → 逐字节回读）', entry: 'e2e/fileops/exploit-file-read.e2e.mjs', deps: ['sandbox'] },
  { name: 'file-write', desc: 'fileWrite 真闭环（INTO OUTFILE → 文件系统侧确认）', entry: 'e2e/fileops/exploit-file-write.e2e.mjs', deps: ['sandbox'] },
  // 随机化真值电池：案例由种子生成（一半注入一半良性），报召回的 **Wilson 95%CI 下界**而不是
  // 一个分数。存在的意义就是提醒"13/13"那种小样本口径撑不起"检出率 100%"这句话。
  { name: 'random-battery', desc: '随机化真值电池（召回 CI 下界 + 良性零误报）', entry: 'e2e/random-lab/battery.mjs', deps: ['sandbox'] },
  { name: 'mssql-lab', desc: 'SQL Server 真机全链路（num/str 双上下文三通道）', entry: 'e2e/mssql-lab/e2e.mjs', deps: ['mssql'] },
  { name: 'mssql-oshell', desc: 'MSSQL xp_cmdshell os-shell 真机闭环（含 auto-enable）', entry: 'e2e/mssql-lab/osshell.e2e.mjs', deps: ['mssql'] },
  { name: 'mssql-dump', desc: 'MSSQL 拖库正确性（string_agg/OFFSET-FETCH 方言真机）', entry: 'e2e/mssql-lab/dump.e2e.mjs', deps: ['mssql'] },
  { name: 'oracle-lab', desc: 'Oracle 26ai Free 真机全链路（检测+拖库）', entry: 'e2e/oracle-lab/e2e.mjs', deps: ['oracle'] },
  { name: 'recall-lab', desc: '假阳性验证（安全靶场零误报）', entry: 'e2e/recall-lab/false-positive.e2e.js', deps: [] },
  { name: 'detection-runner', desc: '数据驱动检测测试', entry: 'e2e/detection-runner/run.js', deps: [] },
  { name: 'udf-lab', desc: 'UDF 接管真实验证（真 DLL，自起隔离沙箱）', entry: 'e2e/udf-lab/udf-takeover.e2e.mjs', deps: ['sandbox'] },
  { name: 'waf-lab', desc: 'WAF 绕过 A/B（真 MySQL 靶场，自起隔离沙箱）', entry: 'e2e/waf-lab/compare-real.e2e.mjs', deps: ['sandbox'] },
];

const PROBES = {
  mysql: { port: 3306, label: 'MySQL:3306' },
  mssql: { port: Number(process.env.MSSQL_TCP_PORT) || 65039, label: 'MSSQL:65039' },
  oracle: { port: 1521, label: 'Oracle:1521' },
  mariadb: { port: 3308, label: 'MariaDB:3308' },
  pg: { port: 5432, label: 'PostgreSQL:5432' },
  java: { label: 'Java' },
};

// 隔离 MySQL 沙箱（e2e/udf-lab/mysql_sandbox.py）：
//   · 沙箱 datadir 在 e2e/udf-lab/.mysql-sandbox/，与宿主 127.0.0.1:3306 完全隔离；
//   · 由 e2e/run-with-sandbox.py 在同一进程内「起 → 用 → 停」（宿主会回收后台进程，
//     不能先起后用）。
// 判定「沙箱可用」= datadir 已初始化（不全则需先 --init，此处报缺依赖并给出提示）。
const SANDBOX_DIR = path.join(ROOT, 'e2e', 'udf-lab', '.mysql-sandbox');
const sandboxAvailable = () => fs.existsSync(path.join(SANDBOX_DIR, 'data'));

const probePort = (port, timeout = 800) =>
  new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1');
    const done = (v) => { try { s.destroy(); } catch { /* noop */ } resolve(v); };
    s.on('connect', () => done(true));
    s.on('error', () => done(false));
    setTimeout(() => done(false), timeout);
  });

const hasJava = () =>
  new Promise((resolve) => {
    const p = spawn('java', ['-version'], { stdio: 'ignore' });
    p.on('error', () => resolve(false));
    p.on('exit', (c) => resolve(c === 0));
    setTimeout(() => { try { p.kill(); } catch { /* noop */ } resolve(false); }, 3000);
  });

async function depStatus(lab) {
  const missing = [];
  for (const d of lab.deps) {
    if (d === 'java') {
      if (!(await hasJava())) missing.push(PROBES.java.label);
    } else if (d === 'sandbox') {
      // 沙箱依赖：只看隔离沙箱 datadir 是否就绪。
      // 【不要】再探测宿主 3306 决定走向 —— 实测踩坑（2026-09-18）：
      //   redteam-lab 会自起宿主 mysqld(3306)，跑完后它可能仍短暂在听；此时若
      //   probePort(3306) 命中就会把 sandbox 类靶场误判为「可直连」，跳过沙箱 →
      //   靶场连 3308 得 ECONNREFUSED、0.4s 就失败。行为必须确定：sandbox 一律走沙箱。
      if (!sandboxAvailable()) {
        missing.push('隔离MySQL沙箱（先跑 python e2e/udf-lab/mysql_sandbox.py --init）');
      }
    } else {
      const pr = PROBES[d];
      if (!(await probePort(pr.port))) missing.push(pr.label);
    }
  }
  return missing;
}

// 判定该靶场是否改由隔离沙箱驱动：凡声明 sandbox 依赖者**一律**走沙箱，不看宿主 3306。
// 理由见 depStatus 内注释（宿主 3306 的短暂可达会造成行为不确定，实测已踩）。
const needsSandbox = (lab) => lab.deps.includes('sandbox');

// 单个靶场的墙钟上界。取值来自实测分布：本清单里最慢的是 redteam-lab ~91s，其余在秒级到
// 几十秒 —— 5 分钟对"真在干活"的套件有 3 倍余量，对**挂死**则能在 CI 的 8 分钟步长内
// 报出"卡在哪个靶场"。此前 runOne **完全没有超时**：任何一套挂死，run-all 就原地等，
// CI 只能看到 job 被整体掐掉、连现场都没有（2026-09-25 A3 端到端挂死实测到这条）。
// 超时按**失败**结算，不当"按设计跳过"——挂死不是跳过。
const LAB_TIMEOUT_MS = Number(process.env.RUN_ALL_LAB_TIMEOUT_MS) || 300000;

const runOne = (lab, useSandbox = false) =>
  new Promise((resolve) => {
    const t0 = Date.now();
    // useSandbox：经 e2e/run-with-sandbox.py 包一层，由它在**同一进程**内
    // 起隔离 MySQL 沙箱 → 跑靶场 → 停沙箱（宿主会回收后台进程，故不能先起后用）。
    const py = process.env.PYTHON || 'C:\\Users\\Admin（无密码）\\.workbuddy\\binaries\\python\\versions\\3.13.12\\python.exe';
    const cmd = useSandbox ? py : 'node';
    const cmdArgs = useSandbox
      ? [path.join(ROOT, 'e2e', 'run-with-sandbox.py'), lab.entry, ...(lab.args || [])]
      : [lab.entry, ...(lab.args || [])];
    const p = spawn(cmd, cmdArgs, {
      cwd: ROOT,
      // lab.env 允许是对象，也允许是函数（multiEngineJarEnv 要看进程环境里有没有 ENGINE_JARS，
      // 有就必须让位 —— 否则无条件注入会把 CI 侧准备好的路径覆盖掉）。
      env: {
        ...process.env,
        NO_PROXY: '127.0.0.1,localhost',
        ...(typeof lab.env === 'function' ? lab.env() : lab.env || {}),
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let timeoutNote = '';
    let settled = false;
    const finish = (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(hardTimer);
      if (timeoutNote) out += timeoutNote;
      // 从输出里抓一眼关键字（各靶场格式不一，仅作提示，不作判定）
      const hint = out.split('\n').filter((l) => /done:|结论|误报|✅|❌|FAIL|PASS/i.test(l)).slice(-2).join(' | ').slice(0, 160);
      // [P1-FIX 2026-09-14] 区分「通过」与「按设计跳过」：
      // 部分套件（如 udf-lab 因 secure_file_priv=NULL）退出码为 0，输出里一行 [SKIP] 就结束了。
      // 旧汇总把它算进「全部通过」—— 15/15 里其实只有 14 个真跑。数字比没有更误导。
      const skipped = code === 0 && /\bSKIP\b/i.test(out);
      // [DIAG-FIX 2026-09-21] 保留**完整输出**（原先只留 3 行 tail 且没人打印，见下方失败分支）
      resolve({ code, skipped, ms: Date.now() - t0, hint, sandbox: useSandbox, tail: out.split('\n').filter(Boolean).slice(-3).join('\n'), full: out });
    };
    const hardTimer = setTimeout(() => {
      timeoutNote = `\n[TIMEOUT] ${lab.name} 超过 ${LAB_TIMEOUT_MS}ms 未完成，已由 run-all 强杀（下面是它截止时被收到的全部输出）\n`;
      try {
        // win32 上 spawn 走 shell 时 kill 只打死外壳、孙进程仍持有管道；这里 stdio 是 pipe 且
        // 不用 shell，但 python 包装层会再起 mysqld/node —— 连树杀才真能放掉端口。
        if (process.platform === 'win32' && p.pid) {
          spawn('taskkill', ['/pid', String(p.pid), '/T', '/F'], { stdio: 'ignore' });
        } else {
          p.kill('SIGKILL');
        }
      } catch { /* 杀不掉也要结算，见下面的兜底 */ }
      setTimeout(() => finish(-2), 5000).unref();
    }, LAB_TIMEOUT_MS);
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { out += d; });
    p.on('exit', (code) => finish(code === null ? -3 : code));
    // spawn 失败（ENOENT，如 pin 死的 python 路径不在这台机器上）走的是 'error' 而不是 'exit'：
    // 没有监听器时它会抛未捕获异常、把整个 run-all 带走（上面的 hasJava 同理由才加了 error 分支）。
    p.on('error', (e) => {
      timeoutNote = `[spawn error] ${cmd}：${e.message}\n`;
      finish(-1);
    });
  });

const argv = process.argv.slice(2);
const listMode = argv.includes('--list');
const allMode = argv.includes('--all');
// [ONLY-FIX 2026-09-20] 原来只认 `--only 名字`（空格形式）。写成 `--only=名字` 时
// `indexOf('--only')` 返回 -1 → only 为 null → **静默退化成"跑全部依赖齐全的靶场"**。
// 实测：本想只跑 1 个 0.5s 的套件，结果跑了 21 个（含 77s 的红队），耗时从 1s 变 10 分钟。
// 更糟的是它不说自己忽略了参数 —— 定向复测的结论会被全量结果污染。
const onlyIdx = argv.findIndex((a) => a === '--only' || a.startsWith('--only='));
const only = onlyIdx >= 0
  ? (argv[onlyIdx] === '--only' ? (argv[onlyIdx + 1] || '') : argv[onlyIdx].slice('--only='.length))
    .split(',').map((s) => s.trim()).filter(Boolean)
  : null;
if (only) console.log(`[run-all] 定向模式：只跑 ${only.join(', ')}`);

console.log('=== e2e 靶场清单（依赖探测）===');
const status = [];
for (const lab of LABS) {
  const missing = await depStatus(lab);
  status.push({ lab, missing, ok: missing.length === 0 });
  const mark = missing.length ? '⛔' : '✅';
  console.log(`${mark} ${lab.name.padEnd(20)} ${lab.desc}`);
  if (missing.length) console.log(`   └ 缺依赖: ${missing.join(', ')}`);
}
console.log('');

if (listMode) process.exit(0);

let targets = status;
if (only) targets = status.filter((s) => only.includes(s.lab.name));
else if (!allMode) targets = status.filter((s) => s.ok);

if (!targets.length) {
  console.log('没有可跑的靶场：指定 --only 或 --all（注意缺依赖的会失败）');
  process.exit(0);
}

console.log(`=== 开始运行 ${targets.length} 个靶场 ===`);
const results = [];
for (const t of targets) {
  const useSandbox = needsSandbox(t.lab);
  process.stdout.write(`▶ ${t.lab.name}${useSandbox ? '（隔离沙箱）' : ''} ... `);
  if (!t.ok) console.log(`(缺依赖: ${t.missing.join(', ')})`);
  const r = await runOne(t.lab, useSandbox);
  results.push({ name: t.lab.name, ...r });
  const verdict = r.code !== 0 ? `❌ 失败(code=${r.code})` : r.skipped ? '⏭ 跳过（按设计）' : '✅ 通过';
  console.log(`${verdict}  ${(r.ms / 1000).toFixed(1)}s  ${r.hint}`);
  // [DIAG-FIX 2026-09-21] 失败必须留下现场。
  // 触发实况：CI 的 e2e-self-contained 里 redteam-lab 报 `❌ 失败(code=1)  90.6s  `（hint 为空），
  // 子进程输出被整个丢弃 —— 只看到「红了」，看不到「为什么红」，排障等于重新猜。
  // 与 acceptance.mjs 的 [DIAG-FIX] 同一条纪律：**门禁留不下现场，就等于把缺陷变成不可查**。
  // hint 只按 /done:|结论|误报|✅|❌|FAIL|PASS/ 抓关键字（各靶场格式不一），
  // 而「[env] 启动 MySQL：D:/mysql/bin/mysqld.exe」这类**关键线索恰好不匹配**任何关键词。
  if (r.code !== 0) {
    const lines = String(r.full || '').split('\n').filter(Boolean);
    console.log(`   ── ${t.lab.name} 输出末 ${Math.min(lines.length, 40)} 行（共 ${lines.length} 行）──`);
    for (const l of lines.slice(-40)) console.log(`   │ ${l}`);
    try {
      fs.mkdirSync(path.join(ROOT, 'e2e', 'results'), { recursive: true });
      fs.writeFileSync(
        path.join(ROOT, 'e2e', 'results', `last-failure-${t.lab.name}.log`),
        `$ ${t.lab.name}\n退出码：${r.code}\n耗时：${(r.ms / 1000).toFixed(1)}s\n\n${r.full}`
      );
      console.log(`   ── 完整现场已落盘：e2e/results/last-failure-${t.lab.name}.log ──`);
    } catch { /* 现场落盘失败不应改变判定 */ }
  } else if (r.skipped) {
    // [DIAG-FIX 2026-09-21] 跳过也必须**说出理由**。
    // 实测：redteam-lab 因缺 mysqld 二进制跳过时，日志只剩一行 `⏭ 跳过（按设计）`，
    // 子进程打的 `[SKIP] 未找到 mysqld 二进制：…` 被 hint 的关键字过滤掉了
    // （hint 只认 /done:|结论|误报|✅|❌|FAIL|PASS/）—— 于是「跳过」等于没说是缺什么。
    const why = String(r.full || '').split('\n').filter((l) => /\[SKIP\]|skip/i.test(l)).slice(0, 5);
    for (const l of why) console.log(`   │ ${l.trim()}`);
  }
}

console.log('');
console.log('=== 汇总 ===');
for (const r of results) {
  const mark = r.code !== 0 ? '❌' : r.skipped ? '⏭' : '✅';
  const tag = r.sandbox ? '  [隔离沙箱]' : '';
  console.log(`${mark} ${r.name.padEnd(20)} ${(r.ms / 1000).toFixed(1)}s${r.skipped ? '  (跳过)' : ''}${tag}`);
}
const failed = results.filter((r) => r.code !== 0);
const skipped = results.filter((r) => r.skipped);
const passed = results.length - failed.length - skipped.length;
// [G2-FIX 2026-09-20] 「缺依赖 → 默认模式直接过滤掉」的靶场在此前**完全不出现在汇总里**：
// 顶部清单打了 ⛔，但汇总只按 results 统计，于是 `通过 6 / 跳过 0 / 失败 0` 看起来是全绿，
// 而 concurrent-isolation 这类（deps 含 pg，CI 无 PostgreSQL）压根没跑、也没人看见。
// 未跑 ≠ 通过 ≠ 跳过 —— 必须单独列出来，否则「CI 全绿」是假绿。
const notRun = only ? [] : status.filter((s) => !s.ok && !targets.includes(s));
if (notRun.length) {
  console.log('');
  console.log('=== 未跑（缺依赖，本轮零断言）===');
  for (const s of notRun) console.log(`⛔ ${s.lab.name.padEnd(20)} 缺: ${s.missing.join(', ')}`);
}
console.log('');
console.log(`通过 ${passed} / 跳过 ${skipped.length} / 失败 ${failed.length}`
  + `${notRun.length ? ` / 未跑 ${notRun.length}` : ''}  （共 ${results.length} 个靶场`
  + `${notRun.length ? `，清单共 ${status.length} 个）` : '）'}`);
if (skipped.length) {
  // 原先这里举的例子是「secure_file_priv 未放行时文件读写类套件无法真跑」——
  // 但本套件里**根本没有** fileRead/fileWrite（它们归 acceptance 管），照抄 acceptance
  // 的总结会让人去找一个不存在的套件。改成只讲本套件真实存在的跳过原因。
  console.log('跳过的不算通过 —— 本套件未执行任何断言。缺失依赖已在每个靶场上方逐条打印，补齐后重跑。');
  console.log('注意：fileRead / fileWrite 不在本套件内（它们需要 secure_file_priv 放行），由 `npm run acceptance` 覆盖。');
}
process.exit(failed.length ? 1 : 0);
