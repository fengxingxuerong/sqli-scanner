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
const LABS = [
  { name: 'redteam-lab', desc: '红队评测：24 靶点（17 注入 + 7 安全对照，自起环境）', entry: 'e2e/redteam-lab/run-with-env.mjs', args: ['r2'], deps: [] },
  { name: 'retest-lab', desc: '单点重测接口端到端（自起靶场）', entry: 'e2e/retest-lab/verify.mjs', deps: [] },
  { name: 'multi-engine-lab', desc: '多引擎 tamper A/B（真 JDBC：H2/HSQLDB/Derby）', entry: 'e2e/multi-engine-lab/verify.mjs', deps: ['java'], env: { ENGINE_JARS: 'D:\\engines\\jars\\h2.jar;D:\\engines\\jars\\hsqldb.jar;D:\\engines\\jars\\derby.jar;D:\\engines\\jars\\derbyshared.jar' } },
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
      env: { ...process.env, NO_PROXY: '127.0.0.1,localhost', ...(lab.env || {}) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { out += d; });
    p.on('exit', (code) => {
      // 从输出里抓一眼关键字（各靶场格式不一，仅作提示，不作判定）
      const hint = out.split('\n').filter((l) => /done:|结论|误报|✅|❌|FAIL|PASS/i.test(l)).slice(-2).join(' | ').slice(0, 160);
      // [P1-FIX 2026-09-14] 区分「通过」与「按设计跳过」：
      // 部分套件（如 udf-lab 因 secure_file_priv=NULL）退出码为 0，输出里一行 [SKIP] 就结束了。
      // 旧汇总把它算进「全部通过」—— 15/15 里其实只有 14 个真跑。数字比没有更误导。
      const skipped = code === 0 && /\bSKIP\b/i.test(out);
      resolve({ code, skipped, ms: Date.now() - t0, hint, sandbox: useSandbox, tail: out.split('\n').filter(Boolean).slice(-3).join('\n') });
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
