// ============================================================================
// scripts/lib/labs.mjs —— [D144 2026-10-23] 本机靶场「体检 / 拉起」的判据与配方
//
// 为什么需要它：25 套件全绿依赖 6 个外部服务（MariaDB / DVWA / VAmPI×2 / Juice / Benchmark×2 / PG），
// 而它们的起法此前只活在 TODO 的散文配方里、路径还是本机硬编码 —— 换一次机器就得靠人肉复读，
// 而**没起来的靶场在验收里只会表现为 SKIP/BLOCKED**（假绿温床：SKIP 不计通过，但很容易被读成「没问题」）。
//
// 口径（与仓库其它门禁一致）：
//   · 纯函数部分（labSpecs / planLab / planAll / renderRows / selectToStart）在这里，可 selftest；
//   · 起停等副作用在 scripts/labs.mjs（CLI）里，进程 pid 记到状态文件，`--stop` 只杀自己起的；
//   · 缺前置（可执行文件/目录不存在）一律**显式 skip + 给出要设哪个环境变量**，绝不静默继续。
//
// 每个靶场的配方各自一个小函数（labSpecs 只负责拼装）：复杂度门禁对「新代码超 100 行的函数」
// 是硬拦 —— 一坨 120 行的清单函数过不了，拆开也更便于单看某一家靶场的起法。
// ============================================================================
import path from 'node:path';

/** 前置项（文件或目录）——`hint` 是「缺了要设哪个环境变量」的提示 */
const need = (kind, filePath, hint) => ({ kind, path: filePath, ...(hint ? { hint } : {}) });

/** 宿主 MariaDB：验收的 MySQL 依赖（本机 datadir 里已有 dvwa/sqli_lab/redteam_lab/param*-lab 等库） */
function mariadbSpec(p, repoRoot) {
  const home = p('MARIADB_HOME', 'D:/tools/mariadb/mariadb-10.11.19-winx64');
  const data = p('MARIADB_DATADIR', 'D:/tools/mariadb/data');
  return {
    id: 'mariadb',
    title: '宿主 MariaDB（验收的 MySQL 依赖，含 dvwa/sqli_lab/redteam_lab 等库）',
    port: 3306,
    requires: [need('file', `${home}/bin/mariadbd.exe`, 'MARIADB_HOME'), need('file', `${data}/my.ini`, 'MARIADB_DATADIR')],
    cmd: `${home}/bin/mariadbd.exe`,
    args: [
      `--defaults-file=${data}/my.ini`,
      '--port=3306',
      `--secure-file-priv=${p('MARIADB_SECURE_DIR', 'D:/tools/mariadb/files')}`,
      '--console',
    ],
    cwd: repoRoot,
  };
}

/** DVWA：外部裁判 3 号 + 数据泄露实证（PHP built-in server，关鉴权、默认 low 档） */
function dvwaSpec(p, verifyLabs) {
  const dir = p('DVWA_DIR', path.join(verifyLabs, 'DVWA-master'));
  return {
    id: 'dvwa',
    title: 'DVWA（外部裁判 3 号 + 数据泄露实证）',
    port: 8099,
    requires: [
      need('file', p('PHP_EXE', 'D:/tools/php83/php.exe'), 'PHP_EXE'),
      need('file', path.join(dir, 'config', 'config.inc.php'), 'DVWA_DIR'),
      // [D188] 可服务性标记：根 index.php/login.php 缺失 = 供应物被清（TEMP 清理/AV），
      // 服务器起得来也只会全 404 —— labs 体检必须当场红，不能等到套件 SKIP
      need('file', path.join(dir, 'index.php'), 'DVWA_DIR(index.php)'),
      need('file', path.join(dir, 'login.php'), 'DVWA_DIR(login.php)'),
    ],
    cmd: p('PHP_EXE', 'D:/tools/php83/php.exe'),
    args: ['-S', '127.0.0.1:8099', '-t', dir],
    cwd: dir,
    env: {
      DISABLE_AUTHENTICATION: 'true',
      DEFAULT_SECURITY_LEVEL: 'low',
      DB_SERVER: '127.0.0.1',
      DB_PORT: '3306',
      DB_DATABASE: 'dvwa',
      DB_USER: 'root',
      DB_PASSWORD: 'root',
    },
  };
}

/** VAmPI 两个实例（5000 漏洞 / 5001 参数化对照）：同一份源码，入口与开关不同 */
function vampiSpec(p, verifyLabs, repoRoot, mode) {
  const venv = p('VAMPI_VENV', path.join(verifyLabs, 'vampi-venv'));
  const src = p('VAMPI_SRC', path.join(verifyLabs, 'VAmPI-master'));
  const vuln = mode === 'vuln';
  const port = vuln ? 5000 : 5001;
  const entry = vuln ? 'app.py' : path.join(repoRoot, 'e2e', 'vampi-lab', 'run_port.py');
  return {
    id: vuln ? 'vampi-vuln' : 'vampi-safe',
    title: vuln ? 'VAmPI 漏洞实例（外部裁判 2 号 / 5000）' : 'VAmPI 参数化对照实例（同源 A/B / 5001）',
    port,
    requires: [need('file', `${venv}/Scripts/python.exe`, 'VAMPI_VENV'), need('file', vuln ? path.join(src, 'app.py') : path.join(repoRoot, 'e2e', 'vampi-lab', 'run_port.py'))],
    cmd: `${venv}/Scripts/python.exe`,
    args: [entry],
    cwd: src,
    // [D188] 官方 `app.py` 只建空 SQLite，不调 /createdb 就没有 users 表 ——
    // 外部裁判 2 号会在「靶场不可达」与「500 空表」之间表现成 FAIL/静默 SKIP（2026-10-28 实测）。
    // seedPath 由 labs.mjs 在端口就绪后调用；两个实例共用同一份 DB，重复调用是幂等的。
    seedPath: '/createdb',
    // tokentimetolive 必须显式设大：官方默认 60s 会让一轮扫描中途全 401 ⇒ 真假恒等（假阴性）
    // 对照实例另需 PYTHONPATH=源码目录（否则 run_port.py 里 `from config import vuln_app` ImportError）
    env: vuln
      ? { tokentimetolive: '7200' }
      : { PYTHONPATH: src, PORT: String(port), vulnerable: '0', tokentimetolive: '7200' },
  };
}

/** Juice Shop：外部裁判 1 号（**必须 Node 22**：Node 24 扫搜索路由会触发 libuv 断言崩进程） */
function juiceSpec(p, home, verifyLabs) {
  const dir = p('JUICE_DIR', path.join(verifyLabs, 'juice-shop-20.3.0'));
  const node22 = p('NODE22_EXE', path.join(home, '.workbuddy', 'binaries', 'node', 'versions', '22.22.2-6', 'node.exe'));
  return {
    id: 'juice',
    title: 'Juice Shop（外部裁判 1 号；**必须 Node 22**，Node 24 会触发 libuv 断言崩进程）',
    port: 3199,
    requires: [need('file', node22, 'NODE22_EXE'), need('file', path.join(dir, 'build', 'app.js'), 'JUICE_DIR')],
    cmd: node22,
    args: ['build/app'],
    cwd: dir,
    env: { PORT: '3199', NODE_ENV: 'production' },
  };
}

/** Benchmark 数据源：HSQLDB 必须常驻（官方 antrun 的 fork 子进程会随 mvn 退出被回收） */
function benchmarkDbSpec(p, home, repoRoot) {
  const dir = p('BENCHMARK_DIR', path.join(repoRoot, '.box-agent-scratch', 'BenchmarkJava-master'));
  const jar = p('HSQL_JAR', path.join(home, '.m2', 'repository', 'org', 'hsqldb', 'hsqldb', '2.7.4', 'hsqldb-2.7.4.jar'));
  const dbFile = path.join(dir, 'target', 'db', 'benchmark.db').replace(/\\/g, '/');
  return {
    id: 'benchmark-db',
    title: 'Benchmark HSQLDB（外部裁判 4 号数据源 / 9001；必须常驻）',
    port: 9001,
    requires: [
      need('file', p('JAVA_EXE', 'D:/tools/jdk/jdk-17.0.2/bin/java.exe'), 'JAVA_EXE'),
      need('file', jar, 'HSQL_JAR'),
    ],
    cmd: p('JAVA_EXE', 'D:/tools/jdk/jdk-17.0.2/bin/java.exe'),
    args: ['-cp', jar, 'org.hsqldb.Server', '--database.0', `file:${dbFile}`, '--dbname.0', 'benchmarkDataBase', '--port', '9001'],
    cwd: dir,
  };
}

/** Benchmark 应用：cargo:run 起 Tomcat（https/8443 自签；别与 clean 连跑，库文件锁会撞） */
function benchmarkAppSpec(p, repoRoot) {
  const dir = p('BENCHMARK_DIR', path.join(repoRoot, '.box-agent-scratch', 'BenchmarkJava-master'));
  return {
    id: 'benchmark-app',
    title: 'Benchmark Tomcat（https/8443 自签；**别与 clean 连跑**，库文件锁会撞）',
    port: 8443,
    requires: [
      need('file', p('MAVEN_CMD', 'D:/tools/maven/apache-maven-3.9.11/bin/mvn.cmd'), 'MAVEN_CMD'),
      need('dir', path.join(dir, 'target'), 'BENCHMARK_DIR'),
    ],
    cmd: p('MAVEN_CMD', 'D:/tools/maven/apache-maven-3.9.11/bin/mvn.cmd'),
    args: ['cargo:run', '-Pdeploy', '-Dspotless.apply.skip=true'],
    cwd: dir,
    env: { JAVA_HOME: p('JAVA_HOME', 'D:/tools/jdk/jdk-17.0.2') },
    // Maven/Tomcat 冷启动明显慢于其它靶场（本机实测 ~80s），45s 会把它判成失败。
    startTimeoutMs: 180000,
  };
}

/** PostgreSQL：本仓库不负责拉起（OOB 真机与红队靶场的外部依赖），只探测 */
function postgresSpec() {
  return {
    id: 'postgres',
    title: 'PostgreSQL 5432（OOB 真机 + 红队靶场用；本仓库不负责拉起，仅探测）',
    port: 5432,
    probeOnly: true,
    requires: [],
  };
}

/**
 * 本机靶场清单（每项 = 一个可探测的端口 + 一组前置 + 一条启动配方）。
 * 所有路径都可用环境变量覆盖；默认值是本机实测过的那套（D134–D138 的配方）。
 * @param {{ env?: Record<string, string|undefined>, repoRoot: string }} ctx 环境与仓库根
 * @returns {Array<any>} 靶场规格列表
 */
export function labSpecs({ env = {}, repoRoot }) {
  const p = (name, dflt) => env[name] ?? dflt;
  const home = env.USERPROFILE ?? env.HOME ?? '';
  // [D188] 靶场供应物默认落仓内 .verify-labs（耐久）：原默认 %TEMP%\verify-labs 会被
  // 临时目录清理/AV 清掉——2026-10-27 实测 DVWA 根 PHP 被选择性清空、套件静默 SKIP。
  // 已供应在旧位置的实例：迁移过去，或用 VERIFY_LABS 环境变量指回旧路径。
  const verifyLabs = p('VERIFY_LABS', path.join(repoRoot, '.verify-labs'));
  return [
    mariadbSpec(p, repoRoot),
    dvwaSpec(p, verifyLabs),
    vampiSpec(p, verifyLabs, repoRoot, 'vuln'),
    vampiSpec(p, verifyLabs, repoRoot, 'safe'),
    juiceSpec(p, home, verifyLabs),
    benchmarkDbSpec(p, home, repoRoot),
    benchmarkAppSpec(p, repoRoot),
    postgresSpec(),
  ];
}

/**
 * 单个靶场的体检结论（纯函数）。
 * @param {any} lab 靶场规格
 * @param {{ portOpen: (port: number) => boolean, pathExists: (p: string) => boolean }} probes 探针
 * @returns {{ id: string, title: string, port: number, status: 'up'|'start'|'skip'|'probe-only', reason: string|null, missingPath: string|null }} 结论
 */
function planLab(lab, probes) {
  const base = { id: lab.id, title: lab.title, port: lab.port, status: 'skip', reason: null, missingPath: null };
  if (lab.probeOnly) {
    const up = probes.portOpen(lab.port);
    return { ...base, status: up ? 'up' : 'probe-only', reason: '本仓库不负责拉起（外部依赖），仅探测' };
  }
  if (probes.portOpen(lab.port)) return { ...base, status: 'up', reason: '端口已在监听（复用，不重复拉起）' };
  const missing = (lab.requires ?? []).find((req) => !probes.pathExists(req.path));
  if (missing) {
    return {
      ...base,
      status: 'skip',
      reason: `缺前置：${missing.path}`,
      missingPath: missing.hint ? `设环境变量 ${missing.hint}=<路径>` : null,
    };
  }
  return { ...base, status: 'start', reason: '前置齐备，可拉起' };
}

/**
 * 全部靶场的体检结论。
 * @param {Array<any>} labs 靶场规格列表
 * @param {{ portOpen: (port: number) => boolean, pathExists: (p: string) => boolean }} probes 探针
 * @returns {Array<any>} 结论列表
 */
export function planAll(labs, probes) {
  return labs.map((lab) => planLab(lab, probes));
}

/**
 * 体检结果渲染成表（人能一眼看出「哪些没起、为什么没起、缺什么」）。
 * @param {Array<any>} rows planAll 的结果
 * @returns {string} 多行文本
 */
export function renderRows(rows) {
  const mark = { up: '✅', start: '⬜', skip: '⛔', 'probe-only': '➖' };
  return rows
    .map((r) => {
      const head = `${mark[r.status] ?? '?'} ${r.id.padEnd(14)} :${String(r.port).padEnd(5)} ${r.status}`;
      const extra = [r.reason, r.missingPath].filter(Boolean).join(' · ');
      return extra ? `${head} —— ${extra}` : head;
    })
    .join('\n');
}

/**
 * 按 id 取要拉起的靶场（`--up=mariadb,dvwa` 形式；缺省 = 全部非 probe-only 且 down 的）。
 * @param {Array<any>} labs 靶场规格列表
 * @param {Array<any>} rows planAll 的结果
 * @param {string|null} only 逗号分隔的 id 白名单
 * @returns {{ todo: Array<any>, unknown: string[] }} 待拉起项与不认识的 id
 */
export function selectToStart(labs, rows, only) {
  const wanted = only ? new Set(only.split(',').map((s) => s.trim()).filter(Boolean)) : null;
  const unknown = wanted ? [...wanted].filter((id) => !labs.some((l) => l.id === id)) : [];
  const todo = labs.filter((l, i) => (wanted ? wanted.has(l.id) : true) && rows[i].status === 'start');
  return { todo, unknown };
}

/**
 * [D148] 把「指定靶场是否在线」判成硬要求（供 acceptance 的 `--require-labs` 用）。
 * 为什么需要：没起的靶场在验收里只表现为 SKIP/BLOCKED，很容易被读成「没问题」；
 * 想让一轮验收真正覆盖外部裁判时，就得先声明「这些必须在」。口径与 `--require=` 一致：
 * 只认事实（端口），不认识/没起的 id 逐条点名，并给出 `--up` 处置命令。
 * @param {Array<any>} rows planAll 的结果
 * @param {string[]} required 必须在线（或至少可拉起）的靶场 id
 * @returns {{ ok: boolean, missing: string[], unknown: string[] }} 判定与逐条点名
 */
export function judgeLabs(rows, required) {
  const byId = new Map(rows.map((r) => [r.id, r]));
  const unknown = required.filter((id) => !byId.has(id));
  // 只认「正在监听」：`start`（前置齐备但没起）也算没达标 —— 调用方要的是「这轮真的能测」，
  // 不是「理论上能拉起」。处置命令由调用方打印（`--up=<ids>`）。
  const missing = required.filter((id) => {
    const row = byId.get(id);
    return row ? row.status !== 'up' : false;
  });
  return { ok: unknown.length === 0 && missing.length === 0, missing, unknown };
}