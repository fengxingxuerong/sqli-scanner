#!/usr/bin/env node
// ============================================================================
// scripts/ci-benchmark.mjs —— [D298 2026-11-15] CI 侧拉起 OWASP Benchmark（外部裁判 4 号）
//
// 背景：acceptance 的 `benchmark` 套件在 CI 长期 SKIP（ci.yml 原注释「Java 构建链仍未验证，
// 不盲猜」）。本机配方见 e2e/benchmark-lab/README.md §「环境准备」：JDK17 + Maven 3.9 +
// `-Pdeploy` 打包 + 手动常驻 HSQLDB @9001 + `mvn cargo:run` 起 https/8443 自签。
//
// 与 ci-dvwa.mjs / ci-vulnlab.mjs 同构：CI 硬起、起不来就显式红，绝不留「静默 SKIP」。
// `planLab` 只看端口是否监听（不看 requires 里的 Windows 默认路径），所以 9001/8443 起来后
// `--require-labs=benchmark-db,benchmark-app` 即生效，**不需要改 scripts/lib/labs.mjs**，
// 也不触碰 ciWindowsOnly.guard.test.js 的本机契约。
//
// ⚠ 本机约束：`up` 只允许在 Linux CI runner 执行；win32 直接退出 1（本仓禁止本地起常驻靶场）。
// 本机可跑 `check`（只做前置检查，不拉进程）与本脚本的静态守卫。
//
// 用法：
//   node scripts/ci-benchmark.mjs up      # 下载(pin) → 打包 → 起 HSQLDB + Tomcat → 就绪探测
//   node scripts/ci-benchmark.mjs stop    # 按 pid 文件收工
//   node scripts/ci-benchmark.mjs check   # 只跑前置检查（java/mvn/目录），不拉进程
//
// 环境变量：BENCHMARK_DIR / BENCHMARK_REF / MAVEN_CMD / HSQL_JAR / BENCHMARK_SKIP_DOWNLOAD
// 退出码：0 = 就绪；1 = 任一前置或步骤失败（显式报原因，绝不静默 SKIP）。
// ============================================================================
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const SCRATCH = path.join(ROOT, '.box-agent-scratch');

/** OWASP-Benchmark/BenchmarkJava 的上游 pin（2026-11-12 master；换版本必须同步改 ci.yml 的 env） */
const REF = process.env.BENCHMARK_REF || 'a452b3aafd232245d0753e54eb243d6651f8ef96';
// [D299] pin 源码写死 version.tomcat=9.0.122，但 Apache 已把 9.0.122 从 downloads.apache.org
// 撤下（实测 404，当前 downloads 只剩 9.0.123+）⇒ cargo:run 下载 Tomcat 失败 ⇒ 8443 永不就绪，
// CI #456 step20 卡 240s 后红。archive.apache.org 仍保留 9.0.122（实测 200），且本项目 Maven
// 下载源早已用 archive（见 e2e/benchmark-lab/README.md）。用 -Dtomcat.url 覆盖 pom property：
// 保留 pin 版本不变（可复现），只把下载底座换到 archive。允许 env 覆盖以便日后上游改版。
const TOMCAT_URL = process.env.BENCHMARK_TOMCAT_URL
  || 'https://archive.apache.org/dist/tomcat/tomcat-9/v9.0.122/bin/apache-tomcat-9.0.122.zip';
const DIR = path.resolve(ROOT, process.env.BENCHMARK_DIR || path.join('.verify-labs', 'benchmark-ci'));
const MAVEN = process.env.MAVEN_CMD || 'mvn';
const LOG = path.join(SCRATCH, 'ci-benchmark.log');
const PIDS = path.join(SCRATCH, 'ci-benchmark.pids.json');
const TGZ = path.join(SCRATCH, 'benchmark-ci.tar.gz');

const log = (msg) => console.log(`[ci-benchmark] ${msg}`);
const fail = (msg) => { throw new Error(`[ci-benchmark] ${msg}`); };

/** 跑同步命令；失败时带 stdout/stderr 尾部抛出（不吞错误链）。 */
function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, {
    encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'], ...opts,
  });
  if (r.error || r.status !== 0) {
    const tail = `${r.stdout || ''}${r.stderr || ''}`.slice(-1200);
    fail(`命令失败：${cmd} ${args.join(' ')} (status=${r.status})\n${tail}`);
  }
  return r.stdout || '';
}

/** 前置：必须 Linux；java 与 mvn 可执行。Windows 本机一律拒绝 up。 */
function preflightLinux() {
  if (process.platform === 'win32') {
    fail('up 仅允许在 Linux CI runner 执行（本仓禁止本机起常驻靶场）；本机只可跑 check');
  }
  const j = run('java', ['-version']);
  log(`java: ${(j || '').split('\n')[0] || '未知'}`);
  const m = run(MAVEN, ['-v']);
  log(`mvn: ${(m || '').split('\n')[0] || '未知'}`);
  fs.mkdirSync(SCRATCH, { recursive: true });
}

/** 前置检查（check 命令用；不要求 Linux，不拉进程）。 */
function check() {
  const j = run('java', ['-version']);
  const m = run(MAVEN, ['-v']);
  log(`java: ${(j || '').split('\n')[0] || '未知'}`);
  log(`mvn: ${(m || '').split('\n')[0] || '未知'}`);
  log(`源码目录: ${DIR} (${fs.existsSync(path.join(DIR, 'pom.xml')) ? '已有 pom.xml' : '待下载'})`);
  log(`pin: ${REF}`);
}

/** 按 pin 下载 tarball 并解压到 DIR（幂等；DVWA/VulnLab 同款 codeload 路径）。 */
async function ensureSource() {
  if (fs.existsSync(path.join(DIR, 'pom.xml'))) {
    log(`源码已就绪：${DIR}`);
    return;
  }
  if (process.env.BENCHMARK_SKIP_DOWNLOAD === '1') {
    fail(`缺源码且 BENCHMARK_SKIP_DOWNLOAD=1：${DIR}/pom.xml 不存在`);
  }
  fs.mkdirSync(path.dirname(DIR), { recursive: true });
  fs.mkdirSync(SCRATCH, { recursive: true });
  const url = `https://codeload.github.com/OWASP-Benchmark/BenchmarkJava/tar.gz/${REF}`;
  log(`下载 ${url}`);
  const res = await fetch(url, { headers: { 'User-Agent': 'sqli-scanner-ci' } });
  if (!res.ok) fail(`下载失败 HTTP ${res.status}`);
  fs.writeFileSync(TGZ, Buffer.from(await res.arrayBuffer()));
  run('tar', ['xzf', TGZ, '-C', SCRATCH]);
  const extracted = fs.readdirSync(SCRATCH)
    .filter((n) => n.startsWith('BenchmarkJava-') && fs.statSync(path.join(SCRATCH, n)).isDirectory());
  if (!extracted.length) fail('tarball 解压后找不到 BenchmarkJava-* 顶层目录');
  const src = path.join(SCRATCH, extracted[0]);
  if (fs.existsSync(DIR)) fs.rmSync(DIR, { recursive: true, force: true });
  fs.renameSync(src, DIR);
  log(`源码落地：${DIR}（来自 ${extracted[0]}）`);
}

/** `-Pdeploy` 打包：不带 deploy 时 HSQLDB 的 database-server/database-init 不会跑。 */
function build() {
  if (fs.existsSync(path.join(DIR, 'target', 'benchmark.war'))) {
    log('已打包（target/benchmark.war 存在），跳过 mvn package');
    return;
  }
  log('mvn package -Pdeploy（首次约 5-10 分钟）');
  const out = run(MAVEN, [
    'initialize', 'clean', 'package', '-Pdeploy', '-DskipTests',
    '-Dspotless.check.skip=true', '-Dspotless.apply.skip=true',
    `-Dtomcat.url=${TOMCAT_URL}`,
  ], { cwd: DIR, timeout: 20 * 60 * 1000 });
  fs.appendFileSync(LOG, `\n=== mvn package ===\n${out}\n`);
}

/** 找 HSQLDB jar：优先 env，其次 ~/.m2 下任意版本。 */
function hsqldbJar() {
  if (process.env.HSQL_JAR) {
    if (!fs.existsSync(process.env.HSQL_JAR)) fail(`HSQL_JAR 不存在：${process.env.HSQL_JAR}`);
    return process.env.HSQL_JAR;
  }
  const base = path.join(os.homedir(), '.m2', 'repository', 'org', 'hsqldb', 'hsqldb');
  if (!fs.existsSync(base)) fail(`找不到 HSQLDB 仓库目录：${base}`);
  for (const v of fs.readdirSync(base)) {
    const jar = path.join(base, v, `hsqldb-${v}.jar`);
    if (fs.existsSync(jar)) return jar;
  }
  fail(`~/.m2 里没有 hsqldb-*.jar（先跑 mvn package -Pdeploy）`);
  return '';
}

/** 后台常驻进程：detached + unref，pid 落文件供 stop 收工。 */
function startDetached(label, cmd, args, cwd) {
  const fd = fs.openSync(LOG, 'a');
  const child = spawn(cmd, args, { cwd, detached: true, stdio: ['ignore', fd, fd] });
  child.unref();
  fs.closeSync(fd);
  if (!child.pid) fail(`${label} 启动失败（无 pid）`);
  log(`${label} 已起 pid=${child.pid}`);
  return { label, pid: child.pid };
}

/** 起 HSQLDB @9001 与 Tomcat https/8443；官方 antrun 的 fork 子进程会随 mvn 退出被回收，必须手动常驻。 */
function startServers() {
  const jar = hsqldbJar();
  fs.mkdirSync(path.join(DIR, 'target', 'db'), { recursive: true });
  const dbFile = path.join(DIR, 'target', 'db', 'benchmark.db').replace(/\\/g, '/');
  const pids = [];
  pids.push(startDetached('hsqldb', 'java', [
    '-cp', jar, 'org.hsqldb.Server',
    '--database.0', `file:${dbFile}`, '--dbname.0', 'benchmarkDataBase', '--port', '9001',
  ], DIR));
  pids.push(startDetached('cargo', MAVEN, [
    'cargo:run', '-Pdeploy', '-Dspotless.apply.skip=true', `-Dtomcat.url=${TOMCAT_URL}`,
  ], DIR));
  fs.writeFileSync(PIDS, JSON.stringify(pids, null, 2));
  return pids;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function tcpOpen(port) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port });
    s.setTimeout(1500);
    s.on('connect', () => { s.destroy(); resolve(true); });
    s.on('error', () => { s.destroy(); resolve(false); });
    s.on('timeout', () => { s.destroy(); resolve(false); });
  });
}

/** 就绪探针：9001 TCP + https/8443 的 Benchmark 端点；超时显式红并回显日志尾部。 */
async function waitReady(seconds = 240) {
  // cargo 起的是自签证书；只在本脚本进程内放行（与 e2e/benchmark-lab/run.mjs 同款）。
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  const url = 'https://127.0.0.1:8443/benchmark/sqli-00/BenchmarkTest00025?BenchmarkTest00025=foo';
  for (let i = 0; i < seconds / 5; i++) {
    if (await tcpOpen(9001)) {
      try {
        const r = await fetch(url, { signal: AbortSignal.timeout(5000) });
        if (r.status === 200) { log(`就绪（第 ${i + 1} 次探测）`); return; }
      } catch { /* 冷启动中，继续等 */ }
    }
    await sleep(5000);
  }
  const tail = fs.existsSync(LOG) ? fs.readFileSync(LOG, 'utf8').split('\n').slice(-40).join('\n') : '(无日志)';
  // [D299] HSQLDB 的 "Network client is not a HSQLDB JDBC driver" 只是 TCP 探针噪音，
  // 常把 tail 刷满、盖住真正的 cargo 错误。显式提示优先排查 Tomcat 下载（#456 真因）。
  fail(`${seconds}s 内未就绪（9001/8443）。优先排查：cargo 是否成功下载 Tomcat ` +
    `（pin=9.0.122，downloads.apache.org 已 404，必须 -Dtomcat.url 指向 archive）；` +
    `查看 ${DIR}/target/cargo.log。日志尾部：\n${tail}`);
}

/** stop：按 pid 文件 SIGTERM 收工（进程组，避免 cargo 的子 java 残留）。 */
function stop() {
  if (!fs.existsSync(PIDS)) { log('无 pid 文件，无需收工'); return; }
  for (const { label, pid } of JSON.parse(fs.readFileSync(PIDS, 'utf8'))) {
    try { process.kill(-pid, 'SIGTERM'); log(`已停 ${label} (pgid ${pid})`); } catch { log(`${label} 已退出`); }
  }
  fs.rmSync(PIDS, { force: true });
}

async function main() {
  const cmd = process.argv[2] || 'check';
  if (cmd === 'stop') { stop(); return; }
  if (cmd === 'check') { check(); return; }
  if (cmd !== 'up') fail(`未知命令 ${cmd}（可用 up / stop / check）`);
  preflightLinux();
  await ensureSource();
  build();
  startServers();
  await waitReady();
  log('外部裁判 4 号已在 CI 就绪');
}

main().catch((e) => {
  console.error(`[ci-benchmark] ✖ ${e.message}`);
  process.exit(1);
});
