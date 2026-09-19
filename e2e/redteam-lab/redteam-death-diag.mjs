// ============================================================================
// redteam-death-diag.mjs —— TODO 3b：env.mjs 间歇性死亡根因诊断
// 复刻 run-with-env 的 spawn 方式，但加严格观测：
//   ① envProc 的 exit(code, signal)/error 事件全记录（死亡时的退出码与信号是关键证据）
//   ② stdio 从 inherit 改为 pipe 全量捕获（隔离「inherit 管道断裂 → EPIPE」假设）
//   ③ 8231 存活监测与扫描进度（第几个点）时间对齐
// 判读：
//   - exit 带 signal（如 SIGTERM/SIGKILL）→ 外部杀（进程树/job 关联假设成立）
//   - exit code 非 0 + stderr 有栈 → 自身崩溃（读栈定位）
//   - stderr 有 EPIPE/write after end → stdio 管道假设成立
//   - 不复现 → 间歇性，需多次采样
// ============================================================================
import { spawn } from 'node:child_process';
import net from 'node:net';
import { appendFileSync, writeFileSync, readFileSync } from 'node:fs';

const ROOT = process.cwd();
const LAB_PORT = 8231;
const log = (s) => { const t = new Date().toISOString().slice(11, 23); console.log(`[${t}] ${s}`); appendFileSync('e2e/redteam-lab/.diag-death.log', `[${t}] ${s}\n`); };
appendFileSync('e2e/redteam-lab/.diag-death.log', `\n===== 诊断开始 ${new Date().toISOString()} =====\n`);

const envOut = [];
const envErr = [];

// —— 与 run-with-env 完全相同的 spawn 方式 ——
// 模式参数：node redteam-death-diag.mjs [inherit]
//   inherit = 完全复刻 run-with-env（stdout/stderr 接本进程管道 → bash → 文件，验证
//             「inherit 管道断裂 → EPIPE 死亡」假设——历史死亡全部发生在此模式）
//   pipe（默认）= 捕获输出，隔离管道因素（第一轮已跑：存活 19/26 未复现）
const MODE = process.argv[2] === 'inherit' ? 'inherit' : 'pipe';
const envProc = spawn(process.execPath, ['e2e/redteam-lab/env.mjs'], {
  cwd: ROOT,
  env: { ...process.env, NO_PROXY: '127.0.0.1,localhost' },
  stdio: ['ignore', MODE, MODE],
});
log(`spawn 模式: stdio=${MODE}`);
const envT0 = Date.now();
log(`envProc 已 spawn pid=${envProc.pid}`);

if (envProc.stdout) envProc.stdout.on('data', (d) => { envOut.push(d); });
if (envProc.stderr) envProc.stderr.on('data', (d) => { envErr.push(d); });
envProc.on('error', (e) => log(`envProc error 事件: ${e.message}`));
envProc.on('exit', (code, signal) => {
  log(`!!! envProc EXIT  code=${code} signal=${signal} killed=${envProc.killed} 存活=${Math.round((Date.now() - envT0) / 1000)}s`);
  if (MODE === 'pipe') {
    log(`!!! env stderr 最后 600 字: ${Buffer.concat(envErr).toString('utf8').slice(-600).replace(/\n/g, ' | ')}`);
    log(`!!! env stdout 最后 300 字: ${Buffer.concat(envOut).toString('utf8').slice(-300).replace(/\n/g, ' | ')}`);
  }
});

const waitPort = (port, timeoutMs) => new Promise((resolve, reject) => {
  const t0 = Date.now();
  const once = () => {
    const s = net.connect(port, '127.0.0.1');
    s.on('connect', () => { s.end(); resolve(true); });
    s.on('error', () => { s.destroy(); if (Date.now() - t0 > timeoutMs) reject(new Error('超时')); else setTimeout(once, 500); });
  };
  once();
});
await waitPort(LAB_PORT, 60000);
log(`靶场就绪 :${LAB_PORT}（${Math.round((Date.now() - envT0) / 1000)}s），开始 run-scan r2`);

// —— 存活监测：每 2s 探测 + 内存采样（验证 OOM 假设：0xC0000409 可为 V8 OOM 的 fast-fail 表现）——
let dead = false;
const { execSync } = await import('node:child_process');
const memLog = [];
const probeIv = setInterval(() => {
  if (dead) return;
  let ws = '?';
  try {
    ws = execSync(`powershell -NoProfile -Command "(Get-Process -Id ${envProc.pid} -ErrorAction SilentlyContinue).WorkingSet64"`, { encoding: 'utf8', timeout: 3000 }).trim();
    if (ws && ws !== '') memLog.push(`${Math.round(Number(ws) / 1048576)}MB`);
  } catch { /* 进程可能已死 */ }
  const ok = net.connect(LAB_PORT, '127.0.0.1');
  ok.on('connect', () => { ok.end(); });
  ok.on('error', () => { if (!dead) { dead = true; log(`!!! 8231 探测失败（TCP 层不可达）内存曲线: ${memLog.join(' → ')}`); clearInterval(probeIv); } });
  setTimeout(() => { try { ok.destroy(); } catch { /* noop */ } }, 1500);
}, 2000);

// —— run-scan（与 run-with-env 同款 spawn）——
const scanCode = await new Promise((resolve) => {
  const p = spawn(process.execPath, ['e2e/redteam-lab/run-scan.mjs', 'r2'], {
    cwd: ROOT,
    env: { ...process.env, NO_PROXY: '127.0.0.1,localhost', LAB_DB_PASSWORD: 'root' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  p.stdout.on('data', (d) => { out += d; });
  p.stderr.on('data', (d) => { out += d; });
  p.on('exit', (c) => { writeFileSync('e2e/redteam-lab/.diag-scan.log', out); resolve(c ?? 0); });
});
clearInterval(probeIv);
log(`run-scan exit=${scanCode} → ${readScanTail()}`);
log(`8231 中途死亡: ${dead ? '是' : '否'}`);
if (envProc.exitCode === null && !dead) log('（envProc 全程存活，诊断结束——本轮未复现，需多次采样）');
process.exit(0);

function readScanTail() {
  try {
    return readFileSync('e2e/redteam-lab/.diag-scan.log', 'utf8')
      .split('\n').filter((l) => /r2 done|HIT|miss/.test(l)).slice(-3).join(' / ');
  } catch { return '(无扫描输出)'; }
}
