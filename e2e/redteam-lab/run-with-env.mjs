// ============================================================================
// run-with-env.mjs —— redteam-lab 编排包装：先常驻拉起 env.mjs（MySQL+PG+靶场），
// 等靶场端口就绪后运行 run-scan，最后优雅关闭。
// 为什么存在：run-all 只看 exit code，而 run-scan 不含起靶场逻辑 —— 靶场没起时
// run-scan 依然 exit 0（r2 done: 0/26 hit），run-all 误报 PASS（实测踩过）。
// 与其让编排层"自报成功"，不如在这里把「靶场就绪」变成硬前置：端口不通即失败。
// ============================================================================
import { spawn } from 'node:child_process';
import net from 'node:net';

const HERE = new URL('.', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const ROOT = resolveRoot();
const LAB_PORT = Number(process.env.REDTEAM_LAB_PORT) || 8231;

import { resolve as pathResolve } from 'node:path';
function resolveRoot() { return pathResolve(HERE, '../..'); }

const waitPort = (port, timeoutMs = 60000) =>
  new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tryOnce = () => {
      const s = net.connect(port, '127.0.0.1');
      s.on('connect', () => { s.end(); resolve(true); });
      s.on('error', () => { s.destroy(); if (Date.now() - t0 > timeoutMs) reject(new Error(`靶场端口 ${port} 等待超时`)); else setTimeout(tryOnce, 800); });
    };
    tryOnce();
  });

let envStarted = false;
let envProcRef = null;

let scanCode = 1;
try {
  // 先探测是否已有常驻靶场（外部启动模式）
  const preReady = await new Promise((resolve) => {
    const s = net.connect(LAB_PORT, '127.0.0.1');
    s.on('connect', () => { s.end(); resolve(true); });
    s.on('error', () => { s.destroy(); resolve(false); });
  });
  let envOut = '';
  let envExit = null;
  if (preReady) {
    console.log(`[run-with-env] 复用已就绪的外部常驻靶场 :${LAB_PORT}`);
  } else {
    // [CI-FIX 2026-09-21] 原先 `stdio: ['ignore','inherit','inherit']` —— 子进程输出直接进本进程
    // stdout，**本进程读不到内容**。于是 env.mjs 早早判定「本环境没有 mysqld 二进制」并打印
    // [SKIP] 后 exit 0 时，这里仍在死等 8231 端口直到 90s 超时，把一次「缺依赖跳过」报成
    // 「redteam-lab ❌ 失败」。改成 pipe：一边转发一边留档，同时监听 exit 以便提前中止等待。
    envProcRef = spawn(process.execPath, ['e2e/redteam-lab/env.mjs'], {
      cwd: ROOT,
      env: { ...process.env, NO_PROXY: '127.0.0.1,localhost' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    envProcRef.stdout.on('data', (d) => { envOut += d; process.stdout.write(d); });
    envProcRef.stderr.on('data', (d) => { envOut += d; process.stderr.write(d); });
    envStarted = true;
  }
  const ready = await Promise.race([
    waitPort(LAB_PORT, 90000).then(() => 'ready'),
    new Promise((r) => {
      if (!envProcRef) return; // 外部复用模式：没有本进程拉起的 env 可等
      envProcRef.on('exit', (c) => { envExit = c ?? 0; r('exit'); });
    }),
  ]);
  if (ready === 'exit') {
    // 环境进程先于端口就绪而退出：按它**自报的语义**决定是跳过还是失败 ——
    // 打印过 [SKIP] 就是「本环境缺依赖」（与 run-all 对缺依赖套件的口径一致），
    // 否则才是真失败。不再用「等端口超时」这种把两种性质混成一个红灯的判法。
    if (/\[SKIP\]/.test(envOut)) {
      console.log('[run-with-env] 环境依赖缺失（见上方 [SKIP] 行）→ 本套件按设计跳过');
      process.exit(0);
    }
    console.error(`[run-with-env] 环境进程提前退出（code=${envExit}）且未宣告跳过 → 判失败`);
    process.exit(envExit || 1);
  }
  console.log(`[run-with-env] 靶场就绪 :${LAB_PORT}，开始 run-scan`);
  scanCode = await new Promise((resolve) => {
    const p = spawn(process.execPath, ['e2e/redteam-lab/run-scan.mjs', ...(process.argv.slice(2).length ? process.argv.slice(2) : ['r2'])], {
      cwd: ROOT,
      env: { ...process.env, NO_PROXY: '127.0.0.1,localhost', LAB_DB_PASSWORD: process.env.LAB_DB_PASSWORD ?? process.env.MYSQL_PASSWORD ?? 'root' },
      stdio: ['ignore', 'inherit', 'inherit'],
    });
    p.on('exit', (c) => resolve(c ?? 0));
  });
  // [gate-FIX 2026-09-14] run-scan 只负责扫描（恒 exit 0），检出率门禁由 gate-check
  // 独立判定（读 ground-truth 算 rate/fp，≥90% 且零误报才 PASS）。此前编排只透传
  // run-scan 的 exit code——靶场进程中途死亡时扫描全 miss 但 exit 0 → run-all 误报
  // PASS（gate-check.mjs 注释里写明的设计用途，此处才真正接线）。实测踩过两形态：
  // ①靶场没起（0/26）；②靶场中途被杀（1/26、4/26）——两者都只有 gate-check 能拦。
  if (scanCode === 0) {
    console.log(`[run-with-env] run-scan 完成，执行检出率门禁 gate-check`);
    scanCode = await new Promise((resolve) => {
      const g = spawn(process.execPath, ['e2e/redteam-lab/gate-check.mjs', ...(process.argv.slice(2).length ? process.argv.slice(2) : ['r2'])], {
        cwd: ROOT,
        env: { ...process.env, NO_PROXY: '127.0.0.1,localhost' },
        stdio: ['ignore', 'inherit', 'inherit'],
      });
      g.on('exit', (c) => resolve(c ?? 0));
    });
  }
} catch (e) {
  console.error(`[run-with-env] ${e.message}`);
  scanCode = 1;
} finally {
  if (envStarted && envProcRef) { try { envProcRef.kill(); } catch { /* noop */ } }
}
process.exit(scanCode);
