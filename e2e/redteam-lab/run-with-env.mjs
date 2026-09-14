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

const envProc = (() => {
  // [stability-FIX 2026-09-14] 已就绪复用（外部常驻模式）：实测 node spawn 出的 env.mjs
  // 在扫描中段会无栈死亡（1/26、4/26、6/26 三次复现，死点随机；而 Start-Process 完全
  // 独立起的同一 env.mjs 稳定满分 19/19——疑似 Windows 进程树/job 关联问题，待深挖）。
  // 8231 已通时跳过自 spawn，直接复用外部常驻靶场；未就绪才自己拉起（CI 路径）。
  // 注意：外部靶场可能带着上一轮的内存 store 残留，E15-second-order 已用唯一 sid 防串扰。
  return { killed: true, kill() {} }; // 占位：真正 spawn 移至下方 try 内按需执行
})();
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
  if (preReady) {
    console.log(`[run-with-env] 复用已就绪的外部常驻靶场 :${LAB_PORT}`);
  } else {
    envProcRef = spawn(process.execPath, ['e2e/redteam-lab/env.mjs'], {
      cwd: ROOT,
      env: { ...process.env, NO_PROXY: '127.0.0.1,localhost' },
      stdio: ['ignore', 'inherit', 'inherit'],
    });
    envStarted = true;
  }
  await waitPort(LAB_PORT, 90000);
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
