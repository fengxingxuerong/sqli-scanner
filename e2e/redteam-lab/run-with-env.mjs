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

const envProc = spawn(process.execPath, ['e2e/redteam-lab/env.mjs'], {
  cwd: ROOT,
  env: { ...process.env, NO_PROXY: '127.0.0.1,localhost' },
  stdio: ['ignore', 'inherit', 'inherit'],
});

let scanCode = 1;
try {
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
} catch (e) {
  console.error(`[run-with-env] ${e.message}`);
  scanCode = 1;
} finally {
  try { envProc.kill(); } catch { /* noop */ }
}
process.exit(scanCode);
