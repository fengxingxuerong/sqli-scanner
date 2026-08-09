// e2e：启动靶机子进程 + 异步跑 CLI（避免同进程 execFileSync 死锁），
// 验证多 safe-url（逗号分隔）随机轮询真正常用：扫描命中布尔注入，且报告里记录 safeProbeAlerts 为空（稳定不告警）。
import { execFile } from 'node:child_process';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readFileSync, unlinkSync } from 'node:fs';

const NODE = 'C:/Users/Admin（无密码）/.workbuddy/binaries/node/versions/22.22.2/node.exe';
const CLI = fileURLToPath(new URL('../cli.js', import.meta.url));
const TARGET = fileURLToPath(new URL('./_safemulti_target.mjs', import.meta.url));
const CWD = fileURLToPath(new URL('.', import.meta.url));
const TARGET_URL = 'http://127.0.0.1:4571/?id=1';
const SAFE = 'http://127.0.0.1:4571/safe1,http://127.0.0.1:4571/safe2';
const OUT_JSON = fileURLToPath(new URL('./_safemulti_out.json', import.meta.url));

function runCli(extraArgs) {
  return new Promise((resolve, reject) => {
    const args = [CLI, '-u', TARGET_URL, '--techniques', 'boolean', '--no-extract',
      '--safe-url', SAFE, '--safe-freq', '2', '--output', OUT_JSON, ...extraArgs];
    execFile(NODE, args, { cwd: CWD }, (err, stdout, stderr) => {
      if (err) return reject(new Error(`CLI 退出码 ${err.code}\n${stdout}\n${stderr}`));
      try {
        const json = JSON.parse(readFileSync(OUT_JSON, 'utf8'));
        resolve(json);
      } catch (e) {
        reject(new Error(`读取报告失败：${e.message}\n${stdout}`));
      }
    });
  });
}

async function main() {
  const targetProc = spawn(NODE, [TARGET], { stdio: ['ignore', 'pipe', 'pipe'] });
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('靶机启动超时')), 5000);
    targetProc.stdout.on('data', (d) => {
      if (String(d).includes('target-up')) { clearTimeout(t); resolve(); }
    });
    targetProc.stderr.on('data', (d) => process.stderr.write(`[target] ${d}`));
  });

  let fail = false;
  try {
    // 默认随机轮询多 safe-url
    const report = await runCli([]);
    const hit = (report.vulns || []).some((v) => v.technique === 'boolean');
    console.log('[多 safe-url 随机轮询] 命中布尔=', hit);
    // 稳定不告警：safeProbeAlerts 应为空或不存在
    const alerts = report.summary?.safeProbeAlerts || [];
    console.log('[多 safe-url] 安全探测告警数=', alerts.length);
    if (!hit) { fail = true; console.log(JSON.stringify(report)); }
    if (alerts.length > 0) { fail = true; console.log('不应在稳定靶机告警', JSON.stringify(alerts)); }

    // --safe-order 顺序轮询也应命中且不告警
    const report2 = await runCli(['--safe-order']);
    const hit2 = (report2.vulns || []).some((v) => v.technique === 'boolean');
    const alerts2 = report2.summary?.safeProbeAlerts || [];
    console.log('[多 safe-url 顺序轮询] 命中布尔=', hit2, '告警数=', alerts2.length);
    if (!hit2 || alerts2.length > 0) { fail = true; }

    if (fail) { console.log('E2E FAIL'); process.exitCode = 1; }
    else console.log('E2E PASS');
  } finally {
    targetProc.kill();
    try { unlinkSync(OUT_JSON); } catch {}
  }
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
