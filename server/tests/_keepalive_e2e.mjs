// e2e：启动靶机子进程 + 异步跑 CLI（避免同进程 execFileSync 死锁），
// 验证默认 keepAlive 与 --no-keep-alive 两种模式都能命中布尔注入。
import { execFile } from 'node:child_process';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const NODE = 'C:/Users/Admin（无密码）/.workbuddy/binaries/node/versions/22.22.2/node.exe';
const CLI = fileURLToPath(new URL('../cli.js', import.meta.url));
const TARGET = fileURLToPath(new URL('./_keepalive_target.mjs', import.meta.url));
const CWD = fileURLToPath(new URL('.', import.meta.url));
const TARGET_URL = 'http://127.0.0.1:4569/?id=1';

function runCli(extraArgs) {
  return new Promise((resolve, reject) => {
    const args = [CLI, '-u', TARGET_URL, '--techniques', 'boolean', '--no-extract', ...extraArgs];
    execFile(NODE, args, { cwd: CWD }, (err, stdout, stderr) => {
      if (err) return reject(new Error(`CLI 退出码 ${err.code}\n${stdout}\n${stderr}`));
      resolve(stdout);
    });
  });
}

async function main() {
  // 启动靶机
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
    // 默认（keepAlive 开）：报告里出现 boolean 漏洞即命中（轮询计数在结束前可能停在上一个值，故以最终报告为准）
    const out1 = await runCli([]);
    const hit1 = /\[Medium\] boolean/i.test(out1);
    console.log('[默认 keepAlive] 命中布尔=', hit1);
    if (!hit1) { fail = true; console.log(out1); }

    // --no-keep-alive（关闭连接复用）
    const out2 = await runCli(['--no-keep-alive']);
    const hit2 = /\[Medium\] boolean/i.test(out2);
    console.log('[--no-keep-alive] 命中布尔=', hit2);
    if (!hit2) { fail = true; console.log(out2); }

    if (fail) { console.log('E2E FAIL'); process.exitCode = 1; }
    else console.log('E2E PASS');
  } finally {
    targetProc.kill();
  }
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
