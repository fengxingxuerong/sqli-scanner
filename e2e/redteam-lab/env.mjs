// ============================================================================
// env.mjs —— 红队评测环境一键拉起（MySQL + 靶场，同一进程内常驻）
//
// 为什么要这个脚本：mysqld 若用「单独的后台命令 + detached」启动，父进程一退出
// 就会被回收（本机实测：连着被杀两次），靶场随后连不上 3306。
// 这里在同一个 node 进程里先后拉起两者并常驻，进程活着 → 两个服务都活着。
//
// 用法：
//   node e2e/redteam-lab/env.mjs            # 前台常驻（Ctrl+C 结束）
//   也可由 CI/Agent 作为后台任务启动
// ============================================================================
import { spawn } from 'node:child_process';
import net from 'node:net';
import { createRequire } from 'node:module';

const MYSQLD = process.env.MYSQLD_PATH || 'D:/mysql/bin/mysqld.exe';
const MYSQL_CWD = process.env.MYSQL_CWD || 'D:/mysql';
const LAB_PORT = Number(process.env.REDTEAM_LAB_PORT) || 8231;

const waitPort = (port, timeoutMs = 60000) =>
  new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tryOnce = () => {
      const s = net.connect(port, '127.0.0.1');
      s.on('connect', () => { s.end(); resolve(true); });
      s.on('error', () => {
        s.destroy();
        if (Date.now() - t0 > timeoutMs) reject(new Error(`端口 ${port} 等待超时`));
        else setTimeout(tryOnce, 1000);
      });
    };
    tryOnce();
  });

// 1) MySQL：已监听则复用，否则拉起
let mysqld = null;
try {
  await waitPort(3306, 1500);
  console.log('[env] MySQL 已在运行，复用');
} catch {
  console.log(`[env] 启动 MySQL：${MYSQLD}`);
  // --skip-grant-tables：本机 MySQL 实例的 root 口令未知，而靶场代码里是空口令连。
  // 加这个参数后免密即可连接，**不去改用户的 root 密码**（最小侵入，仅本次进程生效）。
  // 靶场是本地一次性评测用库，权限系统关闭无影响。
  // ⚠️ 不要加 --skip-grant-tables：它会顺带禁用 TCP（日志里 port: 0、
  // "TCP/IP, --shared-memory, or --named-pipe should be configured"），靶场用的正是 TCP。
  // 口令问题改由 LAB_DB_PASSWORD 解决。
  mysqld = spawn(MYSQLD, ['--console'], { cwd: MYSQL_CWD, stdio: ['ignore', 'ignore', 'ignore'] });
  mysqld.on('error', (e) => console.error(`[env] mysqld 启动失败：${e.message}`));
  await waitPort(3306, 60000);
  console.log('[env] MySQL 就绪（3306）');
}

// 1.5) 探测 root 口令（本机实例未必是空口令；其它 e2e 靶场用的是 root/root）
process.env.LAB_DB_PASSWORD = process.env.LAB_DB_PASSWORD || '';
try {
  // mysql2 装在 server/node_modules：用 createRequire 按 server 包解析（与 lab-app.mjs 同源）
  const req = createRequire(new URL('../../server/package.json', import.meta.url));
  const mysql2 = req('mysql2/promise');
  const candidates = [process.env.LAB_DB_PASSWORD, 'root', ''];
  for (const pw of candidates) {
    try {
      const c = await mysql2.createConnection({ host: '127.0.0.1', port: 3306, user: 'root', password: pw, connectTimeout: 3000 });
      await c.query('SELECT 1');
      await c.end();
      process.env.LAB_DB_PASSWORD = pw;
      console.log(`[env] MySQL 口令探测成功（${pw === '' ? '空口令' : 'root'}）`);
      break;
    } catch { /* 换下一个候选 */ }
  }
} catch (e) {
  console.warn(`[env] 口令探测跳过：${e.message}`);
}

// 2) 靶场：内联启动（与 mysqld 同进程生命周期）
const { createLabApp } = await import('./lab-app.mjs');
const app = await createLabApp();
const server = app.listen(LAB_PORT, () => {
  console.log(`[env] 靶场就绪 http://127.0.0.1:${LAB_PORT}`);
});

// 3) 优雅退出
const shutdown = () => {
  server.close(() => {
    if (mysqld) try { mysqld.kill(); } catch { /* noop */ }
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 3000);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
