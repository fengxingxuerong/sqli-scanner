// ============================================================================
// e2e/api-range-lab/harness.mjs —— 接口靶场的「起靶 + 打靶」夹具
//
// 为什么单独一层：cases 只该写"接口的承诺"，不该关心端口分配、子进程回收、
// SSE 分帧、token 携带。这些正是本仓 e2e 历史上反复出假红的地方：
//   · 写死 4567 并与常驻实例抢端口 → 401 假红（见 server/tests/engine.e2e.test.js 头注释）
//   · 后台起的 mysqld 被宿主回收 → 靶站连不上库
//   · 管道接 `| head` 把服务进程打死
// 故这里：随机空闲端口、子进程 stdio 落独立日志文件（不接管道）、显式 kill 句柄、
// 每个请求带显式 token。
// ============================================================================
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(HERE, '../..');
const SERVER_ENTRY = path.join(ROOT, 'server', 'index.js');

const _require = createRequire(new URL('../../server/package.json', import.meta.url));
const mysql = _require('mysql2/promise');

export function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** 最小 HTTP 客户端：拿状态码 + 头 + 原文/JSON，失败不吞（接口测试要看清现场） */
export function request({ port, method = 'GET', path: p, body, headers = {}, token, timeoutMs = 60000 }) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body), 'utf8');
    const h = {};
    // 显式剔除 undefined/null 头值：Node 会直接抛 Invalid value，而"不带某个头"
    // 在测试里恰恰是最常见的写法（断言 401 就是"不带 token"）。
    for (const [k, v] of Object.entries(headers || {})) if (v !== undefined && v !== null) h[k] = String(v);
    if (token) h['x-api-token'] = token;
    if (data && !h['content-type']) h['content-type'] = 'application/json';
    if (data) h['content-length'] = String(data.length);
    const req = http.request({ host: '127.0.0.1', port, method, path: p, headers: h, timeout: timeoutMs }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {
          /* 非 JSON 响应（HTML/CSV/SARIF 之外的导出、SSE）保留原文 */
        }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('timeout', () => req.destroy(new Error(`请求超时 ${method} ${p} (${timeoutMs}ms)`)));
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

/**
 * 打开一个 SSE 连接并按帧解析。
 * @returns {{events:Array, close:()=>void, done:Promise<Array>}}
 */
export function openSse({ port, path: p, token, lastEventId, timeoutMs = 30000 }) {
  const events = [];
  let resolveDone;
  const done = new Promise((r) => (resolveDone = r));
  const headers = { accept: 'text/event-stream' };
  if (lastEventId) headers['last-event-id'] = String(lastEventId);
  const urlPath = token && !p.includes('token=') ? `${p}${p.includes('?') ? '&' : '?'}token=${encodeURIComponent(token)}` : p;
  const req = http.request({ host: '127.0.0.1', port, method: 'GET', path: urlPath, headers, timeout: timeoutMs }, (res) => {
    let buf = '';
    res.setEncoding('utf8');
    res.on('data', (c) => {
      buf += c;
      let idx;
      while ((idx = buf.indexOf('\n\n')) >= 0) {
        const frame = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const evt = { id: null, data: null, raw: frame };
        for (const line of frame.split('\n')) {
          if (line.startsWith('id:')) evt.id = line.slice(3).trim();
          else if (line.startsWith('data:')) evt.data = line.slice(5).trim();
        }
        if (evt.data) {
          try {
            evt.json = JSON.parse(evt.data);
          } catch {
            evt.parseError = true;
          }
          events.push(evt);
        }
      }
    });
    res.on('end', () => resolveDone(events));
  });
  req.on('timeout', () => req.destroy());
  req.on('error', (e) => {
    e.__sseError = true;
    resolveDone(Object.assign(events, { error: e.message }));
  });
  req.end();
  return { events, done, close: () => req.destroy() };
}

/**
 * 启动一个引擎实例（独立端口 / 独立 token / 独立日志文件）。
 * @param {object} [opts]
 * @param {Record<string,string>} [opts.env] 覆盖项（在默认测试 env 之上）
 * @param {string} [opts.name] 日志文件名后缀
 */
export async function startEngine(opts = {}) {
  const port = await freePort();
  const token = randomBytes(16).toString('hex');
  const logName = `engine-${opts.name || port}.log`;
  const logFile = path.join(ROOT, 'logs', logName);
  const env = {
    ...process.env,
    HOST: '127.0.0.1',
    PORT: String(port),
    SCAN_API_TOKEN: token,
    SSRF_ALLOW_PRIVATE: '1', // 靶站就在回环地址：不放开则所有真靶场扫描被 SSRF 闸门拒掉
    EXPLOIT_ENABLED: '1',
    NO_PROXY: '127.0.0.1,localhost',
    no_proxy: '127.0.0.1,localhost',
    ...(opts.env || {}),
  };
  for (const k of ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']) delete env[k];
  const logStream = fs.createWriteStream(logFile, { flags: 'w' });
  const child = spawn(process.execPath, [SERVER_ENTRY], { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.pipe(logStream);
  child.stderr.pipe(logStream);

  const deadline = Date.now() + (opts.bootTimeoutMs || 30000);
  let up = false;
  while (Date.now() < deadline && !up) {
    try {
      const r = await request({ port, path: '/api/health', timeoutMs: 1500 });
      up = r.status === 200;
    } catch {
      await sleep(200);
    }
  }
  if (!up) {
    const tail = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8').slice(-2000) : '(空)';
    child.kill('SIGTERM');
    throw new Error(`引擎未能在 ${port} 就绪，日志尾部：\n${tail}`);
  }
  return {
    port,
    token,
    logFile,
    pid: child.pid,
    async stop() {
      await new Promise((resolve) => {
        const t = setTimeout(() => {
          try {
            child.kill('SIGKILL');
          } catch {
            /* 已退出 */
          }
          resolve();
        }, 12000);
        child.once('exit', () => {
          clearTimeout(t);
          resolve();
        });
        try {
          child.kill('SIGTERM');
        } catch {
          /* 已退出 */
        }
        t.unref?.();
      });
      logStream.end();
    },
  };
}

export function mysqlConfFromEnv() {
  return {
    host: process.env.MYSQL_HOST ?? '127.0.0.1',
    port: Number(process.env.MYSQL_PORT) || 3306,
    user: process.env.MYSQL_USER ?? 'root',
    password: process.env.MYSQL_PASSWORD ?? 'root',
    database: process.env.MYSQL_DATABASE || 'sqli_lab',
    connectionLimit: 8,
  };
}

export { mysql };
