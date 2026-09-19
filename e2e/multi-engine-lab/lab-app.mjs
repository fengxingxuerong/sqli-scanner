// ============================================================================
// e2e/multi-engine-lab/lab-app.mjs —— 多引擎靶场（H2 / HSQLDB / Derby）
// 结构与 real-mysql-lab/lab-app.js 同构：Express 端点 → 拼接 SQL → 引擎执行。
// 差异：引擎执行经子进程 EngineBridge（JVM 常驻，行协议 \t 分隔），不走 TCP 驱动。
// WAF：复用 waf-real/crs-engine.js（OWASP CRS v4.1.0 官方规则 + 自实现执行器 ≈PL3）。
// 场景端点（与 real-mysql-lab 对齐，便于横向对比）：
//   /num?id=1          数值型注入    SELECT ... WHERE id=<v>
//   /str?name=alice     字符串型注入  SELECT ... WHERE name='<v>'
//   /blind?uid=1        无回显盲注    SELECT COUNT(*) WHERE uid=<v> → 命中与否页面不同
//   /safe?id=1          安全对照      参数化查询（不应误拦/误报）
// ============================================================================
import { createRequire } from 'node:module';
const _require = createRequire(new URL('../../server/package.json', import.meta.url));
const express = _require('express');
import { spawn } from 'node:child_process';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluate, fromExpress } from '../waf-real/crs-engine.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const JAVA_ARGS = ['-cp', `${process.env.ENGINE_JARS};${HERE}`, 'EngineBridge'];

export class EngineBridgeClient {
  constructor(javaBin) {
    this.javaBin = javaBin || process.env.JAVA_BIN || 'java';
    this.proc = null;
    this.pending = [];
    this.buf = '';
    this.ready = false;
  }

  start() {
    this.proc = spawn(this.javaBin, JAVA_ARGS, { cwd: HERE, stdio: ['pipe', 'pipe', 'pipe'] });
    this.proc.stdout.setEncoding('utf8');
    this.proc.stdout.on('data', (d) => {
      this.buf += d;
      let idx;
      while ((idx = this.buf.indexOf('\n')) >= 0) {
        const line = this.buf.slice(0, idx);
        this.buf = this.buf.slice(idx + 1);
        const waiter = this.pending.shift();
        if (waiter) waiter(line);
      }
    });
    this.proc.stderr.setEncoding('utf8');
    this.proc.stderr.on('data', (d) => process.stderr.write(`[bridge] ${d}`));
    this.proc.on('exit', (code) => {
      this.ready = false;
      // 唤醒所有等待者，避免悬挂
      for (const w of this.pending.splice(0)) w(null);
    });
    this.ready = true;
    return this;
  }

  async query(engine, sql) {
    if (!this.ready) throw new Error('bridge not started');
    return new Promise((res) => {
      this.pending.push((line) => {
        if (line == null) return res({ ok: false, error: 'bridge exited' });
        try { res(JSON.parse(line)); } catch { res({ ok: false, error: `bad bridge line: ${line}` }); }
      });
      this.proc.stdin.write(`${engine}\t${sql.replace(/\t/g, ' ')}\n`);
    });
  }

  stop() {
    if (this.proc) {
      try { this.proc.stdin.end(); this.proc.kill(); } catch { /* ignore */ }
    }
  }
}

export function createMultiEngineApp(bridge, engine, { waf = true } = {}) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  if (waf) {
    app.use((req, res, next) => {
      const verdict = evaluate(fromExpress(req));
      if (verdict.blocked) {
        res.status(403).send(`<!DOCTYPE html><html><body><h1>403</h1><p>Request blocked by OWASP CRS rule ${verdict.ruleId}</p></body></html>`);
        return;
      }
      next();
    });
  }

  const wrap = (fn) => (req, res) => {
    fn(req).then(({ status, body }) => {
      res.status(status).type('html').send(`<html><body>${body}</body></html>`);
    }).catch((e) => res.status(500).send(`<html><body>err ${e.message}</body></html>`));
  };

  // 数值型：SELECT * FROM users WHERE id=<v>
  app.get('/num', wrap(async (req) => {
    const v = req.query.id || '1';
    const r = await bridge.query(engine, `SELECT * FROM users WHERE id=${v}`);
    if (!r.ok) return { status: 200, body: `<p>id=${v}</p><pre>${r.error}</pre>` };
    return { status: 200, body: `<p>id=${v}</p><pre>${JSON.stringify(r.rows)}</pre>` };
  }));

  // 字符串型：SELECT * FROM users WHERE name='<v>'
  app.get('/str', wrap(async (req) => {
    const v = req.query.name || 'user1';
    const r = await bridge.query(engine, `SELECT * FROM users WHERE name='${v}'`);
    if (!r.ok) return { status: 200, body: `<p>name=${v}</p><pre>${r.error}</pre>` };
    return { status: 200, body: `<p>name=${v}</p><pre>${JSON.stringify(r.rows)}</pre>` };
  }));

  // 盲注：命中 5 行 vs 0 行，页面长度不同
  app.get('/blind', wrap(async (req) => {
    const v = req.query.uid || '1';
    const r = await bridge.query(engine, `SELECT COUNT(*) FROM users WHERE id=${v}`);
    const n = r.ok && r.rows[0] && r.rows[0][0] ? Number(r.rows[0][0]) : 0;
    if (n > 0) return { status: 200, body: `<p>uid=${v}</p><p>found</p>${'<div>data</div>'.repeat(20)}` };
    return { status: 200, body: `<p>uid=${v}</p><p>not found</p>` };
  }));

  // 安全对照：参数化（数值由 Number() 归一化，非数字直接拒）
  app.get('/safe', wrap(async (req) => {
    const n = Number(req.query.id);
    if (!Number.isInteger(n)) return { status: 400, body: '<p>bad id</p>' };
    const r = await bridge.query(engine, `SELECT * FROM users WHERE id=${n}`);
    return { status: 200, body: `<p>safe id=${n}</p><pre>${r.ok ? JSON.stringify(r.rows) : r.error}</pre>` };
  }));

  return app;
}
