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
import { dirname, delimiter as PATH_DELIM } from 'node:path';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { evaluate, fromExpress } from '../waf-real/crs-engine.js';

const HERE = dirname(fileURLToPath(import.meta.url));

// [CI-FIX 2026-09-25] classpath 分隔符是**平台相关**的（Windows `;` / POSIX `:`），
// 原实现硬写 `;` ⇒ Linux 上整串 `-cp "D:\...\h2.jar;…;<本目录>"` 被 JVM 看成**一个**条目
// ⇒ 找不到主类 EngineBridge ⇒ JVM 立刻退出；调用方随后往它 stdin 写就拿到 EPIPE，
// 而 stdin 没有 'error' 监听器 ⇒ 未捕获异常掀掉整个 e2e。CI 实测：multi-engine-lab
// 以 `Error: write EPIPE` 在 0.5s 失败，日志里连"为什么"都没有。
// 顺带一条：ENGINE_JARS 未设时原串会带字面量 "undefined"（Windows 上被当无效条目而侥幸无感）。
// ⚠ 只按 **path.delimiter** 拆。我第一版写成"；和 : 都拆一下"，结果在 Windows 上把
//   `D:\engines\jars\h2.jar` 从盘符冒号处切成 "D" + "\engines\…" —— 于是每个 jar 都"不存在"。
//   跨平台复制串错分隔符的情况交给下面的 preflight 明确报"jar 不存在"，
//   不去猜着拆：猜错的拆分会制造查不出来的假失败。
const splitJars = (raw) => String(raw || '').split(PATH_DELIM).map((s) => s.trim()).filter(Boolean);
const JAVA_ARGS = ['-cp', [...splitJars(process.env.ENGINE_JARS), HERE].join(PATH_DELIM), 'EngineBridge'];

/**
 * 桥接的前置自检：ENGINE_JARS 必须给出、且每个 jar 真实存在。
 * 缺了还硬跑，JVM 报的是 `No suitable driver` / 找不到主类 —— 那长得像"方言模板回归"，
 * 实际是环境没配（本仓 docs/P2-dialect-probe 里为此专门写过"必须带 ENGINE_JARS"）。
 * @returns {{ok:boolean, why:string, jars:string[]}}
 */
export function bridgePreflight() {
  const jars = splitJars(process.env.ENGINE_JARS);
  if (!jars.length) {
    return { ok: false, why: '未设置 ENGINE_JARS（需指向 h2 / hsqldb / derby / derbyshared 四个 jar）', jars };
  }
  const missing = jars.filter((j) => !existsSync(j));
  if (missing.length) {
    // CI 实测（2026-09-25）：Linux 上 ENGINE_JARS 常是 Windows 的 ';' 串，被本平台分隔符 `:`
    // 一切就碎成 "D" + "\engines\jars\h2.jar;D"… —— 结论（不存在）没错，但读的人看不出
    // 自己贴错了格式。所以补一句人话：本平台的分隔符是什么、这串像哪种写法。
    const looksForeign = missing.some((j) => j.includes(';'));
    return {
      ok: false,
      why:
        `ENGINE_JARS 中这些 jar 不存在：${missing.join('、')}` +
        (looksForeign && PATH_DELIM !== ';'
          ? `（本平台 classpath 分隔符是 "${PATH_DELIM}"，而串里带 ";" —— 像是 Windows 写法直接贴过来的）`
          : ''),
      jars,
    };
  }
  return { ok: true, jars };
}

export class EngineBridgeClient {
  constructor(javaBin) {
    this.javaBin = javaBin || process.env.JAVA_BIN || 'java';
    this.proc = null;
    this.pending = [];
    this.buf = '';
    this.ready = false;
    // 桥死掉时的"它自己说了什么"（stderr 尾部）与不可用原因，用于把裸 EPIPE 变成可诊断的失败
    this.stderrTail = '';
    this.dead = '';
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
    this.proc.stderr.on('data', (d) => {
      // 留尾部若干字符：桥死掉时报错要有"它自己说了什么"，否则只剩一句 write EPIPE
      this.stderrTail = (this.stderrTail + d).slice(-600);
      process.stderr.write(`[bridge] ${d}`);
    });
    // [CI-FIX 2026-09-25] 三个"没人接就变成未捕获异常"的口子，全都接上：
    //   ① stdin：JVM 已退出时 write 会**异步**抛 EPIPE（CI 那次就是这条裸崩掉整个 e2e）
    //   ② 子进程 'error'：JAVA_BIN 指错 / 机器上没 java ⇒ 只有 'error'，没有 'exit'
    //   ③ 唤醒等待者，否则调用方永远 await 着一个不会有回复的 Promise
    this.proc.stdin.on('error', (e) => {
      this.dead = `stdin 写入失败（${e.code || e.message}）；桥此前输出：${this.stderrTail.slice(-200) || '(无)'}`;
      this.ready = false;
      for (const w of this.pending.splice(0)) w(null);
    });
    this.proc.on('error', (e) => {
      this.dead = `无法启动 JVM（${this.javaBin}：${e.code || e.message}）`;
      this.ready = false;
      for (const w of this.pending.splice(0)) w(null);
    });
    this.proc.on('exit', (code) => {
      this.ready = false;
      this.dead = this.dead || `JVM 退出（code=${code}）；输出尾部：${this.stderrTail.slice(-200) || '(无输出)'}`;
      // 唤醒所有等待者，避免悬挂
      for (const w of this.pending.splice(0)) w(null);
    });
    this.ready = true;
    return this;
  }

  /** 桥不可用时的原因（未启动 / 已退出 / spawn 失败），供调用方打进现场 */
  get deadReason() {
    return this.dead || (this.ready ? null : 'bridge not started');
  }

  async query(engine, sql) {
    if (!this.ready) throw new Error(`bridge not started（${this.deadReason || '未调用 start()'}）`);
    return new Promise((res) => {
      this.pending.push((line) => {
        if (line == null) return res({ ok: false, error: this.deadReason || 'bridge exited' });
        try { res(JSON.parse(line)); } catch { res({ ok: false, error: `bad bridge line: ${line}` }); }
      });
      // 同步异常（极少数：流已销毁且错误在写回调外抛）也要唤醒等待者，别让它悬着
      try {
        this.proc.stdin.write(`${engine}\t${sql.replace(/\t/g, ' ')}\n`);
      } catch (e) {
        const w = this.pending.shift();
        if (w) w(null);
      }
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
