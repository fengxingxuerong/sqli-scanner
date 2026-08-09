import { spawn } from 'node:child_process';
import { nanoid } from 'nanoid';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as eventBus from '../core/eventBus.js';
import { logger } from '../core/logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── 解析 sqlmap 脚本与 Python 解释器 ───────────────────────────────
function resolveInterpreter() {
  // 优先用显式指定的 Python；否则回退 python3 → python
  return process.env.PYTHON_PATH || process.env.SQLMAP_PYTHON || 'python3';
}

function resolveSqlmapScript() {
  // SQLMAP_PATH 可覆盖（指向 sqlmap.py）；否则用项目内置 tools/sqlmap/sqlmap.py
  if (process.env.SQLMAP_PATH) return process.env.SQLMAP_PATH;
  return path.resolve(__dirname, '../../tools/sqlmap/sqlmap.py');
}

// ── 输出行分类（按 sqlmap 前缀判定级别）─────────────────────────────
function classify(line) {
  if (/^\[!\]/.test(line)) return 'error';
  if (/^\[\+\]/.test(line)) return 'success';
  if (/^\[\*\]/.test(line)) return 'info';
  if (/^\[~\]/.test(line)) return 'debug';
  if (/^\[\-\]/.test(line)) return 'warn';
  return 'output';
}

// 从 sqlmap 输出中尝试识别「确认注入」行，解析参数名与技术
function tryParseVuln(line) {
  if (!/is vulnerable/i.test(line)) return null;
  const param = (line.match(/parameter '([^']+)'/i) || [])[1] || null;
  const technique = (line.match(/\(([^)]+)\)/) || [])[1] || 'unknown';
  return { param, technique, raw: line.trim() };
}

// ── 安全构造 sqlmap 参数（数组形式，禁用 shell，杜绝命令注入）────────
function buildArgs(input) {
  const t = input.target || {};
  const c = (input.config && input.config.sqlmap) || {};

  if (typeof t.url !== 'string' || !/^https?:\/\//i.test(t.url)) {
    throw new Error('目标 URL 必须是 http/https');
  }

  const args = ['-u', t.url];

  if (t.method) args.push('--method', String(t.method).toUpperCase());
  if (t.data) args.push('--data', String(t.data));
  if (t.cookie) args.push('--cookie', String(t.cookie));
  if (t.headers) args.push('--headers', String(t.headers));
  if (Array.isArray(t.params) && t.params.length) {
    args.push('-p', t.params.map(String).join(','));
  }

  const level = Number(c.level);
  if (Number.isFinite(level) && level >= 1 && level <= 5) args.push('--level', String(level));

  const risk = Number(c.risk);
  if (Number.isFinite(risk) && risk >= 1 && risk <= 3) args.push('--risk', String(risk));

  if (Array.isArray(c.techniques) && c.techniques.length) {
    const letters = c.techniques
      .filter((x) => /^[BEUSTQ]$/i.test(x))
      .join('')
      .toUpperCase();
    if (letters) args.push('--technique', letters);
  }

  if (Array.isArray(c.tamper) && c.tamper.length) {
    args.push('--tamper', c.tamper.map(String).join(','));
  }

  if (c.dbms) args.push('--dbms', String(c.dbms));

  if (c.proxy) {
    if (!/^(https?|socks5?):\/\//i.test(c.proxy)) throw new Error('proxy 格式非法');
    args.push('--proxy', c.proxy);
  }

  const threads = Number(c.threads);
  if (Number.isFinite(threads) && threads >= 1 && threads <= 10) {
    args.push('--threads', String(threads));
  }

  // ── 破坏性操作：必须显式 opt-in，并打明确告警 ──
  const destructive = [];
  if (c.dump) destructive.push('--dump');
  if (c.osShell) destructive.push('--os-shell');
  if (c.fileRead) {
    destructive.push('--file-read', String(c.fileRead));
  }
  if (destructive.length) {
    logger.warn(`sqlmap 启用破坏性参数：${destructive.join(' ')} —— 仅在已授权目标上使用`);
    args.push(...destructive);
  }

  // 非交互 + 输出到可写临时目录（避免 CWD 只读导致写会话失败）
  args.push('--batch');
  return args;
}

/**
 * sqlmap 桥：把前端的结构化请求翻译为 sqlmap CLI 调用，
 * 流式采集输出并转为与内置引擎兼容的 eventBus 事件，供同一套 SSE 推送给前端。
 */
export class SqlmapBridge {
  constructor() {
    this.scans = new Map();
    this.maxConcurrent = Number(process.env.SQLMAP_MAX_CONCURRENT) || 2;
    this._running = 0;
  }

  // 引擎可用性探测（供前端展示）
  status() {
    const script = resolveSqlmapScript();
    const python = resolveInterpreter();
    let ok = false;
    try {
      fs.accessSync(script, fs.constants.R_OK);
      ok = true;
    } catch {
      ok = false;
    }
    return { available: ok, script, python, maxConcurrent: this.maxConcurrent };
  }

  start(input) {
    const script = resolveSqlmapScript();
    if (!fs.existsSync(script)) {
      throw new Error(
        `未找到 sqlmap 脚本（${script}）。请设置环境变量 SQLMAP_PATH 指向 sqlmap.py，或将 sqlmap 克隆到 tools/sqlmap。`
      );
    }
    if (this._running >= this.maxConcurrent) {
      throw new Error(`sqlmap 并发已达上限（${this.maxConcurrent}），请先停止其它扫描或稍后再试。`);
    }

    const scanId = nanoid(12);
    const rec = { logs: [], vulns: [], state: 'running', child: null };
    this.scans.set(scanId, rec);
    eventBus.create(scanId);
    eventBus.emit(scanId, 'scan_started', { scanId, engine: 'sqlmap', target: input.target });

    const py = resolveInterpreter();
    let args;
    try {
      args = buildArgs(input);
    } catch (e) {
      eventBus.emit(scanId, 'scan_error', { message: e.message });
      rec.state = 'error';
      this.scans.delete(scanId);
      return scanId;
    }

    // 会话/输出写到可写临时目录
    const outDir = path.join(os.tmpdir(), `sqli-scanner-sqlmap-${scanId}`);
    args.push('--output-dir', outDir);

    this._running++;
    const child = spawn(py, [script, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: process.env,
    });
    rec.child = child;

    const emitLog = (level, text) => {
      const entry = { level, text, ts: new Date().toISOString() };
      const r = this.scans.get(scanId);
      if (r) r.logs.push(entry);
      eventBus.emit(scanId, 'sqlmap_log', entry);
    };

    let buf = '';
    const onChunk = (chunk) => {
      buf += chunk.toString();
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, idx).replace(/\r$/, '');
        buf = buf.slice(idx + 1);
        if (!line.trim()) continue;
        emitLog(classify(line), line);
        const vuln = tryParseVuln(line);
        if (vuln) {
          const r = this.scans.get(scanId);
          if (r) r.vulns.push(vuln);
          eventBus.emit(scanId, 'sqlmap_vuln', vuln);
        }
      }
    };

    child.stdout.on('data', onChunk);
    child.stderr.on('data', (c) => emitLog('error', c.toString().replace(/\r?\n+$/, '')));

    child.on('error', (err) => {
      emitLog('error', `启动 sqlmap 失败：${err.message}`);
      eventBus.emit(scanId, 'scan_error', { message: `启动 sqlmap 失败：${err.message}` });
      this._finish(scanId, 'error');
    });

    child.on('close', (code, signal) => {
      const r = this.scans.get(scanId);
      const killed = r && r.state === 'killed';
      if (!killed) {
        if (code === 0) {
          emitLog('info', 'sqlmap 正常结束（退出码 0）');
          this._finish(scanId, 'completed');
        } else if (code === null && signal) {
          this._finish(scanId, 'killed');
        } else {
          emitLog('error', `sqlmap 异常退出（退出码 ${code}）`);
          this._finish(scanId, 'error');
        }
      }
      this._running = Math.max(0, this._running - 1);
    });

    return scanId;
  }

  _finish(scanId, state) {
    const r = this.scans.get(scanId);
    if (!r) return;
    r.state = state;
    eventBus.emit(scanId, 'scan_completed', {
      scanId,
      engine: 'sqlmap',
      state,
      vulnCount: r.vulns.length,
      logCount: r.logs.length,
    });
    // 延迟清理事件命名空间，给前端拉取最终报告留时间
    setTimeout(() => eventBus.dispose(scanId), 60000);
  }

  stop(scanId) {
    const r = this.scans.get(scanId);
    if (!r || !r.child) return false;
    r.state = 'killed';
    try {
      r.child.kill('SIGTERM');
    } catch {
      /* ignore */
    }
    eventBus.emit(scanId, 'scan_stopped', { scanId });
    this._running = Math.max(0, this._running - 1);
    return true;
  }

  getReport(scanId) {
    const r = this.scans.get(scanId);
    if (!r) return null;
    return { engine: 'sqlmap', status: r.state, logs: r.logs, vulns: r.vulns };
  }
}

export default SqlmapBridge;
