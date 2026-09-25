// ============================================================================
// sqlmapBridge.js —— sqlmap 桥接器（spawn sqlmap 子进程 + 参数透传 + 日志采集）
// 功能：
//   buildArgs: 32+ sqlmap 参数透传（含 time-sec/ignore-code/exclude-sysdbs/verbose 等）
//   参数 clamp + CR/LF 拒绝 + 头值长度限制
//   子进程 spawn env 白名单（不泄露宿主机环境变量）
//   扫描记录 TTL 清理（60s）+ logs 上限（5000 条）+ 总运行时限
//   status() 不返回绝对路径（防信息泄露）
// ============================================================================

import { spawn } from 'node:child_process';
import { nanoid } from 'nanoid';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as eventBus from '../core/eventBus.js';
import { logger } from '../core/logger.js';
import { AppError, ErrorCode } from '../core/errors.js';
import { isAuthEnabled } from '../core/apiAuthState.js';

// SQLMAP_ALLOW_EVAL：是否允许把 --eval 透传给 sqlmap（默认关）。运行时读取，便于测试与运维动态开关。
function isEvalAllowed() {
  const v = String(process.env.SQLMAP_ALLOW_EVAL || '').trim().toLowerCase();
  return v === '1' || v === 'true';
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── 加固配置 ────────────────────────────────────────────────────────────────
const LOG_CAP = (() => {
  const n = Number(process.env.SQLMAP_LOG_CAP);
  return Number.isInteger(n) && n >= 100 ? n : 5000;
})();
const RECORD_TTL_MS = 60000; // 结束后记录保留时长（给前端拉取最终报告留时间）
const MAX_RUNTIME_MS = (() => {
  const n = Number(process.env.SQLMAP_MAX_RUNTIME_MS);
  return Number.isFinite(n) && n >= 60000 ? n : 30 * 60 * 1000; // 默认 30 分钟
})();
const ARG_MAX = { url: 8192, data: 65536, cookie: 65536, headers: 65536, params: 65536, dbms: 128, tamper: 65536 };

// 长度 clamp 助手（P2-13）
const clampLen = (s, max) => (s.length > max ? s.slice(0, max) : s);
// 头值拒绝 CR/LF（P2-13：防止经 sqlmap --headers 向目标注入额外请求头）
const hasCrlf = (s) => /[\r\n]/.test(s);

function resolveInterpreter() {
  return process.env.PYTHON_PATH || process.env.SQLMAP_PYTHON || 'python3';
}

function resolveSqlmapScript() {
  if (process.env.SQLMAP_PATH) return process.env.SQLMAP_PATH;
  return path.resolve(__dirname, '../../tools/sqlmap/sqlmap.py');
}

function classify(line) {
  if (/^\[!\]/.test(line)) return 'error';
  if (/^\[\+\]/.test(line)) return 'success';
  if (/^\[\*\]/.test(line)) return 'info';
  if (/^\[~\]/.test(line)) return 'debug';
  if (/^\[\-\]/.test(line)) return 'warn';
  return 'output';
}

function tryParseVuln(line) {
  if (!/is vulnerable/i.test(line)) return null;
  const param = (line.match(/parameter '([^']+)'/i) || [])[1] || null;
  const technique = (line.match(/\(([^)]+)\)/) || [])[1] || 'unknown';
  return { param, technique, raw: line.trim() };
}

// 安全构造 sqlmap 参数（数组形式，禁用 shell，杜绝命令注入）——原逻辑 + P2-13 clamp
export function buildArgs(input) {
  const t = input.target || {};
  const c = (input.config && input.config.sqlmap) || {};

  if (typeof t.url !== 'string' || !/^https?:\/\//i.test(t.url)) {
    throw new Error('目标 URL 必须是 http/https');
  }

  const args = ['-u', clampLen(t.url, ARG_MAX.url)];

  if (t.method) args.push('--method', String(t.method).toUpperCase());
  if (t.data) args.push('--data', clampLen(String(t.data), ARG_MAX.data));
  if (t.cookie) args.push('--cookie', clampLen(String(t.cookie), ARG_MAX.cookie));
  if (t.headers) {
    const h = String(t.headers);
    if (hasCrlf(h)) throw new Error('headers 含 CR/LF，已拒绝（防请求头注入）');
    args.push('--headers', clampLen(h, ARG_MAX.headers));
  }
  if (Array.isArray(t.params) && t.params.length) {
    args.push('-p', clampLen(t.params.map(String).join(','), ARG_MAX.params));
  }

  const level = Number(c.level);
  if (Number.isFinite(level) && level >= 1 && level <= 5) args.push('--level', String(level));

  const risk = Number(c.risk);
  if (Number.isFinite(risk) && risk >= 1 && risk <= 3) args.push('--risk', String(risk));

  if (Array.isArray(c.techniques) && c.techniques.length) {
    // 技术字母：B(boolean) E(error) U(union) S(stacked) T(time) Q(inline/query) A(and/or，sqlmap 增加的 AND/OR 变体)
    const letters = c.techniques
      .filter((x) => /^[ABEUSTQ]$/i.test(x))
      .join('')
      .toUpperCase();
    if (letters) args.push('--technique', letters);
  }

  if (Array.isArray(c.tamper) && c.tamper.length) {
    args.push('--tamper', clampLen(c.tamper.map(String).join(','), ARG_MAX.tamper));
  }

  if (c.dbms) args.push('--dbms', clampLen(String(c.dbms), ARG_MAX.dbms));

  if (c.proxy) {
    if (!/^(https?|socks5?):\/\//i.test(c.proxy)) throw new Error('proxy 格式非法');
    args.push('--proxy', c.proxy);
  }

  const threads = Number(c.threads);
  if (Number.isFinite(threads) && threads >= 1 && threads <= 10) {
    args.push('--threads', String(threads));
  }

  // 单位换算：本仓这个字段是**毫秒**（src/shared/constants.ts:61「请求超时（毫秒）」，
  // 面板与 CLI 的 --timeout 也都是 ms），而 sqlmap 的 `--timeout` 是**秒**。
  // 权威依据取自本机那个真二进制（sqlmap 1.10.7，`sqlmap -hh` 原文）：
  //   --timeout=TIMEOUT   Seconds to wait before timeout connection (default 30)
  // 原实现把毫秒直接当秒推过去 ⇒ 面板默认 10000 变成 10000 秒 ≈ 2.8 小时，
  // 于是「单请求超时」永远不会触发，慢目标上改由本文件的 30 分钟总时限把整场扫描
  // 击杀（连已经拿到的结果一起丢）—— 用户设的值方向上还偏偏是往"更长"偏。
  const timeoutMs = Number(c.timeoutMs);
  if (Number.isFinite(timeoutMs) && timeoutMs >= 1 && timeoutMs <= 600000) {
    // 下限兜到 1 秒：sqlmap 收 `--timeout 0` 无意义，而亚秒级超时对连接也没价值
    args.push('--timeout', String(Math.max(1, Math.round(timeoutMs / 1000))));
  }
  const retry = Number(c.retry);
  if (Number.isFinite(retry) && retry >= 1 && retry <= 10) {
    args.push('--retries', String(Math.round(retry)));
  }
  if (c.randomUA) args.push('--random-agent');

  // [sqlmap 对标] 会话/缓存控制：--flush-session（清会话重测）、--fresh-queries（绕过查询结果缓存）
  if (c.flushSession) args.push('--flush-session');
  if (c.freshQueries) args.push('--fresh-queries');
  // [sqlmap 对标] --union-cols：限定 UNION 探测列数范围（默认 1-10，经检测自动扩）
  if (c.unionCols) {
    const cols = String(c.unionCols);
    if (/^\d{1,3}(-\d{1,3})?$/.test(cols)) args.push('--union-cols', cols.slice(0, 16));
  }
  // [sqlmap 对标] --union-char：UNION SELECT 占位字符（默认 NULL，可改数字/字母）
  if (c.unionChar) {
    const ch = String(c.unionChar);
    if (/^[A-Za-z0-9]$/.test(ch)) args.push('--union-char', ch);
  }
  // [sqlmap 对标] --union-from：UNION SELECT 的 FROM 表（用于绕过过滤）
  if (c.unionFrom) {
    const from = String(c.unionFrom).slice(0, 128);
    if (/^[A-Za-z_][A-Za-z0-9_.]*$/.test(from)) args.push('--union-from', from);
  }
  // [sqlmap 对标] --smart：智能启发式（跳过非注入参数），直接透传
  if (c.smart) args.push('--smart');
  // [sqlmap 对标] 新增高频参数：--time-sec（时间盲注秒数）、--ignore-code（忽略状态码）、
  // --exclude-sysdbs（排除系统库，opt-in 对齐 sqlmap CLI，默认不加）、-v（日志详细度 0-6）
  const timeSec = Number(c.timeSec);
  if (Number.isFinite(timeSec) && timeSec >= 1 && timeSec <= 60) {
    args.push('--time-sec', String(Math.round(timeSec)));
  }
  const ignoreCode = c.ignoreCode != null ? Number(c.ignoreCode) : NaN;
  if (Number.isFinite(ignoreCode) && ignoreCode >= 100 && ignoreCode <= 599) {
    args.push('--ignore-code', String(Math.round(ignoreCode)));
  }
  if (c.excludeSysdbs === true) args.push('--exclude-sysdbs');
  // [sqlmap 对标] 低优先级 WAF 规避参数：--no-cast（禁止 CAST 包裹）、--hex（十六进制编码提取）、--no-escape（禁止字符串转义）
  if (c.noCast) args.push('--no-cast');
  if (c.hex) args.push('--hex');
  if (c.noEscape) args.push('--no-escape');
  const verbose = Number(c.verbose);
  if (Number.isFinite(verbose) && verbose >= 0 && verbose <= 6) {
    args.push('-v', String(Math.round(verbose)));
  }

  // [sqlmap 对标 v24] 补齐缺失 CLI 参数 —— 请求形态类
  // --mobile：模拟手机 UA（IM.requests.mobile 等价）；--parse-errors：解析并展示 DBMS 报错
  if (c.mobile) args.push('--mobile');
  if (c.parseErrors) args.push('--parse-errors');
  // --identify-waf：增强 WAF 识别（配合内置 WafIdentifier 结果可互验）
  if (c.identifyWaf) args.push('--identify-waf');
  // --skip-urlencode：跳过默认 URL 编码；--skip-static：跳过静态参数探测
  if (c.skipUrlencode) args.push('--skip-urlencode');
  if (c.skipStatic) args.push('--skip-static');
  // --keep-alive / --null-connection / --predict-output：性能优化三件套
  if (c.keepAlive) args.push('--keep-alive');
  if (c.nullConnection) args.push('--null-connection');
  if (c.predictOutput) args.push('--predict-output');
  // --delay：两次请求间隔秒数（0.5-30，防触发限速/封禁）
  const delay = Number(c.delay);
  if (Number.isFinite(delay) && delay > 0 && delay <= 30) {
    args.push('--delay', String(delay));
  }
  // [sqlmap 对标 v24] 会话保持类：--safe-url / --safe-freq（每 N 次请求访问安全 URL 防会话中断）
  if (c.safeUrl) {
    const u = String(c.safeUrl);
    if (/^https?:\/\//i.test(u)) args.push('--safe-url', clampLen(u, ARG_MAX.url));
  }
  const safeFreq = Number(c.safeFreq);
  if (Number.isFinite(safeFreq) && safeFreq >= 1 && safeFreq <= 100) {
    args.push('--safe-freq', String(Math.round(safeFreq)));
  }
  // [sqlmap 对标 v24] 动态 token：--csrf-url / --csrf-token（CSRF 防护目标必需）
  if (c.csrfUrl) {
    const u = String(c.csrfUrl);
    if (/^https?:\/\//i.test(u)) args.push('--csrf-url', clampLen(u, ARG_MAX.url));
  }
  if (c.csrfToken) args.push('--csrf-token', clampLen(String(c.csrfToken), 256));
  // [sqlmap 对标 v24] 枚举参数（只读无破坏性）：--current-user/--current-db/--hostname/--is-dba
  if (c.currentUser) args.push('--current-user');
  if (c.currentDb) args.push('--current-db');
  if (c.hostname) args.push('--hostname');
  if (c.isDba) args.push('--is-dba');

  const scanCfg = input.config || {};
  const prefix = typeof scanCfg.prefix === 'string' ? scanCfg.prefix.trim() : '';
  if (prefix) args.push('--prefix', prefix.length > 200 ? prefix.slice(0, 200) : prefix);
  const suffix = typeof scanCfg.suffix === 'string' ? scanCfg.suffix.trim() : '';
  if (suffix) args.push('--suffix', suffix.length > 200 ? suffix.slice(0, 200) : suffix);

  // 破坏性操作：必须显式 opt-in，并打明确告警
  const destructive = [];
  if (c.dump) destructive.push('--dump');
  if (c.osShell) destructive.push('--os-shell');
  if (c.fileRead) {
    destructive.push('--file-read', clampLen(String(c.fileRead), 4096));
  }
  // --eval（Python 表达式动态求值参数）属最高危能力：会在**服务端**执行任意 Python 表达式。
  // [P0-SEC 2026-09-18] 从「显式 opt-in + 告警」升级为**默认禁用 + 双条件门控**：
  //   ① 运维显式设置 SQLMAP_ALLOW_EVAL=1（默认关）；
  //   ② 引擎必须已启用 API 鉴权（否则任意本机/同网可达者都能塞一段 Python 进来执行）。
  // 未满足时**直接拒绝**（不静默丢弃参数——静默丢弃会让调用方以为已生效）。
  if (c.evalCode) {
    if (!isEvalAllowed()) {
      throw new AppError(
        ErrorCode.INVALID_PARAM,
        'sqlmap --eval 未启用：该参数会让 sqlmap 在服务端执行 Python 表达式（等价代码执行）。' +
          '确需使用请设置 SQLMAP_ALLOW_EVAL=1，且必须同时启用 API 鉴权（SCAN_API_TOKEN）。'
      );
    }
    if (!isAuthEnabled()) {
      throw new AppError(
        ErrorCode.INVALID_PARAM,
        'sqlmap --eval 需要引擎已启用 API 鉴权：未配置 SCAN_API_TOKEN 时任何人都能提交表达式。' +
          '请设置 SCAN_API_TOKEN（或 SCAN_API_TOKEN_FILE）后重试。'
      );
    }
    logger.warn('sqlmap 启用 --eval（Python 表达式动态求值）—— 仅在已授权目标上使用');
    destructive.push('--eval', clampLen(String(c.evalCode), 4096));
  }
  if (destructive.length) {
    logger.warn(`sqlmap 启用破坏性参数：${destructive.join(' ')} —— 仅在已授权目标上使用`);
    args.push(...destructive);
  }

  args.push('--batch');
  return args;
}

/**
 * sqlmap 桥：把前端的结构化请求翻译为 sqlmap CLI 调用，流式采集输出并转为
 * 与内置引擎兼容的 eventBus 事件，供同一套 SSE 推送给前端。
 */
export class SqlmapBridge {
  constructor() {
    this.scans = new Map();
    this.maxConcurrent = Number(process.env.SQLMAP_MAX_CONCURRENT) || 2;
    this._running = 0;
  }

  // 引擎可用性探测（P2-6：不返回脚本/解释器绝对路径，防信息泄露）
  status() {
    const script = resolveSqlmapScript();
    let ok = false;
    try {
      fs.accessSync(script, fs.constants.R_OK);
      ok = true;
    } catch {
      ok = false;
    }
    return { available: ok, maxConcurrent: this.maxConcurrent };
  }

  start(input) {
    const script = resolveSqlmapScript();
    if (!fs.existsSync(script)) {
      // [防泄露] 不返回脚本绝对路径（状态接口已不暴露路径，启动错误同一策略）
      throw new Error(
        '未找到 sqlmap 脚本。请设置环境变量 SQLMAP_PATH（指向 sqlmap.py）或将 sqlmap 克隆到 tools/sqlmap。'
      );
    }
    if (this._running >= this.maxConcurrent) {
      throw new Error(`sqlmap 并发已达上限（${this.maxConcurrent}），请先停止其它扫描或稍后再试。`);
    }

    const scanId = nanoid(12);
    const rec = { logs: [], vulns: [], state: 'running', child: null, startedAt: Date.now() };
    this.scans.set(scanId, rec);
    eventBus.create(scanId);
    // [P1-4 配套] 事件载荷不再携带完整 target（含 cookie/headers 等敏感字段），只带 URL
    eventBus.emit(scanId, 'scan_started', {
      scanId,
      engine: 'sqlmap',
      target: { url: input.target && input.target.url },
    });

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

    const outDir = path.join(os.tmpdir(), `sqli-scanner-sqlmap-${scanId}`);
    args.push('--output-dir', outDir);

    this._running++;
    const child = spawn(py, [script, ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      // 安全：仅传 sqlmap 需要的环境变量，不泄露宿主机全部 env
      env: {
        PATH: process.env.PATH || '',
        PYTHON_PATH: process.env.PYTHON_PATH || '',
        SQLMAP_PATH: process.env.SQLMAP_PATH || '',
        SQLMAP_PYTHON: process.env.SQLMAP_PYTHON || '',
        SQLMAP_LOG_CAP: process.env.SQLMAP_LOG_CAP || '',
        SQLMAP_MAX_RUNTIME_MS: process.env.SQLMAP_MAX_RUNTIME_MS || '',
        SQLMAP_MAX_CONCURRENT: process.env.SQLMAP_MAX_CONCURRENT || '',
        SQLMAP_OUTPUT_DIR: process.env.SQLMAP_OUTPUT_DIR || '',
        HOME: process.env.HOME || '',
        LANG: process.env.LANG || 'en_US.UTF-8',
      },
    });
    rec.child = /** @type {any} */ (child); // spawn 的 stdio 泛型与 rec.child 的声明不逐一匹配

    // [P1-4] 总运行时限：超时 SIGTERM 子进程并置 error（防 sqlmap 无限期占用并发槽）
    const runtimeTimer = setTimeout(() => {
      const r = this.scans.get(scanId);
      if (!r || r.state !== 'running') return;
      logger.warn(`sqlmap 扫描 ${scanId} 超过总时限 ${Math.round(MAX_RUNTIME_MS / 60000)} 分钟，强制终止`);
      try {
        this._killProcess(r.child);
      } catch {
        /* ignore */
      }
      r._forceTimedOut = true;
    }, MAX_RUNTIME_MS);
    if (typeof runtimeTimer.unref === 'function') runtimeTimer.unref();

    const emitLog = (level, text) => {
      const entry = { level, text, ts: new Date().toISOString() };
      const r = this.scans.get(scanId);
      if (r) {
        // [P1-4] logs 上限：超出截断（丢弃最旧，保留最新）
        r.logs.push(entry);
        if (r.logs.length > LOG_CAP) r.logs.splice(0, r.logs.length - LOG_CAP);
      }
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
      clearTimeout(runtimeTimer);
      const r = this.scans.get(scanId);
      const killed = r && (r.state === 'killed' || r._forceTimedOut);
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
      } else if (r && r._forceTimedOut) {
        this._finish(scanId, 'error');
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
    // [P1-4] 记录 TTL：给前端拉取最终报告留时间后删除记录 + dispose 事件命名空间
    // （原实现 rec 永久驻留内存 → 内存泄漏）
    setTimeout(() => {
      this.scans.delete(scanId);
      eventBus.dispose(scanId);
    }, RECORD_TTL_MS).unref();
  }

  // [B-12] 两阶段终止：SIGTERM 后 5s 未退出则 SIGKILL（防 Python GIL 锁死 / 忽略信号时永远不退出）
  _killProcess(child) {
    try { child.kill('SIGTERM'); } catch { /* ignore */ }
    const killTimer = setTimeout(() => {
      try { child.kill('SIGKILL'); } catch { /* 已退出 */ }
    }, 5000);
    if (typeof killTimer.unref === 'function') killTimer.unref();
  }

  stop(scanId) {
    const r = this.scans.get(scanId);
    if (!r || !r.child) return false;
    r.state = 'killed';
    try {
      this._killProcess(r.child);
    } catch {
      /* ignore */
    }
    eventBus.emit(scanId, 'scan_stopped', { scanId });
    // [P0-FIX] 不在此递减 _running：child.on('close') 回调（第 339 行）是唯一递减点，
    // 否则同一次扫描的并发槽被释放两次，使 maxConcurrent 限制失效。
    return true;
  }

  getReport(scanId) {
    const r = this.scans.get(scanId);
    if (!r) return null;
    return { engine: 'sqlmap', status: r.state, logs: r.logs, vulns: r.vulns };
  }
}

export default SqlmapBridge;
