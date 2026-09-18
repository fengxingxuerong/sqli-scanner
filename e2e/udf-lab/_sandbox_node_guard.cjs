// e2e/udf-lab/_sandbox_node_guard.cjs
//
// Node 侧沙箱守卫（CommonJS，供 --require 预加载）
//
// ============================================================================
// 为什么需要它
// ============================================================================
// 实测确认（2026-09-18）：Python 的 sys.addaudithook **不穿透进程边界**，
// 被测的 node 进程内部 `child_process.execSync('powershell ...')` 完全
// 不被 Python 钩子看见。所以 Python 层做不出对 node 子进程的约束。
//
// Node 侧必须自己装守卫 —— 用 `--require` 在目标脚本执行**之前**加载本文件，
// 劫持 child_process 与 net/dns，使越界动作在**发起前**就被拒绝。
//
// 本文件是**唯一**能真正拦住 node 内越权动作的机制。
// Python 审计钩子负责记录与约束它自己起的进程，两者互补。
//
// ============================================================================
// 边界（诚实声明）
// ============================================================================
// · 只覆盖 `node:child_process`、`node:net`、`node:dns` 的公开入口。
// · 绕过路径：`process.binding`、原生插件、`node:worker_threads` 里再 require、
//   或直接写 `require('child_process')` 的已缓存模块引用 —— 本守卫会在
//   模块缓存层面替换，但无法覆盖 V8 内部原生绑定。
// · 定位是「防误操作 + 让越界动作显式失败」，不是对抗恶意代码的强隔离。
// ============================================================================

'use strict';

const path = require('node:path');

// —— 策略（由环境变量注入，避免硬编码）——
const ALLOWED_EXECUTABLES = new Set(
  (process.env.SANDBOX_ALLOWED_EXECUTABLES ||
    'node,node.exe,cmd,cmd.exe,mysql,mysql.exe,mysqld,mysqld.exe')
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
);

const ALLOWED_CMD_VERBS = new Set(
  (process.env.SANDBOX_ALLOWED_CMD_VERBS || 'echo,whoami,ver,hostname,set')
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
);

const ALLOWED_HOSTS = new Set(
  (process.env.SANDBOX_ALLOWED_HOSTS || '127.0.0.1,localhost,::1')
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
);

// 允许写这些目录（分号分隔；为空则只允许沙箱临时目录）
const WRITE_ROOTS = (process.env.SANDBOX_WRITE_ROOTS || '')
  .split(path.delimiter).map((s) => s.trim()).filter(Boolean)
  .map((p) => path.resolve(p));

const ALLOW_COMMAND_EXEC = process.env.SANDBOX_ALLOW_COMMAND_EXEC === '1';

// —— 审计输出（写 stderr，Python 侧汇总）——
const violations = [];
function violation(kind, detail) {
  const msg = `[node-guard] ${kind}：${detail}`;
  violations.push(msg);
  process.stderr.write(msg + '\n');
}

function SandboxDeny(action, detail) {
  const e = new Error(`[sandbox] 拒绝${action}：${detail}`);
  e.code = 'SANDBOX_DENIED';
  return e;
}

// ---------------------------------------------------------------------------
// child_process 守卫
// ---------------------------------------------------------------------------

function baseName(exe) {
  return path.basename(String(exe || '')).toLowerCase();
}

/** 校验一次命令调用；不允许则抛错。 */
function checkCommand(file, args) {
  const base = baseName(file);
  if (!base) {
    violation('命令被拒', '<空可执行名>');
    throw SandboxDeny('执行', '可执行文件名为空');
  }
  if (!ALLOWED_EXECUTABLES.has(base)) {
    violation('命令被拒', `${base} 不在可执行白名单`);
    throw SandboxDeny('执行', `${base} 不在可执行白名单内`);
  }
  if (base === 'cmd' || base === 'cmd.exe') {
    const argv = Array.isArray(args) ? args : [args];
    const joined = argv.map(String).join(' ');
    const m = /\/c\s+(.+)$/i.exec(joined.replace(/["']/g, ' '));
    if (!m) {
      violation('cmd 被拒', `未使用 /c：${joined.slice(0, 80)}`);
      throw SandboxDeny('cmd 调用', `未使用 /c 形式：${joined.slice(0, 80)}`);
    }
    const first = m[1].trim().split(/\s+/)[0] || '';
    let verb = path.basename(first).toLowerCase().split('.')[0].split('/')[0];
    if (verb && !ALLOWED_CMD_VERBS.has(verb)) {
      for (const a of ALLOWED_CMD_VERBS) {
        if (verb.startsWith(a)) { verb = a; break; }
      }
    }
    if (!ALLOWED_CMD_VERBS.has(verb)) {
      violation('cmd 被拒', `动词 ${verb} 不在白名单`);
      throw SandboxDeny('cmd 调用', `动词 ${verb} 不在白名单`);
    }
    // sys_eval 类动作：动词合法也需显式授权。
    // SANDBOX_ALLOW_COMMAND_EXEC 由 sandbox.py 的 --allow-command-exec 设置；
    // 未授权时拒绝任何 cmd 调用，避免"白名单内命令"被用作命令执行原语。
    if (!ALLOW_COMMAND_EXEC) {
      violation('cmd 被拒', '未声明 --allow-command-exec');
      throw SandboxDeny('cmd 调用',
        '未声明已授权系统命令执行（需 --allow-command-exec）');
    }
  }
}

// 劫持 child_process 各同步/异步入口
const cp = require('node:child_process');

function wrapSync(name) {
  const orig = cp[name];
  if (typeof orig !== 'function') return;
  cp[name] = function (file, args, options) {
    // execSync(cmd) 形态：字符串单参数
    if (typeof file === 'string' && args !== undefined
        && (typeof args === 'object' && !Array.isArray(args))) {
      // execSync('cmd /c ...') —— 首个 token 是可执行名
      const first = file.trim().split(/\s+/)[0];
      checkCommand(first, [file]);
    } else {
      checkCommand(file, args);
    }
    return orig.apply(this, arguments);
  };
}

for (const n of ['execSync', 'execFileSync', 'spawnSync', 'exec', 'execFile', 'spawn', 'fork']) {
  wrapSync(n);
}

// ---------------------------------------------------------------------------
// net / dns 守卫：出站只允许白名单地址
// ---------------------------------------------------------------------------

try {
  const net = require('node:net');
  const origConnect = net.Socket.prototype.connect;

  /**
   * 从 connect() 的任意重载形态里抽出目标主机。
   * net.connect 支持：
   *   connect(options)            → options.host / options.path
   *   connect(port[, host])       → 数字在前，主机在后  ★曾漏掉这种
   *   connect(path[, cb])         → 命名管道/Unix socket
   */
  function extractHost(a) {
    if (a.length === 0) return '';
    const first = a[0];
    // 形态一：options 对象
    if (typeof first === 'object' && first !== null) {
      return String(first.host || first.path || '');
    }
    // 形态二：connect(port, host) —— 数字/数字字符串在前
    if (typeof first === 'number' || /^\d+$/.test(String(first))) {
      for (let i = 1; i < a.length; i++) {
        if (typeof a[i] === 'string' && !/^\d+$/.test(a[i])) return a[i];
      }
      // 只给了端口（等价 localhost）
      return '127.0.0.1';
    }
    // 形态三：connect(path, cb)
    if (typeof first === 'string') {
      return /^\d+$/.test(first) ? '127.0.0.1' : first;
    }
    return '';
  }

  function isAllowedHost(host) {
    const bare = String(host).replace(/^\[|\]$/g, '').toLowerCase();
    if (!bare) return true;                    // 解析不出就不拦（避免误伤）
    if (ALLOWED_HOSTS.has(bare)) return true;
    if (/^\d+(\.\d+){3}$/.test(bare)) {
      // 裸 IP：只放行回环段
      return bare === '127.0.0.1' || bare.startsWith('127.');
    }
    return false;
  }

  net.Socket.prototype.connect = function (...a) {
    const host = extractHost(a);
    if (!isAllowedHost(host)) {
      violation('出站被拒', `connect(${host})`);
      throw SandboxDeny('连接', `非白名单地址 ${host}`);
    }
    return origConnect.apply(this, a);
  };

  // net.connect(...) 顶层函数同样要覆盖
  const origNetConnect = net.connect;
  net.connect = function (...a) {
    const host = extractHost(a);
    if (!isAllowedHost(host)) {
      violation('出站被拒', `net.connect(${host})`);
      throw SandboxDeny('连接', `非白名单地址 ${host}`);
    }
    return origNetConnect.apply(this, a);
  };

  // http/https 也要拦（否则可绕道 fetch/axios）
  for (const mod of ['node:http', 'node:https']) {
    try {
      const m = require(mod);
      const origReq = m.request;
      m.request = function (...a) {
        let host = '';
        const o = a[0];
        if (typeof o === 'string') {
          try { host = new URL(o).hostname; } catch { host = ''; }
        } else if (o && typeof o === 'object') {
          host = String(o.hostname || o.host || '');
        }
        if (host && !isAllowedHost(host)) {
          violation('HTTP 出站被拒', `${mod} request(${host})`);
          throw SandboxDeny('HTTP 请求', `非白名单地址 ${host}`);
        }
        return origReq.apply(this, a);
      };
    } catch { /* 模块不可用时跳过 */ }
  }
} catch { /* net 不可用时跳过 */ }

try {
  const dns = require('node:dns');
  const origLookup = dns.lookup;

  /** 与 net 守卫同一套判定：只放行白名单主机名与回环 IP。 */
  function dnsAllowed(hostname) {
    const h = String(hostname).toLowerCase().replace(/^\[|\]$/g, '');
    if (ALLOWED_HOSTS.has(h)) return true;
    if (/^\d+(\.\d+){3}$/.test(h)) {
      return h === '127.0.0.1' || h.startsWith('127.');
    }
    return false;
  }

  dns.lookup = function (hostname, ...rest) {
    if (!dnsAllowed(hostname)) {
      violation('DNS 被拒', hostname);
      const cb = rest.find((x) => typeof x === 'function');
      const err = SandboxDeny('解析域名', `${hostname} 不在白名单`);
      if (cb) return cb(err);
      throw err;
    }
    return origLookup.call(this, hostname, ...rest);
  };
} catch { /* dns 不可用时跳过 */ }

// ---------------------------------------------------------------------------
// fs 写守卫：只允许写白名单目录
// ---------------------------------------------------------------------------

try {
  const fs = require('node:fs');
  const WRITE_FLAGS = /[wa]/;
  function checkWrite(p) {
    if (!p) return;
    if (WRITE_ROOTS.length === 0) return;
    let rp;
    try { rp = path.resolve(String(p)); } catch { return; }
    const ok = WRITE_ROOTS.some((root) => {
      const rel = path.relative(root, rp);
      return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
    });
    if (!ok) {
      violation('写入被拒', rp);
      throw SandboxDeny('写入', `${rp} 不在白名单目录内`);
    }
  }

  for (const name of ['writeFileSync', 'appendFileSync', 'mkdirSync', 'openSync',
                      'rmSync', 'unlinkSync', 'renameSync', 'copyFileSync']) {
    const orig = fs[name];
    if (typeof orig !== 'function') continue;
    fs[name] = function (p, ...rest) {
      // open 仅写模式才检查
      if (name === 'openSync') {
        const flags = rest[0];
        if (typeof flags === 'string' && !WRITE_FLAGS.test(flags)) {
          return orig.apply(this, arguments);
        }
        checkWrite(p);
        return orig.apply(this, arguments);
      }
      // ★ copyFileSync(src, dest)：只检查**目标**，源文件仅需读权限。
      //   曾误查源路径，导致正常复制 .dll 被拦（实测 2026-09-18）。
      if (name === 'copyFileSync') {
        checkWrite(rest[0]);
        return orig.apply(this, arguments);
      }
      checkWrite(p);
      // renameSync(src, dest)：两处都是写操作，都要检查
      if (name === 'renameSync') checkWrite(rest[0]);
      return orig.apply(this, arguments);
    };
  }

  for (const name of ['writeFile', 'appendFile', 'mkdir', 'open',
                      'rm', 'unlink', 'rename', 'copyFile']) {
    const orig = fs[name];
    if (typeof orig !== 'function') continue;
    fs[name] = function (p, ...rest) {
      try {
        if (name === 'open') {
          const flags = rest[0];
          if (typeof flags === 'string' && !WRITE_FLAGS.test(flags)) {
            return orig.apply(this, arguments);
          }
        }
        // copyFile(src, dest)：只查目标
        if (name === 'copyFile') {
          checkWrite(rest[0]);
        } else {
          checkWrite(p);
          if (name === 'rename') checkWrite(rest[0]);
        }
      } catch (e) {
        const cb = rest.find((x) => typeof x === 'function');
        if (cb) return cb(e);
        throw e;
      }
      return orig.apply(this, arguments);
    };
  }
} catch { /* fs 不可用时跳过 */ }

// 暴露给被测脚本自查
process.__SANDBOX_GUARD__ = { violations, allowCommandExec: ALLOW_COMMAND_EXEC };
