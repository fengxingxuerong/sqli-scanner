// sql.js 加载器 —— 统一三种运行形态下的 sql.js / wasm 定位。
//
// 为什么需要这一层（2026-09-18 B1 实测结论，勿凭直觉改）：
//   引擎有三种分发形态，sql.js 的可见性各不相同：
//     1) 源码直跑（dev / 单测 / e2e）：`server/node_modules/sql.js` 在标准解析链上，
//        直接 `import('sql.js')` 即可，wasm 由 sql.js 自己按 __dirname 找到。
//     2) dist-engine 目录包：`engine.mjs` + `node_modules/sql.js` 同目录，esbuild 把它
//        标成 external，运行时按 cwd 逐级向上解析 → 也能直接 import。
//     3) **SEA 单文件（桌面 sidecar）**：`require/import` 被 SEA 劫持为"只认内建模块"，
//        访问 `sql.js` 会抛 `No such built-in module: sql.js`；`NODE_PATH` 同样无效
//        （SEA 的模块解析不查 NODE_PATH）。因此必须在打包期把 sql-wasm.js **内联**进
//        bundle（esbuild 不再标 external），并把 sql-wasm.wasm 作为 SEA asset 内嵌，
//        运行时用 `node:sea` 的 getAsset 取出、经 `initSqlJs({ wasmBinary })` 直喂。
//
// 关键 API 依据（读 sql.js@1.14.1 dist/sql-wasm.js 源码核实）：
//   源码内有 `k.wasmBinary && (Ea = k.wasmBinary)`，且取 wasm 前有 `if (!Ea && ...)`
//   → 只要传了 wasmBinary，就**完全跳过** `__dirname + readFileSync` 那条路。
//   这是官方支持的绕行口，无需 monkey-patch fs / __dirname。

import { createRequire } from 'node:module';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { logger } from './logger.js';

/** SEA 内嵌 wasm 的 asset key（须与 sea-config.json 的 assets 键一致） */
export const SQL_WASM_ASSET = 'sql-wasm.wasm';

let _cachedInit = null;

/**
 * 判断当前进程是否是 SEA（单文件可执行）形态。
 * `node:sea` 模块只在 SEA 内存在，用 require 探测最可靠（import 会静态报错）。
 * @returns {boolean}
 */
export function isSeaRuntime() {
  try {
    const req = createRequire(import.meta.url);
    const sea = req('node:sea');
    return typeof sea?.isSea === 'function' ? !!sea.isSea() : false;
  } catch {
    return false;
  }
}

/**
 * 取 SEA 内嵌的 wasm 字节；非 SEA 或未内嵌时返回 null。
 * @returns {Buffer|ArrayBuffer|null}
 */
export function readWasmAsset() {
  if (!isSeaRuntime()) return null;
  try {
    const req = createRequire(import.meta.url);
    const sea = req('node:sea');
    if (typeof sea.getAsset !== 'function') return null;
    const buf = sea.getAsset(SQL_WASM_ASSET); // 默认返回 ArrayBuffer
    if (!buf || buf.byteLength === 0) {
      logger.warn(`[direct] SEA 内嵌 asset ${SQL_WASM_ASSET} 为空，回退磁盘查找`);
      return null;
    }
    return buf;
  } catch (e) {
    // 未在 sea-config 的 assets 里声明该键时会抛；记 warn 但不致命（还能走磁盘路径）
    logger.warn(`[direct] 读取 SEA asset ${SQL_WASM_ASSET} 失败：${e && e.message}`);
    return null;
  }
}

/**
 * 解析磁盘上的 sql-wasm.wasm 路径（非 SEA 场景的兜底）。
 * 查找顺序：SCAN_SQLJS_WASM 显式指定 → 模块同目录 → cwd 下 dist-engine/node_modules。
 * @returns {string|null}
 */
export function resolveWasmPath() {
  const explicit = String(process.env.SCAN_SQLJS_WASM || '').trim();
  if (explicit && existsSync(explicit)) return explicit;

  const candidates = [
    // dist-engine 目录包：engine 与 node_modules 同级
    path.join(process.cwd(), 'node_modules', 'sql.js', 'dist', SQL_WASM_ASSET),
    // 从 exe / 模块所在目录旁找（Tauri 若把 sidecar 与依赖放同目录）
    path.join(path.dirname(process.execPath), 'node_modules', 'sql.js', 'dist', SQL_WASM_ASSET),
    path.join(path.dirname(process.execPath), 'engine-deps', 'node_modules', 'sql.js', 'dist', SQL_WASM_ASSET),
  ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return null;
}

/**
 * 加载并初始化 sql.js，返回 SQL 命名空间（含 Database 构造器）。
 * 三种形态自适应：SEA 走内嵌 wasm；其余走 sql.js 自带解析。
 * @returns {Promise<object>} 已初始化的 sql.js 模块
 */
export async function loadSqlJs() {
  if (_cachedInit) return _cachedInit;
  _cachedInit = (async () => {
    const mod = await import('sql.js');
    const initSqlJs = mod.default || mod;
    if (typeof initSqlJs !== 'function') {
      throw new Error('sql.js 导出形态异常：initSqlJs 不是函数');
    }

    // 优先内嵌 asset（SEA 唯一可行路径，也让非 SEA 少一次磁盘 IO）
    const wasmBinary = readWasmAsset();
    if (wasmBinary) {
      logger.debug('[direct] sql.js 使用 SEA 内嵌 wasm');
      return initSqlJs({ wasmBinary });
    }

    // 非 SEA：先用磁盘显式路径（覆盖 cwd 不在 dist-engine 的场景），找不到就交给 sql.js 自身解析
    const wasmPath = resolveWasmPath();
    if (wasmPath) {
      logger.debug(`[direct] sql.js 使用磁盘 wasm：${wasmPath}`);
      return initSqlJs({ locateFile: () => wasmPath });
    }

    logger.debug('[direct] sql.js 使用默认 wasm 定位（模块同目录）');
    return initSqlJs();
  })();

  try {
    return await _cachedInit;
  } catch (e) {
    _cachedInit = null; // 失败不缓存，允许调用方重试（如用户补上依赖后）
    throw e;
  }
}

/** 仅供测试：清空初始化缓存 */
export function _resetSqlJsCacheForTest() {
  _cachedInit = null;
}
