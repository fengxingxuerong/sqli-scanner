// ============================================================================
// version.js —— 引擎版本的单一事实源
//
// 为什么单独成模块：/api/health 曾把 '1.0.0' 字面量写死在路由里，而 package.json
// 早已是 1.1.0（2026-09-28 接口靶场实测）。写死的字面量不会自己过期，只会让运维
// 拿着一个不存在的版本去排障；更糟的是 server/tests/engine.e2e.test.js 把这个
// 过期字面量**断言**成了契约，于是每次升版都会红一条"看起来像产品坏了"的用例。
//
// 取值顺序：
//   ① ENGINE_VERSION（构建/部署显式注入，优先级最高）
//   ② SEA 内嵌 package.json（D128：sidecar 把版本**随包带走**，装到用户机器上不再依赖文件系统）
//   ③ 仓库根 package.json（产品版本；一份代码双形态，根版本才是用户看到的版本）
//   ④ server/package.json（引擎独立发布时的兜底）
//   ⑤ '0.0.0+unknown'（宁可如实报"不知道"，也不复现"报一个不存在的版本"）
//
// [D128 背景] 旧实现只有 ①③④：sidecar 是 SEA 单文件，运行时向上找 package.json——
// 开发树上跑能读到 1.1.1，装到用户机器（exe 旁边没有仓库）就报 `0.0.0+unknown`。
// 即"开发环境永远复现不出来的版本谎报"。修法是把版本作为 SEA asset 内嵌（②），
// 并在构建期用冒烟断言 exe 自报版本 == package.json 版本。
// JSON 用 createRequire 静态 require：Node ESM 直跑时被内联，esbuild 打包
// dist-engine 时同样在构建期解析（避免打包后读不到文件而静默降级）。
// ============================================================================
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

function readJsonVersion(spec) {
  try {
    const v = require(spec)?.version;
    return typeof v === 'string' && v.trim() ? v.trim() : '';
  } catch {
    return '';
  }
}

/**
 * 版本解析器（纯函数，可注入四条来源，便于单测覆盖「装到用户机器上」的路径）。
 * @param {{ envVersion?: string, seaVersion?: string, rootPkgVersion?: string, serverPkgVersion?: string }} [src] 四条来源
 * @returns {{ version: string, source: string }} 版本与来源标注（来源用于排障，不进报告结论）
 */
export function resolveVersion(src = {}) {
  const env = String(src.envVersion ?? '').trim();
  if (env) return { version: env, source: 'env:ENGINE_VERSION' };
  const sea = String(src.seaVersion ?? '').trim();
  if (sea) return { version: sea, source: 'sea:package.json' };
  const root = String(src.rootPkgVersion ?? '').trim();
  if (root) return { version: root, source: 'package.json(root)' };
  const server = String(src.serverPkgVersion ?? '').trim();
  if (server) return { version: server, source: 'package.json(server)' };
  return { version: '0.0.0+unknown', source: 'unknown' };
}

/**
 * 读取 SEA 内嵌的 package.json 版本（非 SEA 运行时/未内嵌时返回空串，绝不抛）。
 * @returns {string} 内嵌版本号；读不到时为空串
 */
function readSeaVersion() {
  try {
    const sea = require('node:sea');
    if (typeof sea.isSea !== 'function' || !sea.isSea()) return '';
    if (typeof sea.getAsset !== 'function') return '';
    const raw = sea.getAsset('package.json', 'utf8');
    const v = JSON.parse(raw)?.version;
    return typeof v === 'string' ? v : '';
  } catch {
    return '';
  }
}

const RESOLVED = resolveVersion({
  envVersion: process.env.ENGINE_VERSION,
  seaVersion: readSeaVersion(),
  rootPkgVersion: readJsonVersion('../../../package.json'),
  serverPkgVersion: readJsonVersion('../../package.json'),
});

export const ENGINE_VERSION = RESOLVED.version;

/** 版本来源（排障用：部署包里读到的是内嵌/注入值，来源标注能区分 env / SEA / 仓库 / server 四种情况） */
export const VERSION_SOURCE = RESOLVED.source;

export default ENGINE_VERSION;
