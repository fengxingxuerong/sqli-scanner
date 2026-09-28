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
//   ② 仓库根 package.json（产品版本；一份代码双形态，根版本才是用户看到的版本）
//   ③ server/package.json（引擎独立发布时的兜底）
//   ④ '0.0.0+unknown'（宁可如实报"不知道"，也不复现"报一个不存在的版本"）
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

export const ENGINE_VERSION =
  String(process.env.ENGINE_VERSION || '').trim() ||
  readJsonVersion('../../../package.json') ||
  readJsonVersion('../../package.json') ||
  '0.0.0+unknown';

/** 版本来源（排障用：部署包里读到的是构建期内联值，来源标注能区分注入/仓库/server 三种情况） */
export const VERSION_SOURCE = String(process.env.ENGINE_VERSION || '').trim()
  ? 'env:ENGINE_VERSION'
  : readJsonVersion('../../../package.json')
    ? 'package.json(root)'
    : readJsonVersion('../../package.json')
      ? 'package.json(server)'
      : 'unknown';

export default ENGINE_VERSION;
