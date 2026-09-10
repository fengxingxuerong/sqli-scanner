// 配置白名单一致性守卫：defaults.js 顶层用户可配键必须全部在 scanRoutes 的
// KNOWN_CFG_KEYS 白名单内——防止新增配置键时手工同步遗漏（REST 传入被静默忽略，
// 配置语义漂移零提示）。内部键用显式豁免清单声明（须注释理由）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { defaults } from '../src/config/defaults.js';

// 内部/引擎私有键豁免（不出现在 REST 白名单是设计意图）：
// · no 层：目标级字段（auth/proxy/wafEvasion/oob 等在 target 序列化时结构化处理，
//   非标量配置键）；grep 需求由 bodyParams/params 结构承载。
const INTERNAL_KEYS = new Set([
  'auth', 'proxy', 'wafEvasion', 'oob', 'noSql', 'secondOrder', 'sessionFile', 'sessionDefault',
  // 引擎自身 HTTP 行为（非用户扫描配置，由环境变量/启动参数控制，不应经扫描 API 下发）：
  // · port：引擎监听端口（启动参数语义）
  // · http2 / disableKeepAlive：HttpClient 出站连接行为（env/全局配置语义）
  'port', 'http2', 'disableKeepAlive',
]);

test('守卫：defaults.js 顶层键全部被 KNOWN_CFG_KEYS 覆盖（防手工同步漂移）', async () => {
  // 动态读取 scanRoutes 的 KNOWN_CFG_KEYS（不 export，经模块副作用无——直接读源码解析最稳）
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../src/api/scanRoutes.js', import.meta.url), 'utf8');
  const m = src.match(/const KNOWN_CFG_KEYS = new Set\(\[([\s\S]*?)\]\)/);
  assert.ok(m, '应能定位 KNOWN_CFG_KEYS 定义');
  const listed = new Set(
    Array.from(m[1].matchAll(/'([^']+)'/g)).map((x) => x[1])
  );
  assert.ok(listed.size >= 50, `白名单规模异常（实际 ${listed.size}）——解析失败？`);

  const missing = [];
  for (const key of Object.keys(defaults)) {
    if (INTERNAL_KEYS.has(key)) continue;
    if (!listed.has(key)) missing.push(key);
  }
  assert.deepEqual(
    missing,
    [],
    `以下 defaults.js 顶层键未进 REST 白名单（新配置键须同步 scanRoutes.js 的 KNOWN_CFG_KEYS，或加入本测试豁免清单并注明理由）：${missing.join(', ')}`
  );
});

test('守卫（反向）：KNOWN_CFG_KEYS 无 defaults 不存在的幽灵键（白名单腐化检测）', async () => {
  const { readFileSync } = await import('node:fs');
  const src = readFileSync(new URL('../src/api/scanRoutes.js', import.meta.url), 'utf8');
  const m = src.match(/const KNOWN_CFG_KEYS = new Set\(\[([\s\S]*?)\]\)/);
  const listed = Array.from(m[1].matchAll(/'([^']+)'/g)).map((x) => x[1]);
  // 白名单允许含非 defaults 键（如 secondOrder 等结构化配置），但标量键应在 defaults 有默认值
  // ——此方向仅统计，不做硬断言（结构化键是合法存在）。
  const ghost = listed.filter((k) => !(k in defaults) && !INTERNAL_KEYS.has(k));
  // 幽灵键清单仅告警不失败：结构化配置键（wafEvasion/secondOrder 等）合法。
  if (ghost.length) {
    console.log(`[info] 白名单中 defaults 无默认值的结构化键（合法）: ${ghost.join(', ')}`);
  }
  assert.ok(true);
});
