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

test('守卫（反向）：KNOWN_CFG_KEYS 每个键都有落地方（白名单腐化检测）', async () => {
  const { readFileSync } = await import('node:fs');
  const scanRoutesSrc = readFileSync(new URL('../src/api/scanRoutes.js', import.meta.url), 'utf8');
  const m = scanRoutesSrc.match(/const KNOWN_CFG_KEYS = new Set\(\[([\s\S]*?)\]\)/);
  assert.ok(m, '解析不到 KNOWN_CFG_KEYS —— scanRoutes.js 结构变了，请同步本守卫');
  const listed = Array.from(m[1].matchAll(/'([^']+)'/g)).map((x) => x[1]);
  assert.ok(listed.length > 0, '白名单解析为空 —— 判据可能空转');

  // [2026-10-05 修正判据方向] 原判据假设"白名单里的键都应是 defaults.js 的顶层标量键"，
  // 报错时才发现那是错的：本仓配置键的**默认值与落地方分散在多处**，白名单键多数不在 defaults.js。
  // 实测分布（这才是真实落点，判据必须覆盖全部）：
  //   · defaults.js                 顶层标量（ratePerSec、boolStableDiff…）
  //   · api/scanGuard/scalarsCore.js pickInt/pickBool 的第 2 参数（dumpMaxRows、unionCols…）
  //   · api/scanGuard/bespokeKeys.js 需自定义校验的键（cookieJar、unionCols、dumpWhere、
  //     extractScope、sessionFile、dbms…）
  //   · api/scanGuard/objectGroups.js 结构化组键（wafEvasion、secondOrder…）
  //   · api/scanGuard/backfill.js    从 target 字段回填的键（testPath、testHeaders、noCast…）
  //   · INTERNAL_KEYS                不经 REST 下发的引擎私有键（豁免）
  // 所以"腐化"的正确判据是**反向**的：白名单里的键必须在上述任一处有落地方，
  // 否则它会被 KNOWN_CFG_KEYS 放行却无人消费 ⇒ 静默无效，配置语义漂移零提示。
  // 落地方有两种写法，都必须匹配到：
  //   ① 带引号：pickInt(cfg, 'dumpMaxRows', …)、boolKey 数组里写 'flushSession'
  //   ② 点号访问：if (cfg.login …)、config.rateGroup = g —— 更常见，且正则里最容易漏
  //     （本测试初版只认 ①，于是误报 7 个键：login/rateGroup/hex/flushSession 等全是 ② 型）
  const { readdirSync } = await import('node:fs');
  // 扫描范围定为**整个 api/ 目录**（不是 api/scanGuard/）：部分旋钮的落地方并不在
  //   scanGuard/ 里 —— 实测 flushSession 在 api/scanConfigTuning.js，
  //   prefilterBudgetMs / maxExtractBodyBytes / scanValidity 亦然（strictBoolKeys 那批）。
  //   只扫 scanGuard/ 会把它们全报成"无落地方"——这正是本测试连续三轮误报的直接原因。
  //
  // ⚠️ 必须**排除 scanRoutes.js 自身**：白名单的键名就写在这个文件里，
  //   若把它当语料，任何新键都能在定义处匹配到自己 ⇒ 判据恒绿、永不报错。
  //   （这正是注入验证抓到的：塞进 __ghostKeyProbe__ 后守卫仍显示通过。）
  //   "落地方"的定义是**消费**该键的代码，不是声明该键的白名单。
  const SELF = 'scanRoutes.js';
  const guardSrc = (function walk(dirUrl, depth = 0) {
    if (depth > 3) return '';
    const parts = [];
    for (const e of readdirSync(dirUrl, { withFileTypes: true })) {
      const child = new URL(e.name + (e.isDirectory() ? '/' : ''), dirUrl);
      if (e.isDirectory()) parts.push(walk(child, depth + 1));
      else if (e.name.endsWith('.js') && e.name !== SELF) parts.push(readFileSync(child, 'utf8'));
    }
    return parts.join('\n');
  })(new URL('../src/api/', import.meta.url));
  assert.ok(guardSrc.length > 1000,
    `扫到的 api/ 源码仅 ${guardSrc.length} 字节 —— 语料为空会让 hasLanding 恒假、反向守卫变成"全员孤儿"假红（或在空语料下恒真），判据不可信`);

  const hasLanding = (k) =>
    (k in defaults)
    || new RegExp(`['"\`]${k}['"\`]`).test(guardSrc)
    || new RegExp(`\\b(?:cfg|config|c)\\s*\\.\\s*${k}\\b`).test(guardSrc)
    || INTERNAL_KEYS.has(k);

  const orphans = listed.filter((k) => !hasLanding(k));
  const structured = listed.filter((k) => !(k in defaults) && INTERNAL_KEYS.has(k));
  if (structured.length) {
    console.log(`[info] 白名单中的结构化配置键（合法，已在 INTERNAL_KEYS 豁免）: ${structured.join(', ')}`);
  }
  assert.deepEqual(orphans, [],
    `以下键在 KNOWN_CFG_KEYS 里但无任何落地方（既不在 defaults.js、也不在 api/ 任何校验器、也不在 INTERNAL_KEYS 豁免）：${orphans.join(', ')}\n` +
    '后果：REST 传入该键会被 KNOWN_CFG_KEYS 放行，却没有任何代码消费它 ⇒ 静默无效，配置语义漂移零提示。');
});
