// ============================================================================
// configNested.cliDefaults.test.js —— CLI 侧嵌套配置组的「带底完整性」守卫
// ============================================================================
// 与 tests/configWhitelist.passthrough.test.js（REST 侧）成对：
//   REST 的入口是 sanitizeStart（逐组带底重建），CLI 的入口是 bin/cli/config.js 的
//   buildConfig —— 两条路都**不经过**对方，而引擎只做浅合并（models.js:90/113
//   `{...defaults, ...input.config}`）。所以「组内少一个子键」这个缺陷必须在**两个入口**
//   各钉一遍，只修 REST 那一半等于没修（本轮就是这种情况：sanitizeStart 已带底，
//   而 `--tamper` 仍然产出只含 tamper 一个键的 wafEvasion）。
//
// 实测后果（不是理论）：scan/detect.js:398 的判据是 `wafEvasion.filterAdaptive === true`，
// defaults 里它是 true（关键词「静默过滤」型靶场实测由 [error] 提到 [error,boolean]）。
// `--tamper space2comment` 旧写法让它在引擎侧变成 undefined ⇒ 自适应重跑那一轮**静默消失**，
// 扫描照常跑完、照常报绿。二阶侧同理：negativeControl / refreshCsrf 变成 undefined。
//
// 判据两层：
//   ① 行为层：逐条真实调 buildConfig，断目标组**每个 defaults 子键都有值**（不只是"组在"）；
//   ② 结构层：源码里不得再出现 `config.<组> = { ... }` 的直接整体赋值 —— 建组只能走
//      patchGroup/patchTamper，否则新增旋钮时又开一条无人看守的断口。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildConfig } from '../bin/cli/config.js';
import { defaults as D } from '../src/config/defaults.js';

const CLI_SRC = readFileSync(new URL('../bin/cli/config.js', import.meta.url), 'utf8');
const NESTED_GROUPS = ['wafEvasion', 'secondOrder', 'oob', 'blindRobust', 'noSql'];

/** 一个组的「完整性」断言：defaults 的每个子键都必须有值，且用户意图键不被带底覆盖 */
function assertGroupComplete(label, config, group, expectedOverrides = {}) {
  const g = config[group];
  assert.ok(g && typeof g === 'object', `${label}：config.${group} 整体没有建立`);
  for (const k of Object.keys(D[group])) {
    assert.notEqual(
      g[k],
      undefined,
      `${label}：${group}.${k} 在引擎侧是 undefined（浅合并下 defaults 的值已被整组替换掉）`
    );
  }
  for (const [k, v] of Object.entries(expectedOverrides)) {
    assert.deepEqual(g[k], v, `${label}：${group}.${k} 未体现用户显式表达的意图`);
  }
}

test('CLI --tamper：wafEvasion 必须带全 defaults（filterAdaptive 是 `=== true` 判据）', () => {
  const c = buildConfig({ u: 'http://t/', tamper: 'space2comment', tamperResolved: ['space2comment'] });
  assertGroupComplete('--tamper', c, 'wafEvasion', {
    filterAdaptive: D.wafEvasion.filterAdaptive,
    adaptiveOnBlock: D.wafEvasion.adaptiveOnBlock,
    bypassSearch: D.wafEvasion.bypassSearch,
    tamper: { ...D.wafEvasion.tamper, enabled: true, plugins: ['space2comment'] },
  });
});

test('CLI --delay / --mobile / --random-agent：单键开关不得清空同组其余子键', () => {
  assertGroupComplete('--delay', buildConfig({ u: 'http://t/', delay: 2 }), 'wafEvasion', {
    jitterMs: 2,
    filterAdaptive: true,
  });
  // randomUA 是字符串窄形态（httpClient.js:836 按 'mobile' 只取移动池），带底不得把它压成布尔
  assertGroupComplete('--mobile', buildConfig({ u: 'http://t/', mobile: true }), 'wafEvasion', {
    randomUA: 'mobile',
    filterAdaptive: true,
  });
  assertGroupComplete('--random-agent', buildConfig({ u: 'http://t/', randomAgent: true }), 'wafEvasion', {
    randomUA: 'desktop',
  });
});

test('CLI 两个开关同时给：后一个的带底不得覆盖前一个已生效的值', () => {
  const c = buildConfig({ u: 'http://t/', tamper: 'x', tamperResolved: ['spaceapostrophe'], delay: 3 });
  assertGroupComplete('--tamper + --delay', c, 'wafEvasion', {
    jitterMs: 3,
    tamper: { ...D.wafEvasion.tamper, enabled: true, plugins: ['spaceapostrophe'] },
  });
});

test('CLI --second-order / --allow-second-order-writes：secondOrder 组带底（negativeControl/refreshCsrf）', () => {
  assertGroupComplete('--second-order', buildConfig({ u: 'http://t/', secondOrderUrl: 'http://t/panel' }), 'secondOrder', {
    enabled: true,
    negativeControl: true,
    refreshCsrf: true,
    triggerUrls: ['http://t/panel'],
  });
  const both = buildConfig({ u: 'http://t/', secondOrderUrl: 'http://t/panel', allowSecondOrderWrites: true });
  assertGroupComplete('--second-order + writes', both, 'secondOrder', {
    enabled: true,
    allowWrites: true,
    triggerUrls: ['http://t/panel'],
  });
});

test('结构守卫：CLI 源码里建嵌套组只能走 patchGroup/patchTamper（禁止裸整体赋值）', () => {
  const offenders = NESTED_GROUPS.filter((g) =>
    new RegExp(`config\\.${g}\\s*=\\s*\\{`).test(CLI_SRC)
  );
  assert.deepEqual(
    offenders,
    [],
    `这些组被直接整体赋值（浅合并下会清空 defaults 的同组子键）：${offenders.join(', ')} —— 改用 patchGroup`
  );
  assert.match(CLI_SRC, /function patchGroup\(/, 'patchGroup 被删了？CLI 侧的带底入口就是它');
});

test('分母守卫：defaults 里新增嵌套组必须进本清单（否则新组在 CLI 侧无人看守）', () => {
  const actual = Object.keys(D).filter((k) => D[k] && typeof D[k] === 'object' && !Array.isArray(D[k]));
  assert.deepEqual([...NESTED_GROUPS].sort(), actual.sort());
});
