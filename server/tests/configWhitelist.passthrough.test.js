// ============================================================================
// tests/configWhitelist.passthrough.test.js —— 「白名单有、透传没有」守卫
// [P0-ENG 2026-09-08]
//
// 为什么需要：本仓已三次踩同一坑——引擎侧把能力实现完、键名也加进了 KNOWN_CFG_KEYS，
// 但 sanitizeStart 里忘了写透传（或被并发编辑吃掉），结果 REST/CLI 传入被静默丢弃，
// 表现为「UI 有开关、引擎有实现、中间断了一截」，而既有守卫只检查 defaults→白名单方向，
// 查不出这一类。典型例子：insecureTls（自签证书目标）曾经只能靠改 defaults/env 生效。
//
// 做法：对白名单里每个键，用「该键能被 sanitizeStart 接受的最小合法值」调一次，
// 断言 sanitized.config 里出现了这个键。探不到值的键走显式豁免清单（须注明理由）。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { sanitizeStart } from '../src/api/scanRoutes.js';
import { defaults as D } from '../src/config/defaults.js';

const src = readFileSync(new URL('../src/api/scanRoutes.js', import.meta.url), 'utf8');
const m = src.match(/const KNOWN_CFG_KEYS = new Set\(\[([\s\S]*?)\]\)/);
assert.ok(m, '应能定位 KNOWN_CFG_KEYS 定义');
const WHITELIST = Array.from(new Set(Array.from(m[1].matchAll(/'([^']+)'/g)).map((x) => x[1])));

// 探针值：必须能通过该键自身的 clamp/校验，否则测不到「透传是否存在」
const PROBE = {
  techniques: ['error'],
  auth: { basic: { username: 'u', password: 'p' } },
  proxy: 'http://127.0.0.1:8080',
  wafEvasion: { randomUA: true },
  oob: { enabled: false },
  noSql: { enabled: false },
  secondOrder: { enabled: false },
  blindRobust: { enabled: true },
  dbms: 'MySQL',
  matchCode: true,
  matchString: 'ok',
  notString: 'no',
  matchRegexp: 'a',
  trueRegexp: 'a',
  falseRegexp: 'b',
  prefix: 'p',
  suffix: 's',
  sessionFile: 'sqli-session-test.json',
  scope: ['example.com'],
  testFilter: 'x',
  testSkip: 'y',
  ssrfViaProxy: 'auto',
  safeUrl: 'http://ping.example.com/health',
  safeFreq: 5,
  // [批次 5 补遗 2026-09-14] CSRF / skip 探针值（默认探针 1 过不了键自身校验）
  csrfUrl: 'http://auth.example.com/login',
  csrfTokenName: 'csrf_token',
  csrfMethod: 'GET',
  csrfRefreshFreq: 30,
  skipParams: ['debug', 'logout'],
  // [P0 2026-09-09 实战批次] 新键探针值（默认探针 1 过不了键自身校验）
  invalidValue: 'bignum',
  knownPoint: { param: 'id' },
  // [CFG-REACH 2026-09-20] paramDel 的探针值：默认探针 1 过不了校验是**正确行为**——
  // 该键会直接参与请求 URL 的 split/join，所以只收 ; , | ^ ~ 这 5 个单字符
  // （见 scanRoutes 的 PARAM_DEL_ALLOWED）。这里给合法值，是为了测「透传在不在」，
  // 而不是放宽校验；校验本身的负例在 configReachability.guard.test.js。
  paramDel: ';',
  // hex / flushSession 走 bespoke 严格布尔分支（引擎按 config.hex === true 判定，
  // 通用透传放过 1/"true" 会变成"收了不生效"）——默认探针 1 被拒是**正确行为**。
  hex: true,
  flushSession: true,
  // [2026-09-23 E2] extractScope 的探针值：默认探针 1 过不了校验是**正确行为**——
  // 它是枚举/拖库动作族的配置对象，mode 必须在 18 个白名单值内（引擎 switch 的判据），
  // 形状校验见 scanRoutes 的 sanitizeExtractScope。这里给最小合法值，测「透传在不在」。
  extractScope: { mode: 'dbs' },
  db: null,
  connectionString: null,
  sqlTemplate: null,
};

// 不参与本守卫的键（附理由）：
// · 直连模式专用：走 sanitizeStart 的 isDirect 早退分支，HTTP 探针形态下不适用
// · 仅在其它键成立时条件写入：safeFreq 依赖 safeUrl（已在 PROBE 里成对给出，故不豁免）
const EXEMPT = new Set(['db', 'connectionString', 'sqlTemplate', 'mode', 'safeFreq',
  'csrfTokenName', 'csrfMethod', 'csrfRefreshFreq']);
// safeFreq 豁免理由：条件写入——仅当同时配置了合法 safeUrl 才透传（单独探测必抱不到）。
// [批次 5 补遗 2026-09-14] csrfTokenName/csrfMethod/csrfRefreshFreq 同款豁免：条件写入——
// 仅当同时配置了合法 csrfUrl 才透传（成对守卫见下方 CSRF 成对测试）。

test('守卫：KNOWN_CFG_KEYS 每个键都要在 sanitizeStart 有透传（防「白名单有、引擎收不到」）', () => {
  const missing = [];
  for (const key of WHITELIST) {
    if (EXEMPT.has(key)) continue;
    const probe = key in PROBE ? PROBE[key] : 1;
    let out = null;
    try {
      out = sanitizeStart({ target: { url: 'http://shop.example.com/item?id=1' }, config: { [key]: probe } });
    } catch (e) {
      missing.push(`${key}（sanitizeStart 直接抛错：${e.message}）`);
      continue;
    }
    if (!out || !out.config || !(key in out.config)) missing.push(key);
  }
  assert.deepEqual(
    missing,
    [],
    `以下白名单键在 sanitizeStart 中无透传（新增配置键必须三处同步：defaults → KNOWN_CFG_KEYS → 透传）：${missing.join(', ')}`
  );
});

test('守卫（条件键配对）：safeFreq 随 safeUrl 一起下发时必须透传', () => {
  const out = sanitizeStart({
    target: { url: 'http://shop.example.com/item?id=1' },
    config: { safeUrl: PROBE.safeUrl, safeFreq: PROBE.safeFreq },
  });
  assert.equal(out.config.safeUrl, PROBE.safeUrl);
  assert.equal(out.config.safeFreq, PROBE.safeFreq);
});

// [批次 5 补遗 2026-09-14] CSRF 条件键成对守卫：csrfTokenName/csrfMethod/csrfRefreshFreq
// 随合法 csrfUrl 一起下发时必须透传（单独探测因条件写入拿不到，见 EXEMPT 豁免理由）。
test('守卫（条件键配对）：CSRF 三键随 csrfUrl 一起下发时必须透传', () => {
  const out = sanitizeStart({
    target: { url: 'http://shop.example.com/item?id=1' },
    config: {
      csrfUrl: PROBE.csrfUrl, csrfTokenName: PROBE.csrfTokenName,
      csrfMethod: PROBE.csrfMethod, csrfRefreshFreq: PROBE.csrfRefreshFreq,
    },
  });
  assert.equal(out.config.csrfUrl, PROBE.csrfUrl);
  assert.equal(out.config.csrfTokenName, PROBE.csrfTokenName);
  assert.equal(out.config.csrfMethod, PROBE.csrfMethod);
  assert.equal(out.config.csrfRefreshFreq, PROBE.csrfRefreshFreq);
});

test('守卫（反向）：非白名单键不得进入 config（含嵌套对象内的多余键）', () => {
  const out = sanitizeStart({
    target: { url: 'http://shop.example.com/item?id=1' },
    config: { evilKey: 'x', __proto__: { polluted: 1 }, oob: { enabled: false, evilNested: 'y' } },
  });
  assert.equal('evilKey' in out.config, false, '未进白名单的键必须被丢弃');
  assert.equal((out.config.oob && out.config.oob.evilNested) === undefined, true, '结构化键只取已知子字段');
  // 兼顶：不能因为带底透传循环而把原型链上的键也复制进来
  assert.equal(out.config.polluted, undefined);
});

// ── 嵌套组的「带底完整性」──────────────────────────────────────────────────
// 上面的探针只查**顶层**键在不在，查不到组内的断口：models.js:113 的 config 合并是
// 浅合并（{...defaults, ...input.config}），所以只要请求体里出现了某个嵌套组，
// 该组就**整体替换**掉 defaults 的同名对象 —— sanitizeStart 少转发一个子键，
// 引擎侧看到的就是 undefined，而不是 defaults 里写的那个值。
//
// 这条不是理论问题：wafEvasion 曾只转发 randomUA/obfuscate/jitterMs/tamper 四键，
// 而 defaults.wafEvasion 有 9 键；引擎侧 filterAdaptive 的判据是 `=== true`（默认开，
// 实测把关键词过滤靶场从 [error] 提到 [error,boolean]）。UI 的 tamper 编辑器与 CLI 的
// --tamper 发的正是「只带 tamper 的 wafEvasion」→ 自适应过滤重跑被静默关掉，
// 扫描照常报绿，只是少一整轮绕过。
//
// 判据写成数据驱动的：**以 defaults 的键集为准**，只发组内第一个子键，
// 断言其余子键全部带着 defaults 的值落地 —— 新增嵌套组或新增子键都自动纳入。
const NESTED_GROUPS = ['wafEvasion', 'oob', 'secondOrder', 'blindRobust'];

test('守卫（嵌套组带底完整性）：只发组内一个子键时，其余子键必须带 defaults 值落地', () => {
  // 先钉住分母：defaults 里新增嵌套组却不进本清单，等于又开一条无人看守的断口
  const actual = Object.keys(D).filter((k) => D[k] && typeof D[k] === 'object' && !Array.isArray(D[k]));
  assert.deepEqual([...NESTED_GROUPS].sort(), actual.sort(), 'NESTED_GROUPS 必须覆盖 defaults 里的全部嵌套组');
  for (const group of NESTED_GROUPS) {
    const def = D[group];
    assert.ok(def && typeof def === 'object', `defaults.${group} 不存在或不是对象`);
    const keys = Object.keys(def);
    const sent = keys[0];
    const out = sanitizeStart({
      target: { url: 'http://shop.example.com/item?id=1' },
      config: { [group]: { [sent]: structuredClone(def[sent]) } },
    });
    const got = out.config[group];
    assert.ok(got && typeof got === 'object', `${group} 整体没有被透传`);
    for (const k of keys) {
      // 断的是**等于 defaults**，不是"键存在"：`!== false` 型判据下 undefined 与默认开
      // 恰好同值，只查"存在"会放过一整类缺陷（extractVerify 就是这么溜过去的）。
      assert.deepEqual(
        got[k],
        def[k],
        `${group}.${k} 没有带着 defaults 的值落地（拿到 ${JSON.stringify(got[k])}，期望 ${JSON.stringify(def[k])}）：` +
          '浅合并下引擎侧看到的将是 undefined 或别的值'
      );
    }
  }
});

// 同一条断言的反向半边：只查"未传时等于 defaults"会漏掉另一半 ——
// 带底逻辑（`{...defaults}` 打底再覆盖）如果写反了覆盖顺序，或者某个子键压根没进转发清单，
// 用户**显式发出来的**非默认值就会被 defaults 吃掉，而"未传"那条测试永远是绿的。
// 这里逐键发一个"与 defaults 不同"的值，断它没被换回 defaults。
// 数值键只断"不等于 defaults"而不断"等于我发的值"：clamp 区间是有意的（z 上限 5、
// 一致率上限 1），发 def+1 落在区间外属于合法归一，不该由本守卫裁定。
const EXPLICIT_ALT = {
  // 形状敏感的字符串键：defaults 值本身是空串/占位，通用 `def + '_alt'` 会被各自的
  // 协议白名单拒掉（那不是缺陷），故逐键给一个**合法且不同**的值。
  'secondOrder.secondUrl': 'http://shop.example.com/read-back',
  'secondOrder.secondMethod': 'POST',
  'secondOrder.triggerMethod': 'POST',
  'secondOrder.secondData': { id: 7 },
  'oob.callbackBase': 'oob.example.com:9100',
  'oob.dnsDomain': 'dns.example.com',
  'wafEvasion.tamper': { enabled: true, plugins: ['spacev2'], intensity: 'high' },
};

function altFor(group, key, def) {
  const custom = EXPLICIT_ALT[`${group}.${key}`];
  if (custom !== undefined) return custom;
  if (typeof def === 'boolean') return !def;
  if (typeof def === 'number') return def + 1;
  if (typeof def === 'string') return `${def || 'x'}_alt`;
  if (Array.isArray(def)) return ['http://shop.example.com/trigger-1'];
  return { alt: true };
}

test('守卫（嵌套组显式值不被带底吃掉）：逐键发非默认值，必须不等于 defaults', () => {
  for (const group of NESTED_GROUPS) {
    const def = D[group];
    for (const k of Object.keys(def)) {
      const alt = altFor(group, k, def[k]);
      const out = sanitizeStart({
        target: { url: 'http://shop.example.com/item?id=1' },
        config: { [group]: { [k]: structuredClone(alt) } },
      });
      const got = out.config?.[group]?.[k];
      assert.notDeepEqual(
        got,
        def[k],
        `${group}.${k}：显式发了 ${JSON.stringify(alt)}，落地却仍是 defaults 的 ${JSON.stringify(def[k])} —— ` +
          '该子键没进 sanitizeStart 的转发清单（或被带底覆盖），调用方的意图被静默丢弃'
      );
    }
  }
});

test('守卫（嵌套组带底完整性）：wafEvasion 的关键布尔位必须等于 defaults，不是仅"存在"', () => {
  const out = sanitizeStart({
    target: { url: 'http://shop.example.com/item?id=1' },
    config: { wafEvasion: { tamper: { enabled: true, plugins: ['spacev2'] } } },
  });
  const we = out.config.wafEvasion;
  // filterAdaptive 是 `=== true` 判据（关掉就等于少一整轮绕过），必须严格等于 defaults
  assert.equal(we.filterAdaptive, D.wafEvasion.filterAdaptive);
  assert.equal(we.adaptiveOnBlock, D.wafEvasion.adaptiveOnBlock);
  assert.equal(we.bypassSearch, D.wafEvasion.bypassSearch);
  assert.equal(we.autoRetry, D.wafEvasion.autoRetry);
  // 用户显式表达的值不得被带底覆盖
  assert.equal(we.tamper.enabled, true);
  assert.deepEqual(we.tamper.plugins, ['spacev2']);
  const off = sanitizeStart({
    target: { url: 'http://shop.example.com/item?id=1' },
    config: { wafEvasion: { filterAdaptive: false, tamper: { enabled: true } } },
  });
  assert.equal(off.config.wafEvasion.filterAdaptive, false, '显式 false 必须赢过 defaults 的 true');
});

test('守卫（嵌套组带底完整性·反向）：带底不得变成「用户没发的键也能被塞进来」', () => {
  const out = sanitizeStart({
    target: { url: 'http://shop.example.com/item?id=1' },
    config: { wafEvasion: { evilNested: 'y', __proto__: { polluted: 1 }, tamper: { evil: 'z' } } },
  });
  const we = out.config.wafEvasion;
  assert.equal(we.evilNested, undefined, '未知子键必须丢弃');
  assert.equal(we.polluted, undefined, '原型污染键不得进入');
  assert.equal(we.tamper.evil, undefined, 'tamper 的未知子键必须丢弃');
  assert.equal(we.randomUA, D.wafEvasion.randomUA, '未发的子键取 defaults');
});
