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
  // [P0 2026-09-09 实战批次] 新键探针值（默认探针 1 过不了键自身校验）
  invalidValue: 'bignum',
  knownPoint: { param: 'id' },
  db: null,
  connectionString: null,
  sqlTemplate: null,
};

// 不参与本守卫的键（附理由）：
// · 直连模式专用：走 sanitizeStart 的 isDirect 早退分支，HTTP 探针形态下不适用
// · 仅在其它键成立时条件写入：safeFreq 依赖 safeUrl（已在 PROBE 里成对给出，故不豁免）
const EXEMPT = new Set(['db', 'connectionString', 'sqlTemplate', 'mode', 'safeFreq']);
// safeFreq 豁免理由：条件写入——仅当同时配置了合法 safeUrl 才透传（单独探测必抱不到）。

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
