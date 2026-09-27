// ============================================================================
// tests/registryMode.contract.test.js —— useRegistry 必须在四个检测器上同一结论
//
// 缺陷形状（本仓反复复发的第三型）：**同一个配置键在兄弟实现里被写成不同判据**。
//   BooleanBlindDetector / ErrorDetector 判 `useRegistry === true`
//   TimeBlindDetector      判 `useRegistry !== false`   ← 反的
// ⇒ 默认配置（defaults.useRegistry=false）下，同一次扫描里 time 走声明式注册表、
//   布尔/报错走扁平数组 —— 于是 --test-filter/--test-skip/level/risk **只在一半通道生效**，
//   而调用方只看到「参数被接受」。两侧的向量集互有增减（MySQL boolean 扁平 69/注册表 49，
//   MySQL error 扁平 61/注册表 69），所以没有任何一侧是「免费的」：错不在选哪边，
//   而在两边各自选。
//
// 本文件不复制判据（照抄 `cfg.useRegistry === true` 就成了自证），而是**从可观测结果反推**
// 每个通道实际用了哪个源，再断言三者的结论一致 —— 谁将来再写出一份不同的比较，这里就红。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TimeBlindDetector } from '../src/engine/detectors/TimeBlindDetector.js';
import { ErrorDetector } from '../src/engine/detectors/ErrorDetector.js';
import { BooleanBlindDetector } from '../src/engine/detectors/BooleanBlindDetector.js';
import { selectPayloads, registryMode } from '../src/engine/payloadRegistry.js';
import { PAYLOADS } from '../src/engine/payloads.js';

const POINT = { id: 'p1', location: 'url', param: 'q', originalValue: '1' };

// 每个通道给出「本次实际用了哪个源」的观测方式：结果集合与默认档不同 ⇒ 走了注册表。
const CHANNELS = [
  {
    name: 'time',
    dbms: 'MySQL',
    technique: 'time',
    resolve: (config) => new TimeBlindDetector()._resolveTimeTemplates({ config, point: POINT }, 'MySQL'),
    asTemplates: (out) => out,
  },
  {
    name: 'error',
    dbms: 'MySQL',
    technique: 'error',
    resolve: (config) => new ErrorDetector()._resolveErrorTemplates({ config, point: POINT }, 'MySQL'),
    asTemplates: (out) => out,
  },
  {
    // 布尔通道不返回模板数组而是返回真假对；注册表对自带 entry.id，扁平索引对没有 ⇒ 可直接观测
    name: 'boolean',
    dbms: 'MySQL',
    technique: 'boolean',
    resolve: (config) =>
      new BooleanBlindDetector()._getBooleanPairs({ config, point: POINT, dbms: 'MySQL' }, PAYLOADS.MySQL.boolean),
    asTemplates: (out) => out.filter((p) => p.id).map((p) => p.id),
    registrySignal: (out) => out.some((p) => p.id),
  },
];

const keyOf = (list) => [...new Set(list.map(String))].sort().join('\u0000');

/** 该通道在这份 config 下是否读了注册表（与默认档对比，不看源码判据） */
function usedRegistry(ch, config) {
  const out = ch.resolve(config);
  if (ch.registrySignal) return ch.registrySignal(out);
  return keyOf(ch.asTemplates(out)) !== keyOf(ch.asTemplates(ch.resolve({})));
}

test('前置事实：默认档与各通道扁平源非空，且注册表/扁平两侧向量集确实不同（否则本文件是空断言）', () => {
  for (const ch of CHANNELS) {
    const flat = ch.resolve({});
    assert.ok(Array.isArray(flat) && flat.length > 0, `${ch.name} 默认档不应为空`);
    const reg = ch.resolve({ useRegistry: true });
    assert.notEqual(
      keyOf(ch.asTemplates(reg)),
      keyOf(ch.asTemplates(flat)),
      `${ch.name} 的注册表档与扁平档向量集相同 ⇒ 「反推用了哪个源」的观测失效，需换判据`
    );
  }
});

test('★契约★ 同一份 config 在 time/error/boolean 三个检测器上得到同一个注册表结论', () => {
  for (const config of [
    {}, // 缺省（defaults.useRegistry=false）
    { useRegistry: false },
    { useRegistry: true },
    { useRegistry: 'true' }, // 字符串：既不是 true 也不是 false —— 三处必须同样判否
  ]) {
    const observed = CHANNELS.map((ch) => `${ch.name}=${usedRegistry(ch, config)}`);
    const verdicts = CHANNELS.map((ch) => usedRegistry(ch, config));
    assert.equal(
      new Set(verdicts).size,
      1,
      `config=${JSON.stringify(config)} 下各通道结论分叉：${observed.join(' ')}（期望与 registryMode 一致）`
    );
    assert.equal(verdicts[0], registryMode(config), `config=${JSON.stringify(config)}：实际 ${observed.join(' ')}`);
  }
});

test('开关按下去后，testFilter 在每条通道上都真的参与筛选（不是只筛 time）', () => {
  for (const ch of CHANNELS) {
    if (ch.name === 'boolean') continue; // 布尔侧由 id 信号覆盖，filter 语义同 selectPayloads
    const filter = ch.name === 'time' ? 'benchmark' : 'extract';
    const expected = selectPayloads({ dbms: ch.dbms, technique: ch.technique, testFilter: filter }).map((e) => e.template);
    assert.ok(expected.length > 0 && expected.length < 60, `filter=${filter} 命中 ${expected.length} 条，用例不具区分度`);
    const got = ch.resolve({ useRegistry: true, testFilter: filter });
    const allowed = new Set(expected.map(String));
    const strays = got.filter((t) => !allowed.has(String(t)));
    assert.deepEqual(
      strays,
      [],
      `${ch.name} 在 useRegistry=true + testFilter=${filter} 下发出了 ${strays.length} 条未匹配 filter 的模板`
    );
  }
});

test('缺省档：三通道都不得偷偷读注册表（README/CLI 承诺 --use-registry 才切换）', () => {
  for (const ch of CHANNELS) {
    assert.equal(usedRegistry(ch, {}), false, `${ch.name} 未设 useRegistry 却读了注册表向量集`);
    assert.equal(usedRegistry(ch, { useRegistry: false }), false, `${ch.name} 显式 false 却读了注册表`);
  }
});
