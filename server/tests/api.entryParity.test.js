// ============================================================================
// tests/api.entryParity.test.js —— 两条入口必须过同一个配置守卫
// ============================================================================
// 起因（2026-09-25）：直连模式（mode:'direct'，对标 sqlmap -d）在 sanitizeStart 里是
// **早退分支**，返回的 config 曾是 `{...defaults, ...cfg}` —— 也就是 HTTP 分支那 500+ 行
// clamp / 形状校验 / 白名单收敛**一条都没走**。实测越界值原样进引擎：
//   concurrency:9999 → 9999 路并发打库；timeoutMs:99999999；带分号的 dumpWhere（会拼进提取 SQL）
// 修法不是"在直连分支里手挑几个键 clamp"（那等于两张清单各自漂移，而漂移正是它当初被漏掉的
// 机制原因），而是整段守卫外移成 buildGuardedConfig，两条入口共用。
//
// 本文件的判据设计（为什么不止测"越界值被收敛"）：
//   ① 收敛值单独钉（否则改成"两边都漏 clamp"时，相等性断言仍绿）；
//   ② **两入口逐键相等**（防未来又出现一条 isDirect 早退）；
//   ③ 白名单之外的键**不得**进 config（旧实现是任意键透传，这条是回归的正面证据）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeStart } from '../src/api/scanRoutes.js';

const HTTP_BODY = { url: 'http://127.0.0.1:8080/item?id=1' };
const DIRECT_BODY = {
  mode: 'direct',
  db: { host: '127.0.0.1', port: 3306, driverType: 'mysql', user: 'u', password: 'p', database: 'd' },
  sqlTemplate: 'SELECT * FROM t WHERE id = {INJECT}',
  originalValue: '1',
};

// 越界 / 非法形态样本：每个键都对应 HTTP 分支上的一处真校验
const OVER = {
  concurrency: 9999, // clampInt 1..10
  timeoutMs: 99999999, // clampInt 1000..60000
  level: 99, // clampInt 1..5
  risk: 42, // clampInt 1..3
  retry: 999, // clampInt 0..5
  dumpRowLimit: 1e9, // clampInt 1..1000
  dumpWhere: '1=1; DROP TABLE users', // 含分号 → 丢弃（会原样拼进提取 SQL）
  paramDel: '<', // 不在窄集合 [;,|^~] → 丢弃
  ratePerSec: '20', // 字符串数字 → 归一成 20
};

test('直连与 HTTP 两条入口的 config 逐键相等（同一守卫的结构证据）', () => {
  const a = sanitizeStart({ ...HTTP_BODY, config: OVER }).config;
  const b = sanitizeStart({ ...DIRECT_BODY, config: OVER }).config;
  // 反向保底：若两边都空（守卫整个没跑），相等性会假绿 ⇒ 先确认它确实产出了键
  assert.ok(Object.keys(a).length > 5, `HTTP 分支只产出 ${Object.keys(a).length} 个键，守卫没跑？`);
  assert.deepEqual(Object.keys(b).sort(), Object.keys(a).sort(), '两入口落地的键集合不同');
  for (const k of Object.keys(a)) {
    assert.deepEqual(b[k], a[k], `键 ${k} 在两入口落地不同：HTTP=${JSON.stringify(a[k])} 直连=${JSON.stringify(b[k])}`);
  }
});

test('越界值在直连分支同样被收敛（不是只"两边一致"，还要"收敛到对的值"）', () => {
  const c = sanitizeStart({ ...DIRECT_BODY, config: OVER }).config;
  assert.equal(c.concurrency, 10, 'concurrency 必须夹到上限 10');
  assert.equal(c.timeoutMs, 60000, 'timeoutMs 必须夹到 60000');
  assert.equal(c.level, 5);
  assert.equal(c.risk, 3);
  assert.equal(c.retry, 5);
  assert.equal(c.dumpRowLimit, 1000);
  assert.equal(c.ratePerSec, 20, '字符串数字应归一成数字');
  assert.ok(!('dumpWhere' in c), `带分号的 dumpWhere 必须被丢弃，实际 ${JSON.stringify(c.dumpWhere)}`);
  assert.ok(!('paramDel' in c), '窄集合外的分隔符必须被丢弃');
});

test('白名单之外的任意键不得进 config（旧实现是 {...defaults, ...cfg} 原样透传）', () => {
  const junk = { notARealKnob: 1, zzz_evil: { a: 1 }, sqlmapBin: 'C:\\evil\\sqlmap.py' };
  const direct = sanitizeStart({ ...DIRECT_BODY, config: { ...junk } }).config;
  const http = sanitizeStart({ ...HTTP_BODY, config: { ...junk } }).config;
  for (const k of Object.keys(junk)) {
    assert.ok(!(k in direct), `直连 config 漏进非白名单键：${k}`);
    assert.ok(!(k in http), `HTTP config 漏进非白名单键：${k}`);
  }
});

test('直连仍要求 sqlTemplate 带 {INJECT}，且 scope 开启时对 DB 主机 fail closed（抽取后不破）', () => {
  assert.throws(
    () => sanitizeStart({ mode: 'direct', db: { host: '127.0.0.1' }, sqlTemplate: 'SELECT 1', config: {} }),
    /INJECT/
  );
  // 配了 scope 却不允许该 DB 主机 ⇒ 必须拒（这条曾是一句"无 SSRF 面"把 scope 一起免掉的洞）
  assert.throws(
    () =>
      sanitizeStart({
        ...DIRECT_BODY,
        config: { scope: ['http://authorized.example/'] },
      }),
    /授权范围|scope|SCOPE/i
  );
  // clamp 不得改变上面两条判据的存在性：带越界配置时同样要拒
  assert.throws(
    () =>
      sanitizeStart({
        ...DIRECT_BODY,
        config: { scope: ['http://authorized.example/'], concurrency: 9999 },
      }),
    /授权范围|scope|SCOPE/i
  );
});
