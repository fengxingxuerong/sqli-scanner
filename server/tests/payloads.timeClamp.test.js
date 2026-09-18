// ============================================================================
// tests/payloads.timeClamp.test.js —— 时间/重运算向量必须有上界
// [P0-FIX 2026-09-09]
//
// 这是「我们对目标做了什么」的问题，不是检出率问题：
//   · `{SLEEP}` 无界替换 → `--time-sec 60` 让目标库每个探针睡 60 秒。乘上采样次数与并发，
//     等于把客户数据库的连接池占死几分钟；共享实例上这就是一次自伤型故障。
//   · MySQL 的 `BENCHMARK({SLEEP}0000000, MD5(1))` 是**字符串拼接**：sleep=60 → 六千万次
//     MD5，CPU 直接打满。
// 收口点选在渲染层（fillPayload）而不是逐条改模板：逐条改必然漏，漏一条就等于没做。
//
// 零回归红线：sleep=1（指纹默认）与 sleep=2（历史默认）的输出必须逐字不变 ——
// 因此 BENCHMARK 的上限取的就是「今天默认配置的产物」，只拦用户显式调大后的失控值。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  fillPayload,
  clampTimeVars,
  capHeavyFunctions,
  TIME_VECTORS,
  TIME_SLEEP_MIN_SEC,
  TIME_SLEEP_MAX_SEC,
  BENCHMARK_MAX_ITER,
} from '../src/engine/payloads/index.js';
import { PAYLOADS } from '../src/engine/payloads.js';

/**
 * 改动前的渲染实现（逐字搬过来当对照）：用它证明「默认配置零回归」，而不是靠一份快照文件
 * 自证——快照是改完后生成的话，只能防住以后的改动，防不住本次改动本身。
 */
function legacyFill(template, vars = {}) {
  return template
    .replaceAll('{ORIG}', vars.orig ?? '')
    // [CTX-FIX 2026-09-18] TIME_VECTORS 新增 {BD}（闭合前缀）占位符；本对照实现按「未提供 bd」
    // 渲染成空串，与 fillPayload 一致 —— 本测试钉的是「sleep/重运算的上界没变」，不是占位符集合。
    .replaceAll('{BD}', vars.bd ?? '')
    .replaceAll('{SLEEP}', String(vars.sleep ?? 1))
    .replaceAll('{NUM}', '7777') // 随机项固定化，两边一致即可比较
    .replaceAll('{SEP}', vars.sep ?? '-- -');
}

test('零回归：默认 sleep（1=指纹、2=检测）的输出与改动前逐字一致', () => {
  const cases = [
    ...TIME_VECTORS.map((v) => v.payload),
    ...PAYLOADS.MySQL.time,
    ...PAYLOADS.MySQL.error.slice(0, 8),
    ...PAYLOADS.PostgreSQL.time,
  ];
  for (const sleep of [1, 2]) {
    for (const tpl of cases) {
      const vars = { orig: '1', sleep, num: 7777 };
      assert.equal(
        fillPayload(tpl, vars),
        legacyFill(tpl, vars),
        `sleep=${sleep} 的默认向量被改动了（这会直接影响检出与 e2e 召回）：${tpl}`
      );
    }
  }
});

test('clampTimeVars：sleep 夹到 [1,15]，非法值回落默认', () => {
  assert.equal(clampTimeVars({ sleep: 60 }).sleep, TIME_SLEEP_MAX_SEC);
  assert.equal(clampTimeVars({ sleep: 0 }).sleep, TIME_SLEEP_MIN_SEC);
  assert.equal(clampTimeVars({ sleep: -5 }).sleep, TIME_SLEEP_MIN_SEC);
  assert.equal(clampTimeVars({ sleep: 3 }).sleep, 3, '区间内的值不得被动到');
  assert.equal(clampTimeVars({}).sleep, 1, '未提供 sleep 时保持历史默认 1');
  assert.equal(clampTimeVars({ sleep: 'abc' }).sleep, 1, '非数值回落默认，而不是把 NaN 拼进 payload');
});

test('渲染后不存在任何 DBMS 的超长 sleep', () => {
  const filled = TIME_VECTORS.map((v) => fillPayload(v.payload, { orig: '1', sleep: 600 }));
  for (const s of filled) {
    assert.ok(!/SLEEP\(600\)/i.test(s), `SLEEP 未夹顶：${s}`);
    assert.ok(!/pg_sleep\(600\)/i.test(s), `pg_sleep 未夹顶：${s}`);
    assert.ok(!/0:0:600/.test(s), `WAITFOR DELAY 未夹顶：${s}`);
    assert.ok(!/RECEIVE_MESSAGE\([^)]*,\s*600\)/.test(s), `DBMS_PIPE 未夹顶：${s}`);
    assert.ok(!/sys\.sleep\(600\)/.test(s), `sys.sleep 未夹顶：${s}`);
    assert.ok(!/\bNaN\b/.test(s), `渲染结果里出现 NaN：${s}`);
  }
});

test('capHeavyFunctions：BENCHMARK 迭代数封顶（防把客户库 CPU 打满）', () => {
  assert.equal(capHeavyFunctions("1 AND BENCHMARK(600000000,MD5(1))-- -").match(/BENCHMARK\((\d+)/)[1], String(BENCHMARK_MAX_ITER));
  // 上限内的值原样保留（默认检出路径零改动）
  const keep = "1 AND BENCHMARK(20000000,MD5(1))-- -";
  assert.equal(capHeavyFunctions(keep), keep);
  // 大写与空白容错
  assert.equal(capHeavyFunctions('BENCHMARK(  999999999 , SHA1(1))').match(/BENCHMARK\(\s*(\d+)/)[1], String(BENCHMARK_MAX_ITER));
  // RANDOMBLOB 兜底（模板里已有 MIN() 夹顶，这里防自定义模板）
  assert.match(capHeavyFunctions('RANDOMBLOB(90000000)'), /RANDOMBLOB\(5000000\)/);
});

test('sleep 超界时经 fillPayload 全链路收口（模板侧无需逐条改动）', () => {
  const out = fillPayload("{ORIG}' AND BENCHMARK({SLEEP}0000000,MD5(1))-- -", { orig: '1', sleep: 60 });
  const iter = Number(out.match(/BENCHMARK\((\d+)/)[1]);
  assert.ok(iter <= BENCHMARK_MAX_ITER, `BENCHMARK 迭代数未封顶：${iter}`);
  assert.ok(!/BENCHMARK\(600000000/.test(out), out);
});
