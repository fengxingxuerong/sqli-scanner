// ============================================================================
// tests/tamperCaseCoverage.test.js —— 大小写类 tamper 的行为与关键字集覆盖
//
// ── 为什么这个文件存在 ───────────────────────────────────────────────────────
// 2026-10-05 克隆检测发现 swapcase.js 与 mixedcase.js 共享 21 个 5-gram，
// 顺着查出真问题：**swapcase 只覆盖 11 个关键字，缺 UPDATE / DELETE**。
//
// 影响不是"少了个功能"那么简单：本仓 payload 确实含这两类注入向量 ——
//   · mysql.js     UPDATE SET 逗号拼接 / DELETE WHERE 子句注入
//   · postgres.js  DELETE USING 子句注入
//   · sqlserver.js UPDATE 逗号拼接
//   · exploit/fileRead.js 用 `; DELETE FROM SQLI_DUMP-- -` 清理临时表
// tamper 链一旦选中 swapcase，这些向量里的关键字**原样发出**，直接撞上 WAF
// 关键字检测 —— 属检出能力损失，而非单纯的风格问题。
//
// 而 tamper.test.js 对这两个插件**只验注册存在**（在 200+ 个名字的清单里），
// 从未断言过 transform 的行为。所以一个真实缺陷可以长期绿着。
//
// 故本文件钉三件事：
//   1) swapcase / mixedcase 覆盖**同一套**关键字（防止再次单边漂移）
//   2) 覆盖集必须含本仓真实使用的注入向量关键字
//   3) swapcase 的改写规则确实是"逐位大小写互换"（不是随便换一种大小写样式）
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { swapcase } from '../src/core/tamper/plugins/swapcase.js';
import { mixedcase } from '../src/core/tamper/plugins/mixedcase.js';

/** 从插件源码里抽出 .replace(/\bKEY\b/gi, 'x') 形式的规则 */
function rulesOf(plugin) {
  const src = plugin.transform.toString();
  return [...src.matchAll(/\.replace\(\/\\b([A-Z]+)\\b\/gi,\s*'([^']+)'\)/g)]
    .map((m) => ({ kw: m[1], out: m[2] }));
}

const SWAP_KWS = new Set(rulesOf(swapcase).map((r) => r.kw));
const MIX_KWS = new Set(rulesOf(mixedcase).map((r) => r.kw));

test('覆盖-1) swapcase 与 mixedcase 覆盖同一套关键字（防单边漂移）', () => {
  const onlySwap = [...SWAP_KWS].filter((k) => !MIX_KWS.has(k));
  const onlyMix = [...MIX_KWS].filter((k) => !SWAP_KWS.has(k));
  assert.deepEqual(onlySwap, [], `swapcase 多出关键字：${onlySwap.join(', ')} —— 两插件应同集合`);
  assert.deepEqual(onlyMix, [], `swapcase 缺这些关键字：${onlyMix.join(', ')}\n` +
    '大小写类 tamper 若覆盖不全，含该关键字的注入向量会原样发出、直接撞上 WAF 关键字检测。\n' +
    '（2026-10-05 的实际缺陷正是缺 UPDATE / DELETE）');
});

test('覆盖-2) 关键字集含本仓真实使用的注入向量关键字', () => {
  // 这些不是"顺手加的"，而是 payload 里确实出现的（mysql.js / postgres.js /
  // sqlserver.js 的 UPDATE/DELETE 子句注入，以及 fileRead.js 的临时表清理）。
  // 若将来向量新增了别的关键字（如 MERGE、UPSERT），请一并在此登记。
  const REQUIRED = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'ORDER',
    'GROUP', 'HAVING', 'LIMIT', 'INSERT', 'UPDATE', 'DELETE'];
  const missingSwap = REQUIRED.filter((k) => !SWAP_KWS.has(k));
  const missingMix = REQUIRED.filter((k) => !MIX_KWS.has(k));
  assert.deepEqual(missingSwap, [], `swapcase 缺：${missingSwap.join(', ')}`);
  assert.deepEqual(missingMix, [], `mixedcase 缺：${missingMix.join(', ')}`);
});

test('行为-3) swapcase 改写确实是"逐位大小写互换"（规则不是随手写的）', () => {
  for (const r of rulesOf(swapcase)) {
    const expected = [...r.kw]
      .map((c, i) => (i % 2 === 0 ? c.toLowerCase() : c.toUpperCase()))
      .join('');
    assert.equal(r.out, expected,
      `${r.kw} 的改写结果应为 ${expected}（首字母小写、逐位交替），实际 ${r.out}`);
  }
});

test('行为-4) transform 真的改写了全部关键字，且大小写无关地匹配', () => {
  for (const kw of SWAP_KWS) {
    // 小写输入也必须被改写（正则带 /gi）；若不匹配会原样返回，等于 tamper 失效
    for (const input of [kw, kw.toLowerCase(), kw[0] + kw.slice(1).toLowerCase()]) {
      const out = swapcase.transform(`1 ${input} 2`, {});
      assert.notEqual(out, `1 ${input} 2`,
        `swapcase 未改写 ${input} —— 正则的 /i 标志或 \\b 边界可能失效`);
    }
  }
});

test('行为-5) 关键字边界不被误伤（\\b 保证不匹配更长标识符）', () => {
  // SELECTED / UPDATE_TIME 这类含关键字子串的标识符不应被改写，
  // 否则会破坏 payload 里的表名/列名/字符串字面量。
  for (const guard of ['SELECTED', 'myUPDATE', 'DELETED_FLAG', 'INSERTION']) {
    assert.equal(swapcase.transform(guard, {}), guard,
      `${guard} 不应被 swapcase 改写（\\b 边界失效会破坏表名/列名）`);
  }
});

test('行为-6) mixedcase 同样改写全部关键字（防只修了 swapcase 一侧）', () => {
  for (const kw of MIX_KWS) {
    const out = mixedcase.transform(`1 ${kw} 2`, {});
    assert.notEqual(out, `1 ${kw} 2`, `mixedcase 未改写 ${kw}`);
  }
});
