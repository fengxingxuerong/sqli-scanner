// ============================================================================
// server/tests/payloadVersion.patch.test.js
//
// 两件判据（都来自 [D9 2026-10-06 竞品吸收] 加版本门条目时踩到的真问题）：
//   A. **补丁级**版本下限能表达、能生效。MySQL 的能力分界大量落在补丁号
//      （LATERAL 8.0.14 / VALUES ROW 8.0.19 / JSON_VALUE 8.0.21），而旧的
//      versionAtLeast 只比到 major.minor ⇒ 声称 8.0.21 实际被读成 8.0，
//      条目会投放到 8.0.0-8.0.20 上拿运行时错误。
//   B. 版本门条目**只在实测过的上下文里声明**：本批四条都只在数值上下文（boundary [""]）
//      上跑过真库差分，所以判据钉住"声明的边界 == 实测过的边界"，并顺手做单引号奇偶自检
//      （渲染后引数为奇 ⇒ 发出去就是畸形请求）。扩上下文必须先补真库差分，不许"顺手多声明一个"。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseDbmsVersion, versionAtLeast, versionBelow } from '../src/engine/dbmsVersion.js';
import { selectPayloads, PAYLOAD_REGISTRY } from '../src/engine/payloadRegistry.js';
import { fillPayload } from '../src/engine/payloads/index.js';
import { validatePayloadEntry } from '../src/engine/payloadSchema.js';

const V = (raw) => parseDbmsVersion('MySQL', raw);
const idsAt = (raw) =>
  selectPayloads({ dbms: 'MySQL', technique: 'boolean', level: 5, dbmsVersion: V(raw) }).map((e) => e.id);

const VERSIONED_IDS = [
  'mysql-bool-cte-80',
  'mysql-bool-window-80',
  'mysql-bool-lateral-8014',
  'mysql-bool-valuesrow-8019',
  'mysql-bool-jsonvalue-8021',
];

test('① 补丁级下限生效：8.0.13 / 8.0.14 / 8.0.20 / 8.0.21 各自判对', () => {
  assert.equal(versionAtLeast(V('8.0.13'), { major: 8, minor: 0, patch: 14 }), false);
  assert.equal(versionAtLeast(V('8.0.14'), { major: 8, minor: 0, patch: 14 }), true);
  assert.equal(versionAtLeast(V('8.0.20'), { major: 8, minor: 0, patch: 21 }), false);
  assert.equal(versionAtLeast(V('8.0.21'), { major: 8, minor: 0, patch: 21 }), true);
  assert.equal(versionAtLeast(V('5.7.25'), { major: 8, minor: 0 }), false);
  // 补丁参与上界：MySQL<5.7 专属条目在 5.7.1 上不许投放
  assert.equal(versionBelow(V('5.7.1'), { major: 5, minor: 7 }), false);
  assert.equal(versionBelow(V('5.6.51'), { major: 5, minor: 7 }), true);
});

test('② 旧语义零回归：数字形态仍只到次版本，对象缺 patch 仍当 0', () => {
  assert.equal(versionAtLeast({ major: 5, minor: 7 }, 5.7), true);
  assert.equal(versionAtLeast({ major: 5, minor: 6 }, 5.7), false);
  assert.equal(versionAtLeast({ major: 8, minor: 0 }, 5.7), true);
  assert.equal(versionAtLeast({ major: 2019 }, { major: 2017 }), true);
  assert.equal(versionAtLeast({ major: 8, minor: 0, raw: '8.0.32' }, { major: 8, minor: 0 }), true);
  // 版本未知 → 保守投放（不砍 payload），未知时上界条目不投放
  assert.equal(versionAtLeast({ major: null, minor: null }, { major: 8, minor: 0, patch: 21 }), true);
  assert.equal(versionBelow({ major: null }, { major: 5, minor: 7 }), false);
});

test('③ schema：补丁级只接受对象形态，8.019 这种数字写法当场拒', () => {
  const base = {
    id: 'x', dbms: ['MySQL'], technique: 'boolean', level: 1, risk: 1,
    clause: ['where'], boundary: [''], template: '{ORIG} AND 1=1', where: 'value',
  };
  assert.equal(validatePayloadEntry({ ...base, minVersion: { major: 8, minor: 0, patch: 21 } }).errors.length, 0);
  const bad = validatePayloadEntry({ ...base, minVersion: 8.019 });
  assert.ok(bad.errors.some((e) => /补丁级/.test(e)), `8.019 必须被拒（会被一位小数编码读成 8.0），实际：${JSON.stringify(bad.errors)}`);
  assert.equal(validatePayloadEntry({ ...base, minVersion: 5.7 }).errors.length, 0); // 一位小数仍合法
});

test('④ 投放矩阵：五条版本门条目按补丁号进出（不是恒真也不是恒假）', () => {
  // 顺序不参与判定（注册表行序＝投放优先级，是另一条判据管的）——这里比集合
  const at = (raw) => VERSIONED_IDS.filter((id) => idsAt(raw).includes(id)).sort();
  const sorted = (a) => [...a].sort();
  assert.deepEqual(at('8.0.28'), sorted(VERSIONED_IDS), '8.0.28 应五条全投');
  assert.deepEqual(at('8.0.21'), sorted(VERSIONED_IDS), '8.0.21 起 JSON_VALUE 才有 ⇒ 五条全投');
  assert.deepEqual(at('8.0.19'), sorted(['mysql-bool-cte-80', 'mysql-bool-window-80', 'mysql-bool-lateral-8014', 'mysql-bool-valuesrow-8019']));
  assert.deepEqual(at('8.0.14'), sorted(['mysql-bool-cte-80', 'mysql-bool-window-80', 'mysql-bool-lateral-8014']));
  assert.deepEqual(at('8.0.0'), sorted(['mysql-bool-cte-80', 'mysql-bool-window-80']), '8.0.0 只有 CTE 与窗口函数');
  assert.deepEqual(at('5.7.44'), [], '5.7 一条都不该投');
  // 每条都必须"在某些版本退场"，否则等于没有门（防"条目写了 minVersion 但形同不写"）
  for (const id of VERSIONED_IDS) {
    assert.ok(!at('5.7.44').includes(id), `${id} 无版本门`);
  }
});

test('⑤ 渲染后奇偶自检：每条版本门条目在其声明的每个 boundary 下，单引号必须成对', () => {
  // orig 取「原始参数值」而不是"值+闭合符"：检测器就是这么算的
  // （BooleanBlindDetector.js:117 `const orig = point.originalValue || '1'`，闭合符由模板自带）。
  const entries = VERSIONED_IDS.map((id) => {
    const e = PAYLOAD_REGISTRY.find((x) => x.id === id);
    assert.ok(e, `${id} 不在注册表里（合并加载断链？）`);
    return e;
  });
  for (const e of entries) {
    assert.deepEqual(e.boundary, [''], '本批条目只在数值上下文实测过；要扩引号/括号上下文，先补真库差分再声明');
    for (const b of e.boundary) {
      void b;
      for (const tpl of [e.template, e.falseTemplate]) {
        const rendered = fillPayload(tpl, { orig: '1' });
        const quotes = (rendered.match(/(?<!\\)'/g) || []).length;
        assert.equal(quotes % 2, 0, `${e.id} 渲染后单引号为奇数（发出去会畸形）：${rendered}`);
      }
    }
  }
});
