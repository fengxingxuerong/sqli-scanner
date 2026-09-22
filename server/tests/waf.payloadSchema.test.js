// waf.payloadSchema.test.js —— 声明式 payload schema 的机械验证（E5 第一步）
// ============================================================================
// 本步的**存在意义**是一条判据：现有 PAYLOAD_REGISTRY 的 681 条能否被 schema 完整描述。
// 判据达成 = 将来把数据源切到 YAML/JSON 才具备可行性；过不了的部分是 DSL 化的硬阻塞。
// 另有一条防漂移断言：数据里出现的字段必须都在 KNOWN_FIELDS 内（否则 DSL 化会静默丢字段）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as regMod from '../src/engine/payloadRegistry.js';
import {
  validatePayloadEntry,
  validatePayloadEntries,
  toDslEntry,
  isJsonSafe,
  schemaSummary,
  KNOWN_FIELDS,
  TECHNIQUE_VALUES,
  WHERE_VALUES,
  CLAUSE_VALUES,
  POSITION_CLAUSES,
} from '../src/engine/payloadSchema.js';

/** 取注册表数组（不硬编码导出名，避免改名即测试崩） */
function registry() {
  const arr = Object.values(regMod).find(
    (v) => Array.isArray(v) && v.length > 100 && v[0] && typeof v[0] === 'object' && 'id' in v[0]
  );
  assert.ok(arr, '未能在 payloadRegistry.js 中找到声明式条目数组');
  return arr;
}

/** 合法基线条目（供单元行为测试构造变体） */
const base = {
  id: 'unit-1',
  dbms: ['MySQL'],
  technique: 'union',
  level: 1,
  risk: 1,
  clause: ['where'],
  boundary: [''],
  template: '{ORIG} UNION SELECT 1-- -',
  where: 'value',
};

test('判据①：现有注册表全部条目通过 schema 校验（DSL 化的硬前提）', () => {
  const r = validatePayloadEntries(registry());
  assert.ok(r.total > 600, `条目数异常：${r.total}`);
  assert.deepEqual(
    r.failed,
    [],
    `有 ${r.failed.length} 条未通过校验：\n  - ${r.failed.slice(0, 10).map((f) => `${f.id}: ${f.errors.join(' | ')}`).join('\n  - ')}`,
  );
  assert.equal(r.okCount, r.total);
});

test('判据②：现有条目 id 无重复（id 是 DSL 的主键）', () => {
  const r = validatePayloadEntries(registry());
  assert.deepEqual(r.duplicateIds, [], `重复 id：${r.duplicateIds.slice(0, 10).join(', ')}`);
});

test('判据③：全部条目 JSON-safe（YAML/JSON 装不下 undefined/函数/Symbol/BigInt）', () => {
  const arr = registry();
  const bad = arr.filter((e) => !isJsonSafe(e));
  assert.deepEqual(bad.map((e) => e.id).slice(0, 5), [], '存在序列化不安全的条目');
  assert.ok(arr.every(isJsonSafe));
});

test('判据④：DSL 化往返无损（toDslEntry 后与原条目深相等，不丢字段）', () => {
  for (const e of registry()) {
    const d = toDslEntry(e);
    assert.deepEqual(d, e, `条目 ${e.id} 经 DSL 化后不等价（字段丢失或被改写）`);
  }
});

test('判据⑤（防漂移）：数据里出现的字段必须都在 KNOWN_FIELDS 内', () => {
  const unknown = new Set();
  for (const e of registry()) {
    for (const k of Object.keys(e)) if (!KNOWN_FIELDS.includes(k)) unknown.add(k);
  }
  assert.deepEqual(
    [...unknown],
    [],
    `数据里有 schema 未建模的字段（DSL 化会静默丢掉）：${[...unknown].join(', ')}`,
  );
});

test('判据⑥：现有条目的一致性 warning 为 0（schema 已按真实数据校准）', () => {
  const r = validatePayloadEntries(registry());
  assert.deepEqual(
    r.warnings.map((w) => `${w.id}: ${w.warnings.join(' | ')}`).slice(0, 8),
    [],
    '出现一致性警告：要么 schema 判据太窄（应校准），要么数据真有问题',
  );
});

test('单元：结构性错误被拦下（缺字段 / 越界 / 非法枚举）', () => {
  const cases = [
    [{ ...base, id: '' }, 'id 必须是非空字符串'],
    [{ ...base, dbms: [] }, 'dbms 必须是非空数组'],
    [{ ...base, technique: 'nosql' }, 'technique 取值非法'],
    [{ ...base, level: 6 }, 'level 必须是'],
    [{ ...base, risk: 0 }, 'risk 必须是'],
    [{ ...base, clause: ['nosuch'] }, 'clause 取值非法'],
    [{ ...base, where: 'side' }, 'where 取值非法'],
    [{ ...base, template: '' }, 'template 必须是非空字符串'],
    [{ ...base, falseTemplate: 123 }, 'falseTemplate 若存在必须是字符串'],
    [{ ...base, boundary: 'not-array' }, 'boundary 必须是数组'],
    [{ ...base, minVersion: '5.7' }, 'minVersion 必须是数字或'],
    [null, '条目不是对象'],
  ];
  for (const [entry, expect] of cases) {
    const r = validatePayloadEntry(entry);
    assert.equal(r.ok, false, `应判定非法：${expect}`);
    assert.ok(r.errors.some((e) => e.includes(expect)), `缺少错误「${expect}」，实际：${r.errors.join('|')}`);
  }
});

test('单元：合法条目（含可选字段两种形态）通过', () => {
  assert.equal(validatePayloadEntry(base).ok, true);
  assert.equal(validatePayloadEntry({ ...base, falseTemplate: '{ORIG} AND 1=2' }).ok, true);
  assert.equal(validatePayloadEntry({ ...base, minVersion: 5.7 }).ok, true);
  assert.equal(validatePayloadEntry({ ...base, maxVersion: { major: 8, minor: 0 } }).ok, true);
  // 不写可选字段也合法
  const minimal = { id: 'x', dbms: ['MySQL'], technique: 'union', level: 1, risk: 1, template: 't' };
  assert.equal(validatePayloadEntry(minimal).ok, true);
});

test('单元：warning 只在一致性可疑时给，不阻塞通过', () => {
  const posNoClause = { ...base, where: 'position', clause: ['where'] };
  const r1 = validatePayloadEntry(posNoClause);
  assert.equal(r1.ok, true, 'warning 不应阻塞');
  assert.ok(r1.warnings.some((w) => w.includes("where='position'")));

  const posOk = { ...base, where: 'position', clause: ['orderby'] };
  assert.equal(validatePayloadEntry(posOk).warnings.length, 0);

  const destLowRisk = { ...base, id: 'x-dest-1', risk: 1 };
  const r2 = validatePayloadEntry(destLowRisk);
  assert.equal(r2.ok, true);
  assert.ok(r2.warnings.some((w) => w.includes('-dest-')));
});

test('单元：批量校验统计口径正确，且幂等（跑两次结果一致）', () => {
  const arr = registry();
  const a = validatePayloadEntries(arr);
  const b = validatePayloadEntries(arr);
  assert.equal(a.total, b.total);
  assert.equal(a.okCount, b.okCount);
  assert.equal(a.failed.length, b.failed.length);
  // 空输入安全
  const empty = validatePayloadEntries(undefined);
  assert.equal(empty.total, 0);
  assert.equal(empty.okCount, 0);
  assert.deepEqual(empty.duplicateIds, []);
});

test('schema 自描述：枚举值完备且不重复（供报告/UI 复用，避免多处手抄）', () => {
  const s = schemaSummary();
  assert.ok(s.techniques.includes('union') && s.techniques.includes('boolean'));
  assert.equal(new Set(s.techniques).size, s.techniques.length, 'technique 枚举有重复');
  assert.equal(new Set(s.clauseValues).size, s.clauseValues.length);
  assert.equal(new Set(KNOWN_FIELDS).size, KNOWN_FIELDS.length, 'KNOWN_FIELDS 有重复');
  // 位置类子句必须是 clause 枚举的子集（否则判据自相矛盾）
  for (const c of POSITION_CLAUSES) assert.ok(CLAUSE_VALUES.includes(c), `${c} 不在 CLAUSE_VALUES 内`);
  for (const w of WHERE_VALUES) assert.ok(typeof w === 'string');
  assert.equal(new Set(TECHNIQUE_VALUES).size, TECHNIQUE_VALUES.length);
});
