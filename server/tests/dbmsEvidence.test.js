// dbmsEvidence 单测（2026-09-10）：方言验证等级的单一事实来源
// 存在理由：README 曾把 18 库笼统写成「3 库真实验证 + 15 库最小适配」（低估了自身，
// 实际有 7 种引擎真实验证记录）；而报告层没有「这个库我没真验过」的声明。
// 本测试锁定两件事：① 等级与 evidence 的一致性；② 未知方言必须按最保守处理。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DBMS_EVIDENCE, dbmsEvidenceOf, groupByLevel } from '../src/engine/dbmsEvidence.js';

test('dbmsEvidence：verified 级别必须提供可复现 evidence 路径', () => {
  for (const [dbms, v] of Object.entries(DBMS_EVIDENCE)) {
    if (v.level === 'verified' || v.level === 'partial') {
      assert.ok(
        typeof v.evidence === 'string' && v.evidence.length > 0,
        `${dbms} 声明为 ${v.level} 但未提供 evidence（无证据即不得声明已验证）`
      );
    } else {
      assert.equal(v.evidence, null, `${dbms} 为 template-only 时不应带 evidence`);
    }
  }
});

test('dbmsEvidence：已知方言返回对应等级与文案', () => {
  const my = dbmsEvidenceOf('MySQL');
  assert.equal(my.level, 'verified');
  assert.equal(my.levelText, '真实引擎验证');
  assert.equal(my.caveat, null);

  const h2 = dbmsEvidenceOf('H2');
  assert.equal(h2.level, 'partial');
  assert.match(h2.caveat, /部分通道/);

  const ora = dbmsEvidenceOf('Oracle');
  assert.equal(ora.level, 'template-only');
  assert.match(ora.caveat, /未在任何真实 DBMS 上跑过/);
});

test('dbmsEvidence：未知/空方言按最保守处理（template-only + 警示）', () => {
  for (const v of [undefined, null, '', 'SomeUnknownDB']) {
    const e = dbmsEvidenceOf(v);
    assert.equal(e.level, 'template-only');
    assert.ok(e.caveat, '未知方言必须带 caveat，不得给出无保留结论');
  }
});

test('dbmsEvidence：分级覆盖 README 宣称的全部 18 个方言', () => {
  const g = groupByLevel();
  const all = [...g.verified, ...g.partial, ...g['template-only']];
  assert.equal(all.length, 18, `应为 18 个方言，实际 ${all.length}`);
  // 真实验证的具体名单（升级/降级都会触发本断言，迫使改动者同步 README）
  assert.deepEqual(g.verified.sort(), ['MariaDB', 'MySQL', 'PostgreSQL', 'SQLite']);
  assert.deepEqual(g.partial.sort(), ['Derby', 'H2', 'HSQLDB']);
  assert.ok(g['template-only'].includes('SQL Server') && g['template-only'].includes('Oracle'));
});
