// ============================================================================
// passwords.analysis.wiring.test.js —— `--passwords` 的**接线守卫**
// ============================================================================
// 守什么：哈希分析有两个**各自都能独立全绿**的部件 ——
//   ① `extraction/hashAnalysis.js`（纯函数，见 hashAnalysis.test.js）；
//   ② `extractScope` 的 `case 'passwords'`（把 ① 挂到提取结果上）。
// 只测 ① 的形态是本仓点名过的假绿：**helper 测得再全，生产代码没人调也照样绿**。
// 所以这里用 mock extractor 真跑一遍 `extractAll`，断言：
//   · `passwords` 原始串**契约不变**（既有消费方零感知）；
//   · `passwordAnalysis` 确实被产出且**由原始串派生**（不是空对象占位）；
//   · 取不到凭据（null）时同样是 null —— 「未提取」与「提取为空」必须可区分；
//   · 两个合并白名单（mergeExtracted / mergeExtractedForResume）都搬运该字段 ——
//     本仓出过「逐字段白名单漏一个 ⇒ 功能在报告里恒为空」的缺陷（scanHelpers 内注释即其墓碑）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { extractAll } from '../src/engine/extractScope.js';
import { emptyExtractedData } from '../src/engine/models.js';
import { mergeExtracted, mergeExtractedForResume } from '../src/engine/scanHelpers.js';

const NATIVE = '*'.concat('A'.repeat(40));
const MYSQL_RAW = `root@localhost:${NATIVE},app@%:${NATIVE}`;

function smWithPasswords(passwords) {
  return { extractor: { async enumeratePasswords() { return passwords; } } };
}

function ctxFor(mode, dbms = 'MySQL') {
  const scope = { mode };
  return { dbms, config: { extractScope: scope }, target: { config: { extractScope: scope } } };
}

test('extractScope(passwords): 原始串契约不变，且派生出 passwordAnalysis', async () => {
  const data = await extractAll(smWithPasswords(MYSQL_RAW), 'sid', ctxFor('passwords'));
  assert.equal(data.passwords, MYSQL_RAW, 'passwords 原始串必须原样保留（既有消费方零感知）');
  assert.equal(typeof data.passwordAnalysis, 'object');
  assert.notEqual(data.passwordAnalysis, null, '分析结构必须真的被产出（防「挂了个 null 占位」）');
  assert.equal(data.passwordAnalysis.total, 2);
  assert.equal(data.passwordAnalysis.medium, 2);
  assert.deepEqual(data.passwordAnalysis.entries.map((e) => e.user), ['root', 'app']);
});

test('extractScope(passwords): 空口令被标 blank/high（这正是本功能的价值点）', async () => {
  const data = await extractAll(smWithPasswords('root@localhost:,app@%:' + NATIVE), 'sid', ctxFor('passwords'));
  assert.equal(data.passwordAnalysis.blank, 1);
  assert.equal(data.passwordAnalysis.medium, 1);
  assert.equal(data.passwordAnalysis.entries[0].risk, 'high');
});

test('extractScope(passwords): 取不到凭据 ⇒ passwords 与 passwordAnalysis 双 null（可区分「未提取」）', async () => {
  const data = await extractAll(smWithPasswords(null), 'sid', ctxFor('passwords'));
  assert.equal(data.passwords, null);
  assert.equal(data.passwordAnalysis, null, '原始串为 null 时不得造出全 0 的空分析结构');
});

test('extractScope(passwords): 分析结果随 dbms 上下文走（PG SCRAM 不该按 MySQL 判）', async () => {
  const pgRaw = 'postgres:SCRAM-SHA-256$4096:c2FsdA==$a2V5MQ==:a2V5Mg==';
  const data = await extractAll(smWithPasswords(pgRaw), 'sid', ctxFor('passwords', 'PostgreSQL'));
  assert.equal(data.passwordAnalysis.strong, 1);
  assert.equal(data.passwordAnalysis.entries[0].user, 'postgres');
});

test('mergeExtracted: 搬运 passwordAnalysis（白名单漏字段 = 报告里恒为空）', () => {
  const target = emptyExtractedData();
  const analysis = { total: 1, blank: 1, weak: 0, medium: 0, strong: 0, unknown: 0, algorithms: { none: 1 }, entries: [], truncated: 0 };
  mergeExtracted(target, { passwords: 'root@x:', passwordAnalysis: analysis });
  assert.equal(target.passwords, 'root@x:');
  assert.equal(target.passwordAnalysis, analysis, 'passwordAnalysis 必须被 mergeExtracted 搬运');
});

test('mergeExtractedForResume: 续跑时恢复 passwordAnalysis（当前为空才回填）', () => {
  const out = mergeExtractedForResume(
    emptyExtractedData(),
    { passwords: 'root@x:', passwordAnalysis: { total: 1, blank: 1, weak: 0, medium: 0, strong: 0, unknown: 0, algorithms: { none: 1 }, entries: [], truncated: 0 } }
  );
  assert.equal(out.passwords, 'root@x:');
  assert.equal(out.passwordAnalysis.total, 1, 'resume 后分析结构必须一起回来');
});

test('emptyExtractedData: 声明 passwordAnalysis 键（形状可发现，不被静默丢弃）', () => {
  assert.ok('passwordAnalysis' in emptyExtractedData(), 'emptyExtractedData 应声明 passwordAnalysis');
});
