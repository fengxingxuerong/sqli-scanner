// tamper 元数据体系回归（[P1-FIX 2026-09-05]：terminal 截断 + dbms 限定告警 + validateChain）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
import { applyTampers } from '../src/core/tamper/applyTampers.js';

const ctx = { config: { wafEvasion: {} } };
const ctxPg = { dbms: 'PostgreSQL', config: { wafEvasion: {} } };

test('terminal 截断：base64encode 之后的插件不再执行（不再静默空转）', () => {
  // 旧行为实测：base64encode -> space2comment 输出纯 b64，space2comment 空转且无告警
  const out = applyTampers('UNION SELECT 1', ctx, ['base64encode', 'space2comment']);
  assert.equal(out, 'VU5JT04gU0VMRUNUIDE=', 'terminal 后链应截断，输出即纯 b64');
  // 单独 base64encode 与串联输出一致 → 截断生效
  const solo = applyTampers('UNION SELECT 1', ctx, ['base64encode']);
  assert.equal(out, solo);
});

test('terminal 元数据已注入编码类插件', () => {
  for (const name of ['base64encode', 'charencode', 'chardoubleencode', 'decimal2char', 'keyword2decimal', 'bin2ascii']) {
    const p = tamperRegistry.get(name);
    assert.ok(p?.terminal, `${name} 应声明 terminal`);
  }
});

test('dbms 元数据已注入方言限定插件', () => {
  assert.deepEqual(tamperRegistry.get('dollarquote').dbms, ['PostgreSQL']);
  assert.deepEqual(tamperRegistry.get('oraclequote').dbms, ['Oracle']);
  assert.deepEqual(tamperRegistry.get('sleep2getlock').dbms, ['MySQL']);
  assert.deepEqual(tamperRegistry.get('percentage').dbms, ['SQL Server']);
});

test('resolve：dbms 不匹配仅告警不截断（对齐 sqlmap 警告但继续）', () => {
  const chain = tamperRegistry.resolve(['dollarquote', 'lowercase'], ctxPg);
  // dollarquote 限定 PG、目标 PG → 保留；lowercase 无限定 → 保留
  assert.equal(chain.length, 2);
  // 无 ctx.dbms 时不过滤（保守）
  assert.equal(tamperRegistry.resolve(['dollarquote']).length, 1);
});

test('list() 输出携带元数据（UI 可用）', () => {
  const list = tamperRegistry.list();
  const b64 = list.find((p) => p.name === 'base64encode');
  assert.equal(b64.terminal, true);
  const dq = list.find((p) => p.name === 'dollarquote');
  assert.deepEqual(dq.dbms, ['PostgreSQL']);
  const plain = list.find((p) => p.name === 'lowercase');
  assert.equal(plain.terminal, undefined);
  assert.equal(plain.dbms, undefined);
});

test('validateChain：terminal 截断 / dbms 警告 / 未知插件', () => {
  // terminal 截断
  const r1 = tamperRegistry.validateChain(['base64encode', 'space2comment']);
  assert.deepEqual(r1.plugins, ['base64encode']);
  assert.ok(r1.warnings.some((w) => /space2comment/.test(w) && /截断/.test(w)));
  // dbms 警告但不剔除
  const r2 = tamperRegistry.validateChain(['dollarquote'], { dbms: 'MySQL' });
  assert.deepEqual(r2.plugins, ['dollarquote']);
  assert.ok(r2.warnings.some((w) => /不匹配/.test(w)));
  // 未知插件
  const r3 = tamperRegistry.validateChain(['nonexistent_tamper', 'lowercase']);
  assert.ok(r3.warnings.some((w) => /nonexistent_tamper/.test(w)));
  assert.deepEqual(r3.plugins, ['lowercase']);
  // 干净链
  const r4 = tamperRegistry.validateChain(['space2comment', 'randomcase']);
  assert.equal(r4.ok, true);
  assert.deepEqual(r4.warnings, []);
});
