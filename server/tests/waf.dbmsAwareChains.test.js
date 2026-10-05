// ============================================================================
// waf.dbmsAwareChains.test.js —— DBMS 感知链选择（批次 D5 2026-10-05）
//
// 背景：unionvaluesrow 系链（真机 2/19 打穿，modsec-live #162）是 MySQL 8 专用语法，
// 曾被提为通用首选 ⇒ artifact-drift 门禁当场抓到 multi-engine PL1 lab 在 H2/HSQLDB 上
// union 技术丢失。本批改为 DBMS 感知：指纹确认 MySQL 时才前置真机打穿链进候选。
// 判据（全部可证伪）：
//   ① unionvaluesrow 必须声明 dbms: ['MySQL']（validateChain 对 H2 目标告警+ok=false）；
//   ② MYSQL_DBMS_CHAINS 导出且内容是真机打穿形态；
//   ③ detect.js：dbms === 'MySQL' 时真机链前置进 blockAdaptive 候选（源码守卫）；
//   ④ 通用 OPERATOR_SWAP_CHAINS 保持 DBMS 无关（不含 unionvaluesrow）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { tamperRegistry } from '../src/core/tamper/TamperRegistry.js';
import '../src/core/tamper/applyTampers.js';
import { MYSQL_DBMS_CHAINS, OPERATOR_SWAP_CHAINS } from '../src/core/waf/wafRecommend.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const read = (rel) => readFileSync(path.join(REPO, rel), 'utf8');

test('① unionvaluesrow 声明 dbms:["MySQL"]：H2 目标上 validateChain 告警且 ok=false', () => {
  const p = tamperRegistry.get('unionvaluesrow');
  assert.ok(p, '插件应已注册');
  assert.deepEqual(p.dbms, ['MySQL'], 'dbms 声明缺失 —— 非 MySQL 目标将产出语法错误的 payload');
  const v = tamperRegistry.validateChain(['unionvaluesrow'], { dbms: 'H2' });
  assert.equal(v.ok, false, 'H2 目标必须判不通过');
  assert.match(v.warnings.join(''), /MySQL/);
  const m = tamperRegistry.validateChain(['unionvaluesrow'], { dbms: 'MySQL' });
  assert.equal(m.ok, true, 'MySQL 目标应通过');
});

test('② MYSQL_DBMS_CHAINS：真机打穿形态在案（#162 链对拍）', () => {
  assert.deepEqual(MYSQL_DBMS_CHAINS[0], ['unionvaluesrow', 'dash2hash']);
  assert.deepEqual(MYSQL_DBMS_CHAINS[1], ['unionvaluesrow', 'dash2hash', 'hexliterals']);
});

test('④ 通用 OPERATOR_SWAP_CHAINS 保持 DBMS 无关（不含 unionvaluesrow / scalarselectinline 组合链）', () => {
  for (const chain of OPERATOR_SWAP_CHAINS) {
    assert.ok(!chain.includes('unionvaluesrow'), '通用链表不得含 MySQL 专用链（H2/HSQLDB 会语法错误）');
  }
});

test('③ detect.js：dbms=MySQL 时真机链前置进 blockAdaptive 候选（源码守卫）', () => {
  const src = read('server/src/engine/scan/detect.js');
  assert.match(src, /import \{ OPERATOR_SWAP_CHAINS, FILTER_BYPASS_CHAINS, MYSQL_DBMS_CHAINS \}/, '导入缺失');
  const prep = src.indexOf("if (dbms === 'MySQL') {");
  const generic = src.indexOf('for (const plugins of OPERATOR_SWAP_CHAINS) {', prep >= 0 ? prep : 0);
  assert.ok(prep >= 0 && generic > prep, 'MySQL 专属链必须**前置**于通用链（真机打穿链优先）');
  // 顺序守卫：真机打穿链在通用链之前被 push
  const pushMysql = src.indexOf('MYSQL_DBMS_CHAINS)', prep);
  const pushGeneric = src.indexOf("suggestions.push({ vendor: GENERIC_BLOCK_VENDOR, plugins: [...plugins] });", pushMysql);
  assert.ok(pushMysql > 0 && pushGeneric > pushMysql, 'MySQL 链必须先于通用链 push');
});
