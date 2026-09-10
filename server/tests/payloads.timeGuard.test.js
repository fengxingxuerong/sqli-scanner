// [P1 2026-09-09] 时间模板延迟语义守卫
// 背景（09-08 批次 #23 + 本批盘点）：time 模板若「静默缺占位符」——既无 {SLEEP} 又无
// 固定延迟/重运算语义——时间检测恒不命中且无任何报错（探测被 timeFloorMs 判成噪声）。
// 严重案例：pg-time-dest-2/3 本是 pg_read_file/lo_import（文件读/OOB 误标成 time），
// 小文件读取无延迟；ora-time-dest-1 是 UTL_HTTP OOB 向量。本批已全部改为真延迟向量。
// 守卫规则：每个 time 模板必须满足其一：
//   ① 含 {SLEEP}（可调延迟）；
//   ② 含固定延迟/重运算语义（RANDOMBLOB/BENCHMARK/REPEAT/GET_LOCK/DBMS_LOCK/
//      DBMS_PIPE/WAITFOR/pg_sleep/sleep N）；
//   ③ heavy 笛卡尔积（COUNT(*) FROM t a, t b）或 Oracle DECODE(SUM( 重查询。
// 不再允许「既无占位符也无语义」的静默缺失模板进入下一次回归。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PAYLOADS, TIME_VECTORS } from '../src/engine/payloads/index.js';
import { PAYLOAD_REGISTRY } from '../src/engine/payloadRegistry.js';

const TUNABLE = '{SLEEP}';
const FIXED_DELAY = /RANDOMBLOB\(\s*\d{6,}|BENCHMARK\(\s*\d{5,}|REPEAT\('[^']+',\s*\d{5,}|GET_LOCK\(|DBMS_LOCK|DBMS_PIPE\.RECEIVE_MESSAGE\('[^']+',\s*\d|WAITFOR\s+DELAY|pg_sleep\(\s*\d|sleep\s+\d/i;
const HEAVY = /COUNT\(\*\)\s+FROM\s+[\w.]+\s+[a-z]\s*,\s*[\w.]+\s+[a-z]|DECODE\(SUM\(/i;

function hasDelaySemantics(tpl) {
  const s = String(tpl);
  if (s.includes(TUNABLE)) return true;
  if (FIXED_DELAY.test(s)) return true;
  if (HEAVY.test(s)) return true;
  return false;
}

function collectTimeTemplates() {
  const out = [];
  for (const [dbms, techs] of Object.entries(PAYLOADS)) {
    const list = techs && techs.time;
    if (Array.isArray(list)) for (const t of list) out.push({ src: `flat:${dbms}`, tpl: String(t) });
  }
  for (const v of TIME_VECTORS || []) {
    out.push({ src: 'TIME_VECTORS', tpl: String(v.payload || '') });
  }
  for (const r of PAYLOAD_REGISTRY) {
    if (String(r.technique) !== 'time') continue;
    out.push({ src: `registry:${r.id}`, tpl: String(r.template || '') });
    if (r.falseTemplate) out.push({ src: `registry:${r.id}:false`, tpl: String(r.falseTemplate) });
  }
  return out;
}

test('time 模板必须含 {SLEEP} 或明确的延迟/重运算语义（禁止静默缺失）', () => {
  const all = collectTimeTemplates();
  assert.ok(all.length > 300, `time 模板数量应充足，实际 ${all.length}`);
  const bad = all.filter((x) => !hasDelaySemantics(x.tpl));
  assert.deepEqual(
    bad,
    [],
    `以下 time 模板既无 {SLEEP} 也无延迟/重运算语义（检测恒不命中的静默缺失）：\n` +
      bad.map((b) => `  ${b.src}: ${b.tpl.slice(0, 110)}`).join('\n')
  );
});

test('关键模板延迟语义锚点存在（回归锁）', () => {
  const reg = new Map(PAYLOAD_REGISTRY.map((r) => [r.id, r]));
  // 本批修复的三条误归类模板：现在必须是可控延迟向量
  assert.match(reg.get('pg-time-dest-2').template, /pg_sleep\(5\)/);
  assert.match(reg.get('pg-time-dest-3').template, /pg_sleep\(5\)/);
  assert.match(reg.get('ora-time-dest-1').template, /DBMS_PIPE\.RECEIVE_MESSAGE\('sqli',5\)/);
  // 已合规的固定延迟向量（不应被误截断回缺位）
  assert.match(reg.get('mysql-time-dest-2').template, /BENCHMARK\(\d+/);
  assert.ok(reg.get('lite-time-dest-1').template.includes('RANDOMBLOB('));
});