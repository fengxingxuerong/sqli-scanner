// ============================================================================
// payloadSafety.guard.test.js —— 默认 payload 池安全护栏
// ============================================================================
// 背景：一批「sqlmap 对标」payload 被直接追加进 payloads/<dbms>.js 的默认数组，
// 混入了服务端写文件、任意文件读、OS 命令执行、注册表读取、永久改服务器配置、
// 命名锁阻塞、CPU/内存 DoS，以及**硬编码第三方域名**的外连 OOB 向量。
// 由于 ErrorDetector 在 dbms 已知时**全量遍历** error 模板，这些向量在默认
// risk=2 / level=1 的常规扫描中就会被投放 —— 属于未授权即对目标造成影响的严重问题。
//
// 本测试是防回归护栏：任何把高危向量塞回默认池的改动都会在 CI 被拦下。
// 需要这些能力时请放进 destructive.js，由 --risk=3 显式开启。
// ============================================================================

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  PAYLOADS,
  DESTRUCTIVE_PAYLOADS,
  DESTRUCTIVE_MIN_RISK,
  enableDestructivePayloads,
  getDestructiveTemplates,
} from '../src/engine/payloads.js';

// 默认池中绝对不得出现的高危模式（正则 → 说明）
const FORBIDDEN_PATTERNS = [
  [/INTO\s+OUTFILE|INTO\s+DUMPFILE/i, '服务端写文件'],
  [/\bLOAD_FILE\s*\(/i, '任意文件读'],
  [/\bpg_read_file\s*\(|\blo_import\s*\(|\bpg_ls_dir\s*\(/i, 'PG 文件读/目录列举'],
  [/\bATTACH\s+DATABASE\b/i, 'SQLite 建库写文件'],
  [/\bload_extension\s*\(/i, '加载原生扩展（任意代码执行）'],
  [/\bxp_cmdshell\b/i, 'OS 命令执行'],
  [/\bsp_execute_external_script\b/i, '外部脚本执行'],
  [/\bsp_configure\b/i, '修改服务器配置'],
  [/\bxp_regread\b/i, '读取注册表'],
  [/\bTO\s+PROGRAM\b/i, 'PG COPY TO PROGRAM 命令执行'],
  [/\bOPENROWSET\s*\(/i, '外连第三方数据库'],
  [/\bxp_dirtree\b|\bxp_fileexist\b/i, 'UNC 路径外连'],
  [/\bdblink_connect\s*\(/i, 'PG 外连'],
  [/\bUTL_HTTP\b/i, 'Oracle HTTP 外连'],
  [/\bGET_LOCK\s*\(/i, '命名锁阻塞业务'],
  [/\bBENCHMARK\s*\(\s*\d{5,}/i, '硬编码大次数 BENCHMARK（CPU 耗尽）'],
  // SQLite 无原生 SLEEP，RANDOMBLOB 重运算是合法的延迟替代（clause.level2.test.js 同口径）。
  // 仅拦截 >=50MB 的极端规模 —— 已远超探测级开销且不受 {SLEEP} 配置控制。
  [/\bRANDOMBLOB\s*\(\s*[5-9]\d{7,}|\bRANDOMBLOB\s*\(\s*\d{9,}/i, '超大 RANDOMBLOB（>=50MB）'],
];

// 任何真实域名/主机都不允许出现在默认池（外连必须走 {CALLBACK} 占位符）
const HARDCODED_HOST = /\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|cn|ru|xyz|top|info)\b/i;

function iteratePayloads() {
  const out = [];
  for (const [dbms, byTech] of Object.entries(PAYLOADS)) {
    for (const [tech, list] of Object.entries(byTech || {})) {
      if (!Array.isArray(list)) continue;
      for (const tpl of list) {
        if (typeof tpl === 'string') out.push({ dbms, tech, tpl });
      }
    }
  }
  return out;
}

describe('payloadSafety · 默认池不含高危向量', () => {
  it('默认池不含写文件/RCE/改配置/DoS 类高危模式', () => {
    const hits = [];
    for (const { dbms, tech, tpl } of iteratePayloads()) {
      for (const [re, label] of FORBIDDEN_PATTERNS) {
        if (re.test(tpl)) hits.push(`${dbms}.${tech} [${label}] ${tpl.slice(0, 70)}`);
      }
    }
    assert.equal(
      hits.length,
      0,
      `默认池出现 ${hits.length} 条高危 payload（应移入 destructive.js）：\n` + hits.join('\n')
    );
  });

  it('默认池不含硬编码外连域名（外连须用 {CALLBACK} 占位符）', () => {
    const hits = [];
    for (const { dbms, tech, tpl } of iteratePayloads()) {
      if (HARDCODED_HOST.test(tpl)) hits.push(`${dbms}.${tech} ${tpl.slice(0, 80)}`);
    }
    assert.equal(hits.length, 0, `默认池硬编码外连域名：\n${hits.join('\n')}`);
  });
});

describe('payloadSafety · 时间模板延迟关键字（防回归）', () => {
  it('MySQL/PG/SQLServer 的 time 模板均含对应延迟关键字', () => {
    const kw = { MySQL: 'SLEEP', PostgreSQL: 'pg_sleep', 'SQL Server': 'WAITFOR' };
    for (const [db, k] of Object.entries(kw)) {
      for (const p of PAYLOADS[db].time) {
        assert.ok(p.includes(k), `${db} time 缺 ${k}: ${p}`);
      }
    }
  });

  it('time 模板不使用低于默认判定阈值的硬编码短延时', () => {
    // timeThresholdMs 默认 1500ms；硬编码 0.5s 之类的短延时必然低于阈值 → 时间盲注系统性漏判
    for (const { dbms, tpl } of iteratePayloads()) {
      // 取模板里第一个延时字面量；跳过 0（CASE ... ELSE pg_sleep(0) 的假分支，延时 0 是正确的）
      const matches = [...tpl.matchAll(/(?:SLEEP|pg_sleep|DBMS_LOCK\.SLEEP)\(\s*([0-9.]+)\s*\)/gi)]
        .map((m) => Number(m[1]))
        .filter((n) => Number.isFinite(n) && n > 0);
      if (!matches.length) continue;
      const minPositive = Math.min(...matches);
      assert.ok(
        minPositive >= 1,
        `${dbms} time 硬编码延时 ${minPositive}s 低于默认阈值，应改用 {SLEEP} 占位符：${tpl.slice(0, 70)}`
      );
    }
  });
});

describe('payloadSafety · 高危池门控', () => {
  it(`risk < ${DESTRUCTIVE_MIN_RISK} 时拒绝启用高危池`, () => {
    assert.throws(
      () => enableDestructivePayloads({}, 1),
      /拒绝启用高危 payload 池/
    );
    assert.throws(
      () => enableDestructivePayloads({}, DESTRUCTIVE_MIN_RISK - 1),
      /拒绝启用高危 payload 池/
    );
  });

  it('risk>=3 时启用，且合并幂等（不重复追加）', () => {
    const fake = { MySQL: { time: ['A'] } };
    const first = enableDestructivePayloads(fake, 3);
    const afterFirst = first.MySQL.time.length;
    assert.ok(afterFirst > 1, '启用后应合并进高危模板');
    enableDestructivePayloads(fake, 3);
    assert.equal(fake.MySQL.time.length, afterFirst, '重复启用不得重复追加');
  });

  it('高危池的外连向量使用 {CALLBACK} 占位符，不硬编码域名', () => {
    const hits = [];
    for (const [dbms, byTech] of Object.entries(DESTRUCTIVE_PAYLOADS)) {
      for (const [tech, list] of Object.entries(byTech)) {
        for (const tpl of list) {
          if (HARDCODED_HOST.test(tpl)) hits.push(`${dbms}.${tech} ${tpl.slice(0, 70)}`);
        }
      }
    }
    assert.equal(hits.length, 0, `高危池仍硬编码域名：\n${hits.join('\n')}`);
  });

  it('getDestructiveTemplates 可按库/技术读取，未知库返回空数组', () => {
    assert.ok(getDestructiveTemplates('MySQL', 'time').length > 0);
    assert.deepEqual(getDestructiveTemplates('不存在的库', 'time'), []);
    assert.ok(getDestructiveTemplates('MySQL').length > 0);
  });
});
