// ============================================================================
// server/tests/echoStrip.escapeVariant.test.js —— 回显剔除的「转义变体」契约
//
// 背景（2026-09-23）：`stripEchoedPayload` 曾有两个版本，能力**不等价**：
//   · 强版（ErrorDetector 私有副本）：5 个剔除变体，含 SQL 转义 `' → ''` 与反斜杠转义
//   · 弱版（echoStrip 共享版）：只有 3 个变体，剔不掉转义型回显
// 走弱版的是主判据链（边界探测 / 布尔比对 / 定库）→ 同一个 P0 只修了报错通道。
// 现已把变体集合上提到 echoStrip.js 作为唯一实现，本文件把「必须剔干净」钉死。
//
// ⚠️ 本项目纪律：断言必须**敏感**。故 §B 特意用弱版实现跑同一输入，证明
//    「剔不干净」时这条断言真的会红 —— 否则它可能只是碰巧通过。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { stripEchoedPayload, normalizeEcho } from '../src/engine/echoStrip.js';

/** 2026-09-23 统一前的弱版实现，仅用于证明 §A 的断言敏感（不是生产代码） */
function weakStrip(body, payload) {
  let t = normalizeEcho(body);
  const variants = new Set([String(payload), normalizeEcho(payload)]);
  try {
    variants.add(encodeURIComponent(payload));
  } catch { /* noop */ }
  for (const v of variants) {
    if (v && v.length > 3) t = t.split(v).join('');
  }
  return t;
}

const PAYLOAD = "alice' AND extractvalue(1,concat(0x7e,version()))-- -";

// §A 强契约：三种转义型回显都必须剔干净
test('§A SQL 转义回显（单引号翻倍）必须被剔除', () => {
  const escaped = PAYLOAD.replace(/'/g, "''");
  const body = `<div class="err">no results for ${escaped}</div>`;
  const out = stripEchoedPayload(body, PAYLOAD);
  assert.ok(!out.includes('extractvalue'), `回显未被剔干净：${out}`);
  assert.ok(!out.includes('alice'), `原文残留：${out}`);
});

test('§A 反斜杠转义回显必须被剔除', () => {
  const escaped = PAYLOAD.replace(/'/g, "\\'");
  const body = `Query failed near '${escaped}' at line 1`;
  const out = stripEchoedPayload(body, PAYLOAD);
  assert.ok(!out.includes('extractvalue'), `反斜杠转义回显未被剔干净：${out}`);
});

test('§A HTML 实体 + URL 编码混合回显（原始 P0 场景）必须被剔除', () => {
  const htmlish = encodeURIComponent(PAYLOAD).replace(/%27/g, '&#39;');
  const body = `Cannot GET /api/safe/error${htmlish}`;
  const out = stripEchoedPayload(body, PAYLOAD);
  assert.ok(!out.includes('extractvalue'), `混合编码回显未被剔干净：${out}`);
});

// §B 断言敏感性：弱版在同一批输入上必须**剔不掉**，否则 §A 是空转的
test('§B 断言敏感性：弱版（缺转义变体）在同一输入上必须仍然含 payload 关键词', () => {
  const escaped = PAYLOAD.replace(/'/g, "''");
  const body = `<div class="err">no results for ${escaped}</div>`;
  const weakOut = weakStrip(body, PAYLOAD);
  assert.ok(
    weakOut.includes('extractvalue'),
    '弱版竟也剔干净了 —— 说明 §A 的断言对「有没有转义变体」不敏感，是假绿，需要重建样本'
  );
  const strongOut = stripEchoedPayload(body, PAYLOAD);
  assert.notEqual(strongOut.length, weakOut.length, '强弱版输出应不同（否则说明两者已经等价，本文件失去意义）');
});

// §C 反向：真报错来自数据库，与 payload 原文不是同一串，不得被误删
test('§C 真报错文本不得被剔除（避免替出假阴性）', () => {
  const body = `<b>error</b> You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version`;
  const out = stripEchoedPayload(body, PAYLOAD);
  assert.ok(out.includes('You have an error in your SQL syntax'), `真实报错被误删：${out}`);
  assert.ok(out.includes('MySQL'), `真实报错上下文被误删：${out}`);
});

// §D 边界：payload 为空时不得抛错、不得返回 undefined（ErrorDetector 私有版的旧语义是「返回原文」，
//    统一后改为「返回归一化后的 body」；调用点 payload 恒非空，此处只钉住不崩与类型）
test('§D 空 payload 时不抛错且返回字符串', () => {
  const out = stripEchoedPayload('<p>x</p>', '');
  assert.equal(typeof out, 'string');
  assert.ok(out.includes('x'));
  assert.equal(stripEchoedPayload('', PAYLOAD), '');
});
