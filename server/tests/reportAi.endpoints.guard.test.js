// [D254 2026-11-05] key ↔ 端点配对判据（双网关真实 LLM 实测后的适配面）
//
// 修前：run.mjs 把 KEY_1/2/3 全设成同一个 key、且只有一个 AI_REPORT_API_BASE，
// 429 后「跨角色降级」等于同一网关原地等 60s ⇒ 三角色连环失败。
// 证据：docs/llm-gateway-capability-2026-11-05.txt
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveEndpoints } from '../src/services/ReportAI.js';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const MAIN = 'http://gw-a/v1/chat/completions';

test('单网关：三个角色全部回落主端点（生产行为零变化）', () => {
  assert.deepEqual(resolveEndpoints({ AI_REPORT_API_BASE: MAIN }), [MAIN, MAIN, MAIN]);
});

test('双网关：_2 生效、_3 未配回落主端点', () => {
  const b2 = 'http://gw-b/v1/chat/completions';
  assert.deepEqual(resolveEndpoints({ AI_REPORT_API_BASE: MAIN, AI_REPORT_API_BASE_2: b2 }), [MAIN, b2, MAIN]);
});

test('缺陷注入复验：移除 _2 后 writer 回到主网关（判据不是恒绿）', () => {
  const b2 = 'http://gw-b/v1/chat/completions';
  assert.equal(resolveEndpoints({ AI_REPORT_API_BASE: MAIN, AI_REPORT_API_BASE_2: b2 })[1], b2);
  assert.equal(resolveEndpoints({ AI_REPORT_API_BASE: MAIN })[1], MAIN);
});

test('三端点全配：按 key 索引严格对齐', () => {
  const b2 = 'http://gw-b/v1/chat/completions';
  const b3 = 'http://gw-c/v1/chat/completions';
  assert.deepEqual(resolveEndpoints({ AI_REPORT_API_BASE: MAIN, AI_REPORT_API_BASE_2: b2, AI_REPORT_API_BASE_3: b3 }), [MAIN, b2, b3]);
});

test('未配主 base → 全空（opt-in 关闭，绝不静默外发第三方）', () => {
  assert.deepEqual(resolveEndpoints({}), ['', '', '']);
});

test('接线：验收套件必须注入 _2/_3 与推理模型参数（防只改 ReportAI 一半）', () => {
  const src = readFileSync(path.join(REPO, 'e2e/ai-gateway-lab/run.mjs'), 'utf8');
  for (const key of [
    'AI_REPORT_API_BASE_2', 'AI_REPORT_API_BASE_3',
    'AI_REPORT_MAX_TOKENS', 'AI_REPORT_429_COOLDOWN_MS', 'AI_GATEWAY_URL_2',
  ]) {
    assert.ok(src.includes(key), `run.mjs 未接线 ${key} —— 双网关分担不会生效`);
  }
});
