// ============================================================================
// server/tests/poc.encodedCarrier.test.js
//
// 编码态载体的**交付面**判据（[A2 2026-10-06]）。
// 为什么单独一支：引擎做对了 ≠ 交付件说清了。PoC 的 `payload` 字段是解码后的语义形态，
// 而 url/curl/raw 是重编码后的线上形态 —— 不标注，读者拿 `payload` 直接发就打不中，
// 还会把"引擎做对了"读成"PoC 少了一步"（本项目反复在治的「声明与真值分处两地」同族）。
//
// 变异自证：把 pocBuilder.js 里 `if (point && point.encoding)` 那条 note 摘掉 ⇒ ① 的红。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildPocEvidence } from '../src/engine/pocBuilder.js';
import { createTarget } from '../src/engine/models.js';

const PAYLOAD = "alice' UNION SELECT 1,2,3-- -";

test('① base64url 点：curl/raw/url 必须是重编码后的线上形态，note 必须说清两种形态', () => {
  const target = createTarget({ url: 'http://lab/b64url?user=YWxpY2U', config: {} });
  const point = { location: 'url', param: 'user', originalValue: 'alice', rawValue: 'YWxpY2U', encoding: 'base64url' };
  const poc = buildPocEvidence(target, point, PAYLOAD);
  const wire = Buffer.from(PAYLOAD, 'utf8').toString('base64url');

  // 线上形态：url / curl / raw 三处都必须是编码后的串，且不得出现明文 payload 里的引号形态
  assert.ok(poc.url.includes(wire), `url 应带编码后的值 ${wire}，实际：${poc.url}`);
  assert.ok(poc.curl.includes(wire), `curl 应带编码后的值，实际：${poc.curl}`);
  assert.ok(poc.raw.includes(wire), 'raw 应带编码后的值');
  assert.ok(!poc.curl.includes(PAYLOAD), 'curl 里不该出现未编码的语义 payload');

  // 语义形态保留在 payload 字段（引擎据此构造），且 note 明确指路
  assert.equal(poc.payload, PAYLOAD);
  assert.match(poc.note, /base64url/, `note 应点明编码形态，实际：${poc.note}`);
  assert.match(poc.note, /payload 是解码后的语义形态/);
  assert.match(poc.note, /复现请直接用 curl\/raw/);
});

test('② 非编码点零行为变化（回归）：不插编码说明', () => {
  const target = createTarget({ url: 'http://lab/str?name=alice', config: {} });
  const point = { location: 'url', param: 'name', originalValue: 'alice' };
  const poc = buildPocEvidence(target, point, PAYLOAD);
  // 按 URLSearchParams 的线上编码比"参数值解回来等于语义 payload"，
  // 不去断言具体的百分号/加号写法（那是编码器的细节，不是本判据要钉的东西）
  assert.equal(new URL(poc.url).searchParams.get('name'), PAYLOAD);
  assert.doesNotMatch(poc.note, /base64|以 .* 传输/);
});

test('③ base64（标准字母表）同样标注，且编码串与语义串不互换', () => {
  const target = createTarget({ url: 'http://shop/b64?id=MQ==', config: {} });
  const point = { location: 'url', param: 'id', originalValue: '1', rawValue: 'MQ==', encoding: 'base64' };
  const poc = buildPocEvidence(target, point, '1 AND 1=1');
  const wire = Buffer.from('1 AND 1=1', 'utf8').toString('base64');
  assert.ok(poc.url.includes(encodeURIComponent(wire)) || poc.url.includes(wire), `实际：${poc.url}`);
  assert.equal(poc.payload, '1 AND 1=1');
  assert.match(poc.note, /以 base64 传输/);
});
