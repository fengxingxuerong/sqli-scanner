// [P1-SAFE 2026-11-02] 自动发现表单的写请求门控：
//   · confirmFormWrites 默认 false → POST 表单不建点；
//   · 确认后仍默认跳过 logout/delete/remove/update 等高风险 action；
//   · 跳过原因写入 target.formDiscoveryGate，供 summary.constraints 显式披露。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TargetParser } from '../src/engine/TargetParser.js';
import { createTarget } from '../src/engine/models.js';

function parserFor(html) {
  return new TargetParser({ async request() { return { data: html, status: 200 }; } });
}

test('confirmFormWrites 默认 false：POST 表单不建点，并登记跳过原因', async () => {
  const html = '<form method="POST" action="/login"><input name="username" value="a"></form>';
  const target = createTarget({ url: 'http://x.com/p', method: 'GET', config: { level: 1, crawlForms: true } });
  const points = await parserFor(html).discover(target);
  assert.equal(points.filter((p) => p.formMethod === 'POST').length, 0);
  assert.equal(target.formDiscoveryGate.skipped, 1);
  assert.equal(target.formDiscoveryGate.items[0].reason, 'form-writes-unconfirmed');
});

test('confirmFormWrites=true：普通 POST 表单恢复建点', async () => {
  const html = '<form method="POST" action="/login"><input name="username" value="a"></form>';
  const target = createTarget({
    url: 'http://x.com/p', method: 'GET',
    config: { level: 1, crawlForms: true, confirmFormWrites: true },
  });
  const points = await parserFor(html).discover(target);
  assert.equal(points.filter((p) => p.formMethod === 'POST').length, 1);
  assert.equal(target.formDiscoveryGate, undefined);
});

test('高风险 action 即使确认也跳过（POST /logout）', async () => {
  const html = '<form method="POST" action="/logout"><input name="next" value="/"></form>';
  const target = createTarget({
    url: 'http://x.com/p', method: 'GET',
    config: { level: 1, crawlForms: true, confirmFormWrites: true },
  });
  const points = await parserFor(html).discover(target);
  assert.equal(points.filter((p) => p.formMethod === 'POST').length, 0);
  assert.equal(target.formDiscoveryGate.items[0].reason, 'high-risk-action');
});

test('高风险 action 对 GET 表单同样生效（/delete?id=1）', async () => {
  const html = '<form method="GET" action="/delete"><input name="id" value="1"></form>';
  const target = createTarget({
    url: 'http://x.com/p', method: 'GET',
    config: { level: 1, crawlForms: true, confirmFormWrites: true },
  });
  const points = await parserFor(html).discover(target);
  assert.equal(points.some((p) => p.param === 'id'), false);
  assert.equal(target.formDiscoveryGate.items[0].reason, 'high-risk-action');
});

test('普通 GET 表单不受 confirmFormWrites 影响', async () => {
  const html = '<form method="GET" action="/search"><input name="q" value=""></form>';
  const target = createTarget({ url: 'http://x.com/p', method: 'GET', config: { level: 1, crawlForms: true } });
  const points = await parserFor(html).discover(target);
  assert.equal(points.filter((p) => p.formMethod === 'GET').length, 1);
});
