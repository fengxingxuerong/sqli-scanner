import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeStart } from '../src/api/scanRoutes.js';

const base = (config) => ({ url: 'http://t/?id=1', config: config || {} });

test('oob 开启：透传 enabled/callbackBase/httpPort/timeoutMs', () => {
  const out = sanitizeStart(base({
    techniques: ['oob'],
    risk: 3,
    oob: { enabled: true, callbackBase: 'your.domain', httpPort: 9999, timeoutMs: 8000 },
  }));
  assert.equal(out.config.oob.enabled, true);
  assert.equal(out.config.oob.callbackBase, 'your.domain');
  assert.equal(out.config.oob.httpPort, 9999);
  assert.equal(out.config.oob.timeoutMs, 8000);
});

test('oob 缺省字段回退默认值', () => {
  const out = sanitizeStart(base({ oob: { enabled: true } }));
  assert.equal(out.config.oob.callbackBase, '127.0.0.1:8899');
  assert.equal(out.config.oob.httpPort, 8899);
  assert.equal(out.config.oob.timeoutMs, 5000);
});

test('oob httpPort 越界回退 8899', () => {
  const out = sanitizeStart(base({ oob: { enabled: true, httpPort: 99999 } }));
  assert.equal(out.config.oob.httpPort, 8899);
});

test('oob timeoutMs 越界回退 5000', () => {
  const out = sanitizeStart(base({ oob: { enabled: true, timeoutMs: 10 } }));
  assert.equal(out.config.oob.timeoutMs, 5000);
});

test('oob 未传 → config 不含 oob（零回归）', () => {
  const out = sanitizeStart(base({}));
  assert.equal(out.config.oob, undefined);
});
