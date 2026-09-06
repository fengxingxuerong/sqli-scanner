// P2-S11 会话续跑：sanitizeStart 对 sessionDefault 布尔透传（前端「会话续跑」开关 → API → 引擎）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeStart } from '../src/api/scanRoutes.js';

function start(cfg) {
  return sanitizeStart({
    url: 'http://127.0.0.1:9999/x?id=1',
    method: 'GET',
    config: cfg || {},
  });
}

test('sessionDefault：true/false 原样落入 config，缺省不写入', () => {
  assert.equal(start({ sessionDefault: true }).config.sessionDefault, true);
  assert.equal(start({ sessionDefault: false }).config.sessionDefault, false);
  assert.equal(start({}).config.sessionDefault, undefined); // 缺省不写，引擎沿用 defaults(false)
});
