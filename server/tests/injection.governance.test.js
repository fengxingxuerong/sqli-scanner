// ============================================================================
// tests/injection.governance.test.js —— 治理参数在「非检测阶段」也必须生效
// [P0-FIX 2026-09-09]
//
// 为什么需要：`--delay` / `--reqrate` / `--max-requests` 是「别把客户系统打挂、别把自己送进黑名单」
// 的刹车，不是性能旋钮。原实现只在 Detector.send 里透传，sendInjection（指纹 / 预筛选 / 盲注提取 /
// 二阶触发页等 13 个调用点共用）漏传 → 请求量最大的长尾阶段反而全速裸奔，且用户完全看不出来。
// forceSsl / ignoreRedirects 漏传则会让同一注入点「检测看到的响应」与「提取看到的响应」不是同一个。
// ============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sendInjection } from '../src/engine/injection.js';
import { defaults } from '../src/config/defaults.js';

function capture() {
  const seen = [];
  return {
    seen,
    client: { async request(opts) { seen.push(opts); return { status: 200, data: 'ok', headers: {} }; } },
  };
}

const TARGET = {
  mode: 'http',
  baseUrl: 'http://shop.example.com/item?id=1',
  method: 'GET',
  bodyParams: {},
  cookieParams: {},
  headerParams: {},
};
const POINT = { id: 'p1', location: 'url', param: 'id', originalValue: '1' };

test('sendInjection 透传治理三键（delay/reqRate/maxReq）到出口层', async () => {
  const { seen, client } = capture();
  const config = { ...defaults, delay: 2, reqRate: 1, maxReq: 500 };
  await sendInjection(client, { config, target: TARGET }, { method: 'GET', url: 'http://shop.example.com/item?id=1' });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].delay, 2, '--delay 必须在提取/指纹阶段也生效');
  assert.equal(seen[0].reqRate, 1, '--reqrate 必须在提取/指纹阶段也生效');
  assert.equal(seen[0].maxReq, 500, '--max-requests 上限必须在所有阶段一致');
});

test('sendInjection 透传协议两键（forceSsl/ignoreRedirects）', async () => {
  const { seen, client } = capture();
  const config = { ...defaults, forceSsl: true, ignoreRedirects: true };
  await sendInjection(client, { config, target: TARGET }, { method: 'GET', url: 'http://shop.example.com/item?id=1' });
  assert.equal(seen[0].forceSsl, true);
  assert.equal(seen[0].ignoreRedirects, true);
});

test('未配置时保持显式 false/0：与「不传」在出口层等价，零回归', async () => {
  const { seen, client } = capture();
  await sendInjection(client, { config: { ...defaults }, target: TARGET }, { method: 'GET', url: 'http://shop.example.com/item?id=1' });
  assert.equal(seen[0].delay, 0);
  assert.equal(seen[0].reqRate, 0);
  assert.equal(seen[0].maxReq, 0);
  assert.equal(seen[0].forceSsl, false);
  assert.equal(seen[0].ignoreRedirects, false);
});

test('与 Detector.send 的透传集合不再漂移（同源契约）', async () => {
  // 取两处实际写入 opts 的 config 键集合，比较差集：sendInjection 不得少于 Detector.send
  const { readFileSync } = await import('node:fs');
  const grab = (file, marker) => {
    const src = readFileSync(file, 'utf8');
    const start = src.indexOf(marker);
    const body = src.slice(start, src.indexOf('});', start));
    return new Set(Array.from(body.matchAll(/^\s*([A-Za-z0-9_]+):/gm)).map((m) => m[1]));
  };
  const det = grab(new URL('../src/engine/Detector.js', import.meta.url), 'async send(httpClient, ctx, req, opts = {})');
  const inj = grab(new URL('../src/engine/injection.js', import.meta.url), 'export async function sendInjection');
  // 只比对「治理/协议/网络」类键，检测阶段专有的 networkTiming（纯测量用途）不要求对齐
  const GOVERNED = ['timeoutMs', 'retry', 'proxy', 'auth', 'wafEvasion', 'delay', 'reqRate', 'maxReq', 'forceSsl', 'ignoreRedirects'];
  const missing = GOVERNED.filter((k) => det.has(k) && !inj.has(k));
  assert.deepEqual(missing, [], `sendInjection 相比 Detector.send 少了这些出口层键：${missing.join(', ')}`);
});
