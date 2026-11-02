// [P1-CFG 2026-11-02] 默认值单一真源守门：
//   · 引擎 defaults / CLI parseArgs / 前端生成 JSON 必须与 sharedDefaults.js 一致；
//   · 任何一端手写默认值造成漂移，本测试当场红。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SHARED_SCAN_DEFAULTS } from '../src/config/sharedDefaults.js';
import { defaults } from '../src/config/defaults.js';
import { parseArgs } from '../bin/cli/args.js';

const ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const GENERATED = JSON.parse(readFileSync(resolve(ROOT, 'src/shared/scanDefaults.generated.json'), 'utf8'));

test('前端生成物 = 服务端 sharedDefaults', () => {
  assert.deepEqual(GENERATED, { ...SHARED_SCAN_DEFAULTS });
});

test('引擎 defaults 的共享键 = sharedDefaults', () => {
  for (const [k, v] of Object.entries(SHARED_SCAN_DEFAULTS)) {
    assert.equal(defaults[k], v, `defaults.${k} 与 sharedDefaults 漂移`);
  }
});

test('CLI parseArgs 默认速率/并发 = sharedDefaults', () => {
  const args = parseArgs([]);
  assert.equal(args.ratePerSec, SHARED_SCAN_DEFAULTS.ratePerSec);
  assert.equal(args.concurrencyDet, SHARED_SCAN_DEFAULTS.concurrency);
});

test('新配置键默认值：pocRedactAuth=true / confirmFormWrites=false', () => {
  assert.equal(defaults.pocRedactAuth, true);
  assert.equal(defaults.confirmFormWrites, false);
  assert.equal(parseArgs([]).pocRedactAuth, true);
  assert.equal(parseArgs([]).confirmFormWrites, false);
  assert.equal(parseArgs(['--no-poc-redact-auth']).pocRedactAuth, false);
  assert.equal(parseArgs(['--confirm-form-writes']).confirmFormWrites, true);
});
