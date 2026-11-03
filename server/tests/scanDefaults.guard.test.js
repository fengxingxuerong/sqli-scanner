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
import { buildGuardedConfig } from '../src/api/scanConfigGuard.js';
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

// [P1-CFG 2026-11-02] REST 缺省不再是硬编码 false：临时改 defaults 单源，
// 断言 buildGuardedConfig({}) 跟着变（旧实现 `!!cfg.enableExtract` 会恒为 false）。
test('REST 缺省 enableExtract 跟随 defaults 单源（缺省/显式两路）', () => {
  const scope = { enabled: false };
  const original = defaults.enableExtract;
  try {
    defaults.enableExtract = true;
    assert.equal(buildGuardedConfig({}, scope).enableExtract, true, '缺省应取 defaults，而非硬编码 false');
  } finally {
    defaults.enableExtract = original;
  }
  assert.equal(buildGuardedConfig({}, scope).enableExtract, SHARED_SCAN_DEFAULTS.enableExtract);
  assert.equal(buildGuardedConfig({ enableExtract: false }, scope).enableExtract, false, '显式 false 必须保留');
  assert.equal(buildGuardedConfig({ enableExtract: true }, scope).enableExtract, true, '显式 true 必须保留');
});
