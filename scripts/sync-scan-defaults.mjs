#!/usr/bin/env node
// ============================================================================
// sync-scan-defaults.mjs —— 把服务端共享默认值同步为前端可导入的 JSON
//
// 单一真源：server/src/config/sharedDefaults.js（SHARED_SCAN_DEFAULTS）。
// 前端 src/shared/constants.ts 只 import 生成物 `scanDefaults.generated.json`，
// 不再手写并发/速率/超时/crawlDepth/enableExtract 等默认值。
//
// 用法：
//   node scripts/sync-scan-defaults.mjs          写文件
//   node scripts/sync-scan-defaults.mjs --check  只校验（不一致 exit 1，供 check:all/CI）
// ============================================================================
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SHARED_SCAN_DEFAULTS } from '../server/src/config/sharedDefaults.js';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const TARGET = resolve(ROOT, 'src/shared/scanDefaults.generated.json');

function render() {
  return JSON.stringify(SHARED_SCAN_DEFAULTS, null, 2) + '\n';
}

const expected = render();
if (process.argv.includes('--check')) {
  try {
    const actual = readFileSync(TARGET, 'utf8');
    if (actual !== expected) {
      console.error('[defaults] ✗ src/shared/scanDefaults.generated.json 与服务端 sharedDefaults.js 不一致');
      console.error('          修法：npm run defaults:sync（不要手改生成物）');
      process.exit(1);
    }
    console.log('[defaults] ✓ 前后端默认值与 server/src/config/sharedDefaults.js 一致');
  } catch (e) {
    console.error(`[defaults] ✗ 读取生成物失败：${e?.message || e}`);
    process.exit(1);
  }
} else {
  writeFileSync(TARGET, expected, 'utf8');
  console.log(`[defaults] ✓ 已生成 ${TARGET}`);
}
