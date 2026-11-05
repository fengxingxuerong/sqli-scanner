// [D253 2026-11-05] 单目标扫描退出码判据（外部裁判靶场实测抓出的假绿回归面）
//
// 修前实测：`--param-filter=path` 删光注入点 → 引擎日志 `[错误]`，cli.js 与
// one-click-scan.mjs 却都 exit 0，还产出 0 洞报告。证据见
// docs/cli-compat-external-labs-2026-11-05.txt。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanExitCode, scanExecutionError } from '../src/services/scanExit.js';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const makeReport = (riskLevel, summary = {}) => ({ riskLevel, summary });

test('正常报告：Critical/High → 2，Medium/Low/无报告 → 0', () => {
  assert.equal(scanExitCode(makeReport('Critical')), 2);
  assert.equal(scanExitCode(makeReport('High')), 2);
  assert.equal(scanExitCode(makeReport('Medium')), 0);
  assert.equal(scanExitCode(makeReport('Low')), 0);
  assert.equal(scanExitCode(null), 0);
});

test('缺陷注入复验：executionError 存在时优先判 1，即使 riskLevel 是 High', () => {
  const failed = makeReport('High', { executionError: { code: 'INVALID_PARAM', message: '--param-filter=path 没有匹配到任何注入点' } });
  assert.equal(scanExitCode(failed), 1);
  assert.match(scanExecutionError(failed), /没有匹配到任何注入点/);
  // 把缺陷注回去（移除错误标记）必须回到 2 —— 证明判据不是恒绿
  assert.equal(scanExitCode(makeReport('High')), 2);
});

test('executionError 形态兼容 + 无失败返回 null', () => {
  assert.equal(scanExecutionError(makeReport('Low')), null);
  assert.equal(scanExecutionError(makeReport('Low', { executionError: 'boom' })), 'boom');
  assert.equal(scanExecutionError(makeReport('Low', { executionError: { code: 'E42' } })), 'E42');
  assert.equal(scanExitCode(makeReport('Low', { executionError: 'boom' })), 1);
});

test('接线：cli.js 与 one-click-scan.mjs 都必须走同一判据（防只修一条入口）', () => {
  for (const rel of ['server/bin/cli.js', 'scripts/one-click-scan.mjs']) {
    const src = readFileSync(path.join(REPO, rel), 'utf8');
    assert.match(src, /services\/scanExit\.js/, `${rel} 未引用 scanExit.js —— 该入口会继续假绿`);
  }
});
