// ============================================================================
// tests/ciBenchmarkBuildRetry.guard.test.js —— [D322] Maven 冷构建有限重试的判据
// ============================================================================
// CI #497 实证：mvn -Pdeploy 解析 maven-buildtime-extension:3.0.5 偶发
// `Failed to read artifact descriptor`，artifact 本身 central 200、上轮 #496 success。
// 判据钉住：可重试错误才重试、确定性错误首次即抛、退避可注入、ci-benchmark 真接线。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isTransientBuildError, withBuildRetry } from '../../scripts/lib/buildRetry.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPT = readFileSync(join(REPO, 'scripts', 'ci-benchmark.mjs'), 'utf8');

// #497 job 日志 721-725 行的真实错误形态
const REAL_497 = '[ERROR] Extension co.leantechniques:maven-buildtime-extension:3.0.5 or one of its '
  + 'dependencies could not be resolved: Plugin could not be resolved: '
  + 'Failed to read artifact descriptor for co.leantechniques:maven-buildtime-extension:jar:3.0.5';

function assertBuildRetryWiring(script) {
  assert.match(script, /withBuildRetry\(/, 'build() 未使用 withBuildRetry 有限重试执行器');
  assert.match(script, /await build\(\)/, 'main() 未 await build()，重试会变成后台浮空 Promise');
  assert.match(script, /attempts:\s*3/, '重试次数未定在 attempts: 3（有限重试，不可无限）');
}

test('D322-1) #497 真失败文本判可重试；确定性编译错误判不可重试', () => {
  assert.equal(isTransientBuildError(REAL_497), true);
  assert.equal(isTransientBuildError('Downloading from central: ... Failed to read artifact descriptor'), true);
  assert.equal(isTransientBuildError('[ERROR] COMPILATION ERROR : cannot find symbol'), false);
  assert.equal(isTransientBuildError(''), false);
});

test('D322-2) transient 两次后成功：真跑 3 次，退避可注入且递增', async () => {
  const calls = [];
  const naps = [];
  const out = await withBuildRetry((i) => {
    calls.push(i);
    if (i < 3) throw new Error(REAL_497);
    return 'built';
  }, { attempts: 3, backoffMs: 10, sleep: async (ms) => { naps.push(ms); } });
  assert.equal(out, 'built');
  assert.deepEqual(calls, [1, 2, 3]);
  assert.deepEqual(naps, [10, 20]);
});

test('D322-3) 确定性错误首次即抛，绝不重试洗绿', async () => {
  const calls = [];
  await assert.rejects(withBuildRetry(() => {
    calls.push(1);
    throw new Error('[ERROR] COMPILATION ERROR : cannot find symbol');
  }, { attempts: 3, sleep: async () => {} }), /COMPILATION ERROR/);
  assert.equal(calls.length, 1);
});

test('D322-4) 三次全 transient 仍失败：次数用尽后抛最后一次错误', async () => {
  let n = 0;
  await assert.rejects(withBuildRetry(() => {
    n += 1;
    throw new Error(REAL_497);
  }, { attempts: 3, sleep: async () => {} }), /Failed to read artifact descriptor/);
  assert.equal(n, 3);
});

test('D322-5) 真 ci-benchmark.mjs 的 build() 与 main() 接线齐备', () => {
  assertBuildRetryWiring(SCRIPT);
});

test('D322-6) 反例自证：去掉重试或漏 await 必须判红', () => {
  assert.throws(() => assertBuildRetryWiring(
    SCRIPT.replace('withBuildRetry(', 'skipRetry(')), /withBuildRetry/);
  assert.throws(() => assertBuildRetryWiring(
    SCRIPT.replace('await build();', 'build();')), /await build/);
  assert.throws(() => assertBuildRetryWiring(
    SCRIPT.replace('attempts: 3,', 'attempts: 99,')), /attempts: 3/);
});
