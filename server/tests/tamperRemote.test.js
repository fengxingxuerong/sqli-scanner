// tamperBypassDemo 远程模式授权护栏测试：缺失 --authorized 时必须拒绝运行
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const execFileP = promisify(execFile);
const script = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'scripts',
  'tamperBypassDemo.mjs'
);

test('远程模式缺少 --authorized 时拒绝运行并提示授权', async () => {
  try {
    await execFileP('node', [script, '--url', 'http://example.com/x'], { timeout: 15000 });
    assert.fail('应因缺少授权而拒绝运行');
  } catch (e) {
    assert.notEqual(e.code ?? 0, 0);
    assert.match(e.stderr || '', /授权|authorized/i);
  }
});
