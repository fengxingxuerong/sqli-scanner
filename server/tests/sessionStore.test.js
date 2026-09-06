// sessionStore 单元测试：路径白名单 + 写队列串行化
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'fs';
import path from 'path';
import os from 'os';
import { isSafeSessionPath, ScanSession } from '../src/core/sessionStore.js';

test('isSafeSessionPath 拒绝绝对路径', () => {
  // 不同盘符的 Windows 绝对路径：跨盘相对解析必为绝对 → 拒绝
  assert.equal(isSafeSessionPath('D:\\evil\\secret.txt'), false);
  // POSIX 绝对路径：在 Windows 解析为当前盘绝对路径，相对 tmpdir 必以 .. 开头 → 拒绝
  assert.equal(isSafeSessionPath('/etc/passwd'), false);
  // tmpdir 同盘但更上层的绝对路径：相对 tmpdir 以 .. 开头 → 拒绝
  assert.equal(isSafeSessionPath('C:\\Windows\\System32\\drivers\\etc\\hosts'), false);
});

test('isSafeSessionPath 拒绝 ..', () => {
  // 显式点号段
  assert.equal(isSafeSessionPath('..'), false);
  // 无分隔符但含 .. 片段：走白名单分支，includes('..') 为真 → 拒绝
  assert.equal(isSafeSessionPath('...'), false);
  assert.equal(isSafeSessionPath('foo..bar'), false);
  assert.equal(isSafeSessionPath('a..b'), false);
});

test('isSafeSessionPath 允许合法文件名', () => {
  assert.equal(isSafeSessionPath('sqli-session-latest.json'), true);
  assert.equal(isSafeSessionPath('scan-2024.json'), true);
  assert.equal(isSafeSessionPath('a'), true);
  assert.equal(isSafeSessionPath('report_1.data'), true);
});

test('写队列串行化：并发写入按入队顺序完成、不乱序', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'sess-'));
  const file = path.join(dir, 'session.json');
  try {
    const s = new ScanSession('sid-serial', { url: 'http://x' }, file);
    const order = [];
    // 同步入队多个写操作；串行化保证其完成顺序与入队顺序一致
    const p1 = s
      .setPoints([{ id: 'p1', location: 'url', param: 'id', originalValue: '1' }])
      .then(() => order.push('p1'));
    const p2 = s
      .savePointResult('p1', { found: [{ technique: 'boolean', result: {} }], extracted: false })
      .then(() => order.push('p2'));
    const p3 = s
      .savePointResult('p1', { found: [{ technique: 'union', result: {} }], extracted: true })
      .then(() => order.push('p3'));
    const p4 = s
      .finalize({ riskLevel: 'high', finishedAt: '2024-01-01T00:00:00Z' })
      .then(() => order.push('p4'));
    await Promise.all([p1, p2, p3, p4]);
    // 完成顺序严格等于入队顺序 —— 串行化的直接证据
    assert.deepEqual(order, ['p1', 'p2', 'p3', 'p4']);
    // 最终落盘内容为合法 JSON（未交错损坏）且状态正确
    const raw = await fs.readFile(file, 'utf-8');
    const data = JSON.parse(raw);
    assert.equal(data.scanId, 'sid-serial');
    assert.equal(data.points.length, 1);
    assert.equal(data.perPoint.p1.status, 'done');
    assert.ok(data.completedAt != null);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
