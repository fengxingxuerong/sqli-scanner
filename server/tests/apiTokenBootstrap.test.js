// [P0-SEC 2026-09-17] 默认鉴权护栏（A2）
// 背景：本服务可对任意可达目标发起扫描与拖库。旧实现「没配 token 就不装鉴权中间件」，
// 而 Dockerfile 是 HOST=0.0.0.0 且未设 token → 直接 docker run 就是一个无鉴权的扫描代理。
// 本测试锁死 fail-closed 行为与 token 解析优先级，防止后续提交把护栏悄悄改回去。
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveApiToken } from '../index.js';

test('回环监听且未配置 → 允许无鉴权（本地/桌面体验），source=none', () => {
  const r = resolveApiToken({ host: '127.0.0.1', env: {} });
  assert.deepEqual(r, { token: '', source: 'none' });
  const r2 = resolveApiToken({ host: 'localhost', env: {} });
  assert.equal(r2.token, '');
});

test('显式 SCAN_API_TOKEN → 生效，source=env', () => {
  const r = resolveApiToken({ host: '127.0.0.1', env: { SCAN_API_TOKEN: 'tok-1' } });
  assert.deepEqual(r, { token: 'tok-1', source: 'env' });
});

test('SCAN_API_TOKEN_FILE 优先于 SCAN_API_TOKEN（Docker/K8s secret 场景）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sqli-token-'));
  const file = join(dir, 'scan_token');
  writeFileSync(file, 'file-token\n', 'utf-8'); // 尾随换行必须被 trim
  const r = resolveApiToken({ host: '127.0.0.1', env: { SCAN_API_TOKEN_FILE: file, SCAN_API_TOKEN: 'env-token' } });
  assert.deepEqual(r, { token: 'file-token', source: 'file' });
});

test('非回环监听且无 token → 拒绝启动（fail-closed，给出修复指引）', () => {
  assert.throws(
    () => resolveApiToken({ host: '0.0.0.0', env: {} }),
    (e) => e.message.includes('拒绝以无鉴权方式监听') && e.message.includes('SCAN_API_TOKEN')
  );
  // 显式逃生口才可放行
  const r = resolveApiToken({ host: '0.0.0.0', env: { SCAN_API_ALLOW_NO_TOKEN: '1' } });
  assert.deepEqual(r, { token: '', source: 'none-explicit' });
});

test('非回环 + 有 token → 正常通过', () => {
  const r = resolveApiToken({ host: '0.0.0.0', env: { SCAN_API_TOKEN: 'prod-tok' } });
  assert.deepEqual(r, { token: 'prod-tok', source: 'env' });
});

test('SCAN_API_TOKEN_EMIT=1（桌面 sidecar）：生成 64 hex 且进程内幂等', () => {
  const a = resolveApiToken({ host: '127.0.0.1', env: { SCAN_API_TOKEN_EMIT: '1' } });
  const b = resolveApiToken({ host: '127.0.0.1', env: { SCAN_API_TOKEN_EMIT: '1' } });
  assert.equal(a.source, 'generated');
  assert.match(a.token, /^[a-f0-9]{64}$/);
  // 幂等是硬要求：否则「打印给壳的 token」与「鉴权用的 token」会是两个（已在联调中踩到）
  assert.equal(a.token, b.token);
});
