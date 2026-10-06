// ============================================================================
// tests/sessionSecret.keySource.test.js —— 会话密钥来源口径必须与鉴权口径一致
// ============================================================================
// ── 防的是什么 ───────────────────────────────────────────────────────────────
// sessionSecret（会话落盘封存）的密钥来源，与 index.js 的 resolveApiToken（API 鉴权）
// 是**同一个 token 的两种读法**。两处各读一套，就必然漂移——
// 这与 EXPLOIT_ENABLED 那次分叉（REST 认 `1/true`、CLI 只认 `1`）是同一族缺陷。
//
// 实测到的具体分歧（2026-10-05 修正）：
//   resolveApiToken 的优先级是 **SCAN_API_TOKEN_FILE > SCAN_API_TOKEN > （无）**；
//   而 secretKeySource 只读 process.env.SCAN_API_TOKEN，**完全无视 _FILE**。
//
// 后果落在容器部署的**官方推荐路径**上：
//   docker-compose.yml / Dockerfile 都把 `SCAN_API_TOKEN_FILE=/run/secrets/scan_token`
//   列为正式方案②（K8s/Docker secret 的标准做法）；
//   按它部署 ⇒ secretKeySource 落到 `process-random`
//   ⇒ 容器重启后**所有已落盘会话都解不开**，注入点被标为"待重扫"。
// 症状是「续跑功能随机失效」，而且**没有任何报错**——降级路径本就设计成静默。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolveApiToken } from '../index.js';
import { secretKeySource, sealSecret, openSecret, _resetSecretKeyForTest } from '../src/core/sessionSecret.js';

/** 在一个干净 env 快照下运行 fn，结束后恢复 */
function withEnv(vars, fn) {
  const prev = {};
  for (const k of ['SCAN_SESSION_KEY', 'SCAN_API_TOKEN', 'SCAN_API_TOKEN_FILE']) {
    prev[k] = process.env[k];
    if (vars[k] === undefined) delete process.env[k];
    else process.env[k] = vars[k];
  }
  _resetSecretKeyForTest();
  try {
    return fn();
  } finally {
    for (const k of ['SCAN_SESSION_KEY', 'SCAN_API_TOKEN', 'SCAN_API_TOKEN_FILE']) {
      if (prev[k] === undefined) delete process.env[k];
      else process.env[k] = prev[k];
    }
    _resetSecretKeyForTest();
  }
}

function tmpTokenFile(content) {
  const dir = mkdtempSync(join(tmpdir(), 'session-secret-'));
  const p = join(dir, 'token');
  writeFileSync(p, content);
  return { p, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

test('口径-1) 只配 SCAN_API_TOKEN_FILE 时，密钥来源必须仍是派生（不得降级为进程随机）', () => {
  const { p, cleanup } = tmpTokenFile('file-token-value');
  try {
    withEnv({ SCAN_API_TOKEN_FILE: p, SCAN_API_TOKEN: undefined, SCAN_SESSION_KEY: undefined }, () => {
      assert.equal(secretKeySource(), 'derived:SCAN_API_TOKEN',
        '只配 _FILE 时降级成 process-random ⇒ 容器重启后续跑全失效（本测试的核心）');
    });
  } finally {
    cleanup();
  }
});

test('口径-2) 与 resolveApiToken 的优先级一致：_FILE 优先于 env', () => {
  const { p, cleanup } = tmpTokenFile('file-token-value');
  try {
    withEnv({ SCAN_API_TOKEN_FILE: p, SCAN_API_TOKEN: 'env-token', SCAN_SESSION_KEY: undefined }, () => {
      const auth = resolveApiToken({ host: '127.0.0.1', env: process.env });
      assert.equal(auth.token, 'file-token-value', '鉴权侧应读 _FILE');
      assert.equal(auth.source, 'file', '鉴权侧来源应为 file');
      assert.equal(secretKeySource(), 'derived:SCAN_API_TOKEN',
        '封存侧也必须认定"有可用 token"，否则与鉴权侧对同一个部署的判断不一致');
    });
  } finally {
    cleanup();
  }
});

test('口径-3) SCAN_SESSION_KEY 仍是最高优先级（不被本次改动动摇）', () => {
  withEnv({ SCAN_SESSION_KEY: 'explicit-key', SCAN_API_TOKEN: 'env-token' }, () => {
    assert.equal(secretKeySource(), 'env:SCAN_SESSION_KEY');
  });
});

test('口径-4) 三者都无 ⇒ process-random（兜底语义不变，且不抛错）', () => {
  withEnv({ SCAN_SESSION_KEY: undefined, SCAN_API_TOKEN: undefined, SCAN_API_TOKEN_FILE: undefined }, () => {
    assert.equal(secretKeySource(), 'process-random');
  });
});

test('行为-5) _FILE 路径下封存→解封可往返（且模拟"重启"后仍可解）', () => {
  const { p, cleanup } = tmpTokenFile('file-token-value');
  try {
    let sealed;
    withEnv({ SCAN_API_TOKEN_FILE: p, SCAN_API_TOKEN: undefined, SCAN_SESSION_KEY: undefined }, () => {
      sealed = sealSecret('Cookie: admin=secret-session');
      assert.ok(String(sealed).startsWith('enc:v1:'), '应落盘为密文');
      assert.equal(openSecret(sealed), 'Cookie: admin=secret-session', '同进程内应可解');
    });
    // 模拟进程重启：清除密钥缓存但保持同一 _FILE 配置
    withEnv({ SCAN_API_TOKEN_FILE: p, SCAN_API_TOKEN: undefined, SCAN_SESSION_KEY: undefined }, () => {
      assert.equal(openSecret(sealed), 'Cookie: admin=secret-session',
        '重启后应仍可解 —— 前提是密钥来自 _FILE 派生而非进程随机');
    });
  } finally {
    cleanup();
  }
});

test('容错-6) _FILE 指向不存在的路径时退回 env，不抛错', () => {
  const missing = join(tmpdir(), 'definitely-not-here-', 'token');
  withEnv({ SCAN_API_TOKEN_FILE: missing, SCAN_API_TOKEN: 'env-token', SCAN_SESSION_KEY: undefined }, () => {
    assert.equal(secretKeySource(), 'derived:SCAN_API_TOKEN', '读不到 _FILE 应退回 env');
    const sealed = sealSecret('x');
    assert.equal(openSecret(sealed), 'x');
  });
});

test('容错-7) _FILE 存在但内容为空 ⇒ 退回 env（与 resolveApiToken 同语义）', () => {
  const { p, cleanup } = tmpTokenFile('   \n');
  try {
    withEnv({ SCAN_API_TOKEN_FILE: p, SCAN_API_TOKEN: 'env-token', SCAN_SESSION_KEY: undefined }, () => {
      assert.equal(secretKeySource(), 'derived:SCAN_API_TOKEN', '空文件应视为未提供');
    });
  } finally {
    cleanup();
  }
});