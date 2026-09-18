// [P0-SEC 2026-09-18 / A5] 会话落盘敏感值封存
// 背景：sessions/*.json 的 points[].originalValue 是注入点原始参数值；当注入点是
// Cookie / 认证头时它等同于会话凭据，且 compose 把 sessions 目录挂在 named volume 上。
// 取向：不打码（会破坏断点续跑），改为**落盘加密 + 读盘解密**——内存保持明文。
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  sealSecret, openSecret, isSealed, secretKeySource, _resetSecretKeyForTest,
} from '../src/core/sessionSecret.js';
import { ScanSession } from '../src/core/sessionStore.js';

async function withEnv(env, fn) {
  const saved = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  _resetSecretKeyForTest();
  try {
    // 必须 await：否则异步用例会在 env 恢复之后才真正执行（密文用错 key 解，断言偶然通过）
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    _resetSecretKeyForTest();
  }
}

test('封存/解封往返：普通串、中文、长串、含冒号与换行', async () => {
  await withEnv({ SCAN_SESSION_KEY: 'unit-test-key' }, () => {
    for (const v of ['1', 'session=abc123; role=admin', '中文值:带冒号', 'x'.repeat(4096), 'a\nb']) {
      const sealed = sealSecret(v);
      assert.ok(isSealed(sealed), '应为封存形态');
      assert.notEqual(sealed, v);
      assert.ok(!String(sealed).includes(v.slice(0, 8)) || v.length < 8, '密文不应包含明文片段');
      assert.equal(openSecret(sealed), v);
    }
  });
});

test('幂等：已封存的值再次封存不变（避免二次加密后无法还原）', async () => {
  await withEnv({ SCAN_SESSION_KEY: 'k' }, () => {
    const once = sealSecret('secret');
    assert.equal(sealSecret(once), once);
  });
});

test('非字符串/空值原样返回（不制造无意义密文）', async () => {
  await withEnv({ SCAN_SESSION_KEY: 'k' }, () => {
    assert.equal(sealSecret(''), '');
    assert.equal(sealSecret(undefined), undefined);
    assert.equal(sealSecret(null), null);
    assert.equal(openSecret('plain-value'), 'plain-value'); // 兼容加密上线前的旧会话
  });
});

test('密钥来源优先级：SCAN_SESSION_KEY > SCAN_API_TOKEN > 进程随机', async () => {
  await withEnv({ SCAN_SESSION_KEY: 'a', SCAN_API_TOKEN: 'b' }, () => {
    assert.equal(secretKeySource(), 'env:SCAN_SESSION_KEY');
  });
  await withEnv({ SCAN_SESSION_KEY: undefined, SCAN_API_TOKEN: 'b' }, () => {
    assert.equal(secretKeySource(), 'derived:SCAN_API_TOKEN');
  });
  await withEnv({ SCAN_SESSION_KEY: undefined, SCAN_API_TOKEN: undefined }, () => {
    assert.equal(secretKeySource(), 'process-random');
    // 进程随机 key 本进程内仍可往返
    assert.equal(openSecret(sealSecret('v')), 'v');
  });
});

test('换 key 后解不开 → 返回 null（由调用方降级处理，不抛异常）', async () => {
  const sealed = await withEnv({ SCAN_SESSION_KEY: 'key-A' }, () => sealSecret('top-secret'));
  await withEnv({ SCAN_SESSION_KEY: 'key-B' }, () => {
    assert.equal(openSecret(sealed), null);
  });
});

test('会话落盘：文件里不含明文，读回后内存仍是明文（断点续跑不受影响）', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sqli-session-secret-'));
  const file = join(dir, 'sqli-session-case.json');
  try {
      await withEnv({ SCAN_SESSION_KEY: 'unit-key' }, async () => {
      const s = new ScanSession('case1', { url: 'http://lab.local/items?cat=1' }, file);
      await s.setPoints([
        { id: 'p1', location: 'cookie', param: 'SESSION', originalValue: 'SESSIONID=abc123secret' },
        { id: 'p2', location: 'url', param: 'cat', originalValue: '1' },
      ]);
      // 落盘内容：不得出现明文凭据
      const raw = readFileSync(file, 'utf-8');
      assert.ok(!raw.includes('abc123secret'), '会话文件不应包含明文 Cookie 值');
      assert.ok(raw.includes('enc:v1:'), '应有封存前缀');
      // 读回：内存语义不变
      const loaded = await ScanSession.load(file);
      assert.equal(loaded.points[0].originalValue, 'SESSIONID=abc123secret');
      assert.equal(loaded.points[1].originalValue, '1');
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('旧明文会话仍可读入；换 key 的会话该点降级为 pending（不崩、不发错误请求）', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sqli-session-legacy-'));
  const file = join(dir, 'sqli-session-legacy.json');
  try {
    // ① 加密上线前的旧格式（明文 originalValue）
    writeFileSync(file, JSON.stringify({
      scanId: 'legacy', url: 'http://lab.local/a?id=1',
      points: [{ id: 'p1', location: 'url', param: 'id', originalValue: '1' }],
      perPoint: { p1: { status: 'done', found: [], extracted: false } },
    }), 'utf-8');
    const legacy = await withEnv({ SCAN_SESSION_KEY: 'any' }, () => ScanSession.load(file));
    assert.equal(legacy.points[0].originalValue, '1', '旧明文应原样读入');

    // ② 用 key-A 写，再用 key-B 读 → 该点解不开，应被降级为 pending
    await withEnv({ SCAN_SESSION_KEY: 'key-A' }, async () => {
      const s = new ScanSession('rekey', { url: 'http://lab.local/a?id=1' }, file);
      await s.setPoints([{ id: 'p9', location: 'cookie', param: 'S', originalValue: 'SESS=deadbeef' }]);
      s.perPoint.p9 = { status: 'done', found: [], extracted: false };
      await s.finalize({ riskLevel: 'High', finishedAt: new Date().toISOString() });
    });
    const rekeyed = await withEnv({ SCAN_SESSION_KEY: 'key-B' }, () => ScanSession.load(file));
    assert.equal(rekeyed.points[0].originalValue, undefined, '解不开的值不应以密文形态流入扫描');
    assert.equal(rekeyed.perPoint.p9.status, 'pending', '解不开的点应标记为待重扫');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
