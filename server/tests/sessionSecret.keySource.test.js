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

// ── 令牌材料缓存（2026-10-12 优化空间勘查 §C2）────────────────────────────────
// 原实现在 getKey() 里**先**算 source 才查密钥缓存，而 source 判定本身要读令牌文件
// ⇒ 每个注入点/每次落盘都读一次文件（实测 200 次 sealSecret ⇒ 201 次 readFileSync）。
// 但真正致命的不是性能，而是**稳定性**：source 每次现算，文件一次抖动（权限/挂载瞬断）
// 就让这次 source 变成 process-random ⇒ 与 cachedKeySource 不符 ⇒ 重新派生随机密钥
// ⇒ 此前封存的会话值**全部解不开**，而降级路径本就静默（＝"续跑随机失效"）。
//
// 缓存策略是「只缓存成功结果」：读失败/读到空**不缓存**，保留后续重试的恢复口
// （容器启动早期 secret 尚未挂载完是常态，不能把一次瞬断固化成整个进程降级）。
// 下面两条分别钉这两个方向，缺一条都会让改动退回无覆盖状态。
// ─────────────────────────────────────────────────────────────────────────────
test('缓存-8) 令牌文件读取抖动不得让已封存会话解不开（source 不得退化成 process-random）', () => {
  const { p, cleanup } = tmpTokenFile('file-token-value');
  try {
    withEnv({ SCAN_API_TOKEN_FILE: p, SCAN_API_TOKEN: undefined, SCAN_SESSION_KEY: undefined }, () => {
      assert.equal(secretKeySource(), 'derived:SCAN_API_TOKEN');
      const sealed = sealSecret('Cookie: admin=secret-session');

      // 模拟挂载瞬断：令牌文件在进程运行期间变得不可读
      rmSync(p, { force: true });

      assert.equal(secretKeySource(), 'derived:SCAN_API_TOKEN',
        '文件抖一下就退化成 process-random ⇒ 已封存会话全解不开（续跑静默失效，本测试的核心）');
      assert.equal(openSecret(sealed), 'Cookie: admin=secret-session',
        '抖动前后必须是同一把密钥：已封存值仍要能解');
      assert.notEqual(secretKeySource(), 'process-random');
    });
  } finally {
    cleanup();
  }
});

test('缓存-9) 首次读取失败**不缓存** ⇒ secret 稍后挂载完成后可恢复为派生（不得固化成降级）', () => {
  const dir = mkdtempSync(join(tmpdir(), 'session-secret-late-'));
  const p = join(dir, 'token');
  try {
    withEnv({ SCAN_API_TOKEN_FILE: p, SCAN_API_TOKEN: undefined, SCAN_SESSION_KEY: undefined }, () => {
      // 阶段一：容器刚起来，secret 还没挂上
      assert.equal(secretKeySource(), 'process-random', '挂载前确实是兜底（这一步不是本测试的目标）');
      assert.equal(openSecret(sealSecret('early')), 'early', '进程随机在本进程内仍可往返');

      // 阶段二：secret 挂载完成（同路径出现文件），env 配置本身没变
      writeFileSync(p, 'late-mounted-token');

      assert.equal(secretKeySource(), 'derived:SCAN_API_TOKEN',
        '失败结果不能被缓存：否则一次瞬断会把整个进程永久钉死在 process-random');
      const sealedLate = sealSecret('Cookie: admin=late');
      assert.equal(openSecret(sealedLate), 'Cookie: admin=late', '恢复派生后封存/解封应正常');
      // 说明：阶段一用进程随机封的值此刻解不开是**预期**语义（随机 key 本就跨源不可解），
      // 这里不断言它，避免把设计与缺陷混在一起。
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});