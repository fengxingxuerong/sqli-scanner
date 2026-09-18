// [P0-SEC 2026-09-18 / A4] sqlmap `--eval` 门控
// 背景：--eval 会把调用方给的字符串当 **Python 表达式在服务端执行**（sqlmap 自身特性）。
// 旧实现只打一条 warn 就放行 —— 无鉴权部署下，任何能打到 HTTP 的人都等于拿到代码执行。
// 现在双条件门控：SQLMAP_ALLOW_EVAL=1 **且** 引擎已启用 API 鉴权；不满足直接拒绝。
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildArgs } from '../src/engine/sqlmapBridge.js';
import { setAuthEnabled, _resetAuthStateForTest } from '../src/core/apiAuthState.js';

// 注意：evalCode 位于 config.sqlmap 命名空间下（见 sqlmapBridge.buildArgs：`input.config.sqlmap`），
// 不是 config 顶层——写错命名空间会让门控静默失效（本地踩过）。
const baseInput = () => ({
  target: { url: 'http://example.com/item?id=1' },
  config: {},
});

function withEnv(env, fn) {
  const saved = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test('默认（未设 SQLMAP_ALLOW_EVAL）→ 拒绝 --eval，且错误信息给出启用条件', () => {
  _resetAuthStateForTest();
  withEnv({ SQLMAP_ALLOW_EVAL: undefined }, () => {
    assert.throws(
      () => buildArgs({ ...baseInput(), config: { sqlmap: { evalCode: "import os; os.system('id')" } } }),
      (e) => e.message.includes('sqlmap --eval 未启用') && e.message.includes('SQLMAP_ALLOW_EVAL=1')
    );
  });
});

test('开了开关但引擎未启用鉴权 → 仍拒绝（否则任何人可提交表达式）', () => {
  _resetAuthStateForTest();
  withEnv({ SQLMAP_ALLOW_EVAL: '1' }, () => {
    assert.throws(
      () => buildArgs({ ...baseInput(), config: { sqlmap: { evalCode: 'x=1' } } }),
      (e) => e.message.includes('需要引擎已启用 API 鉴权') && e.message.includes('SCAN_API_TOKEN')
    );
  });
});

test('开关 + 鉴权同时满足 → 透传 --eval（保留告警语义）', () => {
  _resetAuthStateForTest();
  setAuthEnabled(true);
  withEnv({ SQLMAP_ALLOW_EVAL: '1' }, () => {
    const args = buildArgs({ ...baseInput(), config: { sqlmap: { evalCode: 'pwd="x"' } } });
    assert.ok(args.includes('--eval'), '应包含 --eval');
    assert.equal(args[args.indexOf('--eval') + 1], 'pwd="x"');
  });
  _resetAuthStateForTest();
});

test('不传 evalCode 时不受门控影响（常规扫描路径不变）', () => {
  _resetAuthStateForTest();
  withEnv({ SQLMAP_ALLOW_EVAL: undefined }, () => {
    const args = buildArgs(baseInput());
    assert.ok(!args.includes('--eval'));
    assert.ok(args.includes('--batch'));
  });
});
