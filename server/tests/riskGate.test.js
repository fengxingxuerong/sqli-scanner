// --risk 分级门控测试（对标 sqlmap --risk）
//
// 覆盖：
//  1) validateRiskGate 纯函数：三类高风险技术阈值 / 缺省=1 / 取值范围 / 默认放行
//  2) CLI 集成：--risk 不足启用二阶注入 → 被门控拦截（exit!=0 + 提示 risk），不发任何请求
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateRiskGate, RISK_MIN, MIN_RISK, MAX_RISK } from '../src/engine/riskGate.js';

// ===== 1. 纯函数 =====
test('RISK_MIN 常量：二阶/堆查询=2，带外=3', () => {
  assert.equal(RISK_MIN.second_order, 2);
  assert.equal(RISK_MIN.stacked, 2);
  assert.equal(RISK_MIN.oob, 3);
});

test('validateRiskGate: risk 1 + 二阶注入 → 拦截', () => {
  assert.throws(
    () => validateRiskGate({ risk: 1, secondOrder: { enabled: true } }),
    /risk/i
  );
});

test('validateRiskGate: risk 1 + stacked 技术 → 拦截', () => {
  assert.throws(
    () => validateRiskGate({ risk: 1, techniques: ['union', 'stacked'] }),
    /risk/i
  );
});

test('validateRiskGate: risk 1 + oob 技术 → 拦截', () => {
  assert.throws(
    () => validateRiskGate({ risk: 1, techniques: ['oob'] }),
    /risk/i
  );
});

test('validateRiskGate: risk 2 + 二阶注入 → 放行', () => {
  assert.equal(validateRiskGate({ risk: 2, secondOrder: { enabled: true } }), true);
});

test('validateRiskGate: risk 2 + stacked 技术 → 放行', () => {
  assert.equal(validateRiskGate({ risk: 2, techniques: ['stacked'] }), true);
});

test('validateRiskGate: risk 2 + oob 技术 → 仍拦截（需 3）', () => {
  assert.throws(
    () => validateRiskGate({ risk: 2, techniques: ['oob'] }),
    /risk/i
  );
});

test('validateRiskGate: risk 3 + oob 技术 → 放行', () => {
  assert.equal(validateRiskGate({ risk: 3, techniques: ['oob'] }), true);
});

test('validateRiskGate: risk 缺省（undefined）+ stacked → 按 1 拦截', () => {
  assert.throws(
    () => validateRiskGate({ techniques: ['stacked'] }),
    /risk/i
  );
});

test('validateRiskGate: risk 越界（0 / 4）→ 拦截', () => {
  assert.throws(() => validateRiskGate({ risk: 0, techniques: ['stacked'] }), /1-3/);
  assert.throws(() => validateRiskGate({ risk: 4, techniques: ['stacked'] }), /1-3/);
});

test('validateRiskGate: risk 1 + 默认一阶技术（无高风险）→ 放行', () => {
  assert.equal(
    validateRiskGate({ risk: 1, techniques: ['union', 'error', 'boolean', 'time'] }),
    true
  );
});

test('validateRiskGate: risk 1 + 二阶注入未启用（enabled:false）→ 放行', () => {
  assert.equal(validateRiskGate({ risk: 1, secondOrder: { enabled: false } }), true);
});

// ===== 2. CLI 集成（门控拦截，不发请求）=====
test('CLI: --risk 1 启用二阶注入 → 被门控拦截（exit!=0 + 提示 risk）', (t, done) => {
  const cliPath = fileURLToPath(new URL('../cli.js', import.meta.url));
  const args = [
    cliPath,
    '-u', 'http://127.0.0.1:1/?id=1',
    '--second-order', 'http://127.0.0.1:1/trigger',
    '--risk', '1',
  ];
  execFile(process.execPath, args, { timeout: 30000 }, (err, stdout, stderr) => {
    try {
      // 被拦截：进程以非零退出
      assert.ok(err, '门控应拦截并以非零退出');
      const out = `${stdout}\n${stderr}`;
      assert.ok(/risk/i.test(out), `输出应提示 risk 门控，实际：\n${out}`);
      done();
    } catch (e) {
      done(e);
    }
  });
});
