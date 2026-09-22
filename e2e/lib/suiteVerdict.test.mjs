// e2e/lib/suiteVerdict 单测：三态判定 + 「沙箱没起来」的三种形态
// 为什么值得测：这套判据决定「红」是被记到环境头上还是代码头上，
// 判错了会把下一个人引向错误的排障方向（§G / §S 两次都栽在这里）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isSandboxDead, classifySuite } from '../lib/suiteVerdict.mjs';

// ── 三种「沙箱没起来」形态都必须被认出 ──
const SHAPE_INNER = `[sandbox-run] node = node
Traceback (most recent call last):
  File "/repo/e2e/udf-lab/mysql_sandbox.py", line 210, in launch
    raise RuntimeError("mysqld 启动超时 45s")
RuntimeError: mysqld 启动超时 45s`;

const SHAPE_LAUNCHER = `[sandbox-run] node = node
Traceback (most recent call last):
  File "/repo/e2e/run-with-sandbox.py", line 31, in <module>
    import mysql_sandbox
ModuleNotFoundError: No module named 'mysql_sandbox'`;

// CI 容器常见形态：连 python 都没起来 / 缺 mysqld 二进制 —— 无 traceback，**且从未就绪**
const SHAPE_NO_TRACEBACK = `[sandbox-run] node = node
[sandbox-run] entry = e2e/fileops/exploit-file-read.e2e.mjs
[sandbox-run] 沙箱实例已停止`;

test('isSandboxDead：形态①沙箱内部抛错（栈顶在 mysql_sandbox.py）', () => {
  assert.equal(isSandboxDead(SHAPE_INNER), true);
});

test('isSandboxDead：形态②启动器自身 import 失败（旧判据漏检）', () => {
  assert.equal(isSandboxDead(SHAPE_LAUNCHER), true);
});

test('isSandboxDead：形态③无 traceback 且从未就绪（CI 缺 python/mysqld，旧判据漏检）', () => {
  assert.equal(isSandboxDead(SHAPE_NO_TRACEBACK), true);
});

// ⚠️ 反例（最重要的一条）：沙箱**就绪过**、但断言真失败 → 绝不能被贴环境标签。
// 第一版形态③只认 `[sandbox-run]` 前缀 + 无 PASS/SKIP，实测会把这种**真回归掩盖成 BLOCKED**。
const REAL_REGRESSION = `[sandbox-run] node = node
[sandbox-run] 沙箱就绪：127.0.0.1:3308 user=root db=sqli_lab
[scan] 完成：检出 0 个注入点（期望 ≥1）
❌ 断言失败：union 技术位未检出任何注入点
[sandbox-run] 退出码 = 1
[sandbox-run] 沙箱实例已停止`;

test('isSandboxDead：沙箱就绪过 → 不判沙箱死亡（真回归不许被掩盖）', () => {
  assert.equal(isSandboxDead(REAL_REGRESSION), false);
});

test('classifySuite：沙箱就绪过 + 断言失败 → FAIL（不是 BLOCKED）', () => {
  assert.equal(classifySuite({ pass: false, skipped: false }, REAL_REGRESSION, 1).status, 'FAIL');
});

// 真实历史现场（e2e/results/last-failure-oob-real-lab.log）：沙箱就绪，失败原因是 PG 缺失。
// 沙箱没坏 → 不该被形态③ 认领。
const OOB_REAL = `[setup] 初始化 PG oob_lab 库…
Error: connect ECONNREFUSED 127.0.0.1:5432
[sandbox-run] node = node.exe
[mysql-sandbox] 已就绪（2.0s）
[sandbox-run] 沙箱就绪：127.0.0.1:3308 user=root db=sqli_lab
[sandbox-run] 退出码 = 1
[sandbox-run] 沙箱实例已停止`;

test('isSandboxDead：真实历史现场（沙箱就绪、PG 缺失）不判沙箱死亡', () => {
  assert.equal(isSandboxDead(OOB_REAL), false);
});

test('isSandboxDead：正常输出不得误判为沙箱死亡', () => {
  assert.equal(isSandboxDead('[pre] secure_file_priv="" LOAD_FILE 直读=OK\n[PASS] fileRead 闭环'), false);
  assert.equal(isSandboxDead('[SKIP] 当前实例 secure_file_priv 未放行'), false);
  assert.equal(isSandboxDead('随便一段普通输出，没有沙箱前缀'), false);
  assert.equal(isSandboxDead(''), false);
});

// ── classifySuite：三态的优先级与语义 ──
test('classifySuite：断言通过 → PASS', () => {
  assert.equal(classifySuite({ pass: true }, 'whatever', 0).status, 'PASS');
});

test('classifySuite：只跳过未执行断言 → SKIP（不是 PASS，也不进 failed）', () => {
  const r = classifySuite({ pass: true, skipped: true, skipReason: 'secure_file_priv 未放行' }, '[SKIP]', 0);
  assert.equal(r.status, 'SKIP');
  assert.match(r.reason, /secure_file_priv/);
});

test('classifySuite：断言失败 + 沙箱死亡 → BLOCKED（不能记成 FAIL）', () => {
  for (const out of [SHAPE_INNER, SHAPE_LAUNCHER, SHAPE_NO_TRACEBACK]) {
    const r = classifySuite({ pass: false, skipped: false }, out, 1);
    assert.equal(r.status, 'BLOCKED', '三种沙箱死亡形态都应判 BLOCKED');
    assert.match(r.reason, /不是被测代码失败/);
  }
});

test('classifySuite：断言失败且沙箱健在 → FAIL（真红不许被 BLOCKED 掩盖）', () => {
  const r = classifySuite({ pass: false, skipped: false }, '靶场返回 500，断言不通过', 1);
  assert.equal(r.status, 'FAIL');
});

test('classifySuite：SKIP 优先于沙箱判据（跳过是显式声明，不该被改写成 BLOCKED）', () => {
  const r = classifySuite({ pass: true, skipped: true, skipReason: 'x' }, SHAPE_INNER, 0);
  assert.equal(r.status, 'SKIP');
});
