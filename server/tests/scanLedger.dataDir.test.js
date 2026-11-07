// [DATADIR 2026-11-05] 台账数据目录默认解析 + 优先级链单测。
//
// 背景（真实缺陷）：SEA 单文件引擎里 import.meta.url 指向 exe 自身，
// 原默认 `pathResolve(HERE, '../../data/ledger')` 变成 <exe 上两级>/data/ledger ——
// 绿色包把 data/ 建到了解压目录**外面**，装 Program Files 时还会因无写权限写失败。
// 本文件锁三件事：
//   ① SEA 形态默认 <exe 目录>/data/ledger；node 跑源码形态**不变**（防止有人改 SEA 分支时把 node 一起改，
//      那会落到 node.exe 所在目录，比原缺陷更严重）。
//   ② 优先级：--data-dir（setLedgerDirOverride） > SQLI_LEDGER_DIR > 形态默认值。
//   ③ --data-dir 传相对路径按**当前工作目录**解析（不按 exe 目录、不按模块目录）。
import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import {
  defaultLedgerDir, setLedgerDirOverride, _resetLedgerDirOverride, ledgerRoot,
} from '../src/services/scanLedger.js';

const OLD_ENV = process.env.SQLI_LEDGER_DIR;
let tmpRoot;

beforeEach(() => {
  _resetLedgerDirOverride();
  if (OLD_ENV === undefined) delete process.env.SQLI_LEDGER_DIR;
  else process.env.SQLI_LEDGER_DIR = OLD_ENV;
  tmpRoot = mkdtempSync(join(tmpdir(), 'sqli-datadir-'));
});

afterEach(() => {
  _resetLedgerDirOverride();
  if (OLD_ENV === undefined) delete process.env.SQLI_LEDGER_DIR;
  else process.env.SQLI_LEDGER_DIR = OLD_ENV;
  rmSync(tmpRoot, { recursive: true, force: true });
});

test('SEA 形态默认落到 exe 目录下的 data/ledger', () => {
  const exe = resolve(tmpRoot, 'portable', 'sqli-engine.exe');
  const got = defaultLedgerDir({ isSea: true, execPath: exe });
  assert.equal(got, resolve(dirname(exe), 'data', 'ledger'));
});

test('node 跑源码形态保持模块上两级，且绝不等于 exe 目录', () => {
  const moduleDir = resolve(tmpRoot, 'repo', 'server', 'src', 'services');
  const got = defaultLedgerDir({ isSea: false, moduleDir });
  assert.equal(got, resolve(moduleDir, '..', '..', 'data', 'ledger'));
  // 防回归：SEA 分支不能污染 node 形态（否则会写到 node.exe 所在目录）
  const seaLike = defaultLedgerDir({ isSea: true, execPath: resolve(tmpRoot, 'node.exe') });
  assert.notEqual(got, seaLike);
});

test('优先级：--data-dir > SQLI_LEDGER_DIR > 默认', () => {
  const envDir = resolve(tmpRoot, 'env-ledger');
  const cliDir = resolve(tmpRoot, 'cli-ledger');
  process.env.SQLI_LEDGER_DIR = envDir;
  assert.equal(ledgerRoot(), envDir);
  setLedgerDirOverride(cliDir);
  assert.equal(ledgerRoot(), cliDir);
});

test('--data-dir 相对路径按当前工作目录解析', () => {
  const oldCwd = process.cwd();
  process.chdir(tmpRoot);
  try {
    // [D267] macOS 的 /var 是指向 /private/var 的符号链接：chdir 之后 process.cwd()
    // 返回解析后的物理路径，与字面 tmpRoot 不同（CI 实测 actual=/private/var/... vs
    // expected=/var/...）。本用例的语义是「相对路径按**当前工作目录**解析」，
    // 所以期望值必须以 chdir 后的 cwd 为准；Windows/Linux 上两者本来就相同。
    const cwdNow = process.cwd();
    setLedgerDirOverride('relative-ledger');
    const got = ledgerRoot();
    assert.equal(got, resolve(cwdNow, 'relative-ledger'));
    assert.ok(existsSync(got), '目录不存在时应按既有逻辑创建');
  } finally {
    process.chdir(oldCwd);
  }
});
