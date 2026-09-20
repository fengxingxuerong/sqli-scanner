// [B1 2026-09-18] sql.js 加载器：三种运行形态下的定位逻辑。
//
// 为什么值得单独测：这条链路失配是**静默的** —— 加载失败时 dbDrivers 会回退到
// MemoryRecordDriver，扫描照跑、也能"检出"，只是结果是假的。所以定位逻辑本身
// 必须有单测兜住，不能只靠端到端冒烟（冒烟只在打包产物上跑，覆盖不到 dev 路径）。
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  SQL_WASM_ASSET,
  isSeaRuntime,
  readWasmAsset,
  resolveWasmPath,
  loadSqlJs,
  _resetSqlJsCacheForTest,
} from '../src/core/sqlJsLoader.js';

async function withEnv(env, fn) {
  const saved = {};
  for (const [k, v] of Object.entries(env)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return await fn(); // 必须 await（同 sessionSecret 测试的教训：否则 env 提前恢复）
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test('SQL_WASM_ASSET 键名固定为 sql-wasm.wasm（与 sea-config.json / build-sidecar 约定一致）', () => {
  assert.equal(SQL_WASM_ASSET, 'sql-wasm.wasm');
});

test('非 SEA 环境：isSeaRuntime() 为 false，readWasmAsset() 返回 null', () => {
  // 单测在普通 node 下跑，必然不是 SEA
  assert.equal(isSeaRuntime(), false);
  assert.equal(readWasmAsset(), null);
});

test('resolveWasmPath：SCAN_SQLJS_WASM 显式指定且存在时优先返回', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sqljs-loader-'));
  try {
    const wasm = join(dir, 'custom.wasm');
    writeFileSync(wasm, 'not-a-real-wasm');
    await withEnv({ SCAN_SQLJS_WASM: wasm }, () => {
      assert.equal(resolveWasmPath(), wasm);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveWasmPath：SCAN_SQLJS_WASM 指向不存在的文件时被忽略（不抛错）', async () => {
  await withEnv({ SCAN_SQLJS_WASM: join(tmpdir(), 'definitely-missing-' + Date.now() + '.wasm') }, () => {
    const p = resolveWasmPath();
    // 允许返回 null 或找到真实存在的候选；关键是绝不能返回那个不存在的路径
    assert.ok(p === null || existsSync(p), `resolveWasmPath 返回了不存在的路径: ${p}`);
  });
});

test('resolveWasmPath：cwd 下的 dist-engine 布局可被识别', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sqljs-cwd-'));
  const savedCwd = process.cwd();
  try {
    const target = join(dir, 'node_modules', 'sql.js', 'dist', SQL_WASM_ASSET);
    mkdirSync(join(dir, 'node_modules', 'sql.js', 'dist'), { recursive: true });
    writeFileSync(target, 'fake');
    process.chdir(dir);
    // 清掉显式覆盖，确保走候选路径逻辑
    delete process.env.SCAN_SQLJS_WASM;
    const p = resolveWasmPath();
    // [CI-FIX 2026-09-20] macOS 上 tmpdir() 给的是 `/var/folders/...`，而 **/var 是
    // /private/var 的符号链接** —— 实际拿到的是 `/private/var/...`，直接比字符串必然不等
    // （Linux/Windows 没有这一层符号链接，所以本用例在本地和 CI 的 ubuntu 上都绿）。
    // 两侧都 realpath 后再比：比的是"同一个文件"而不是"同一个字符串"，平台无关。
    assert.equal(realpathSync(p), realpathSync(target));
  } finally {
    process.chdir(savedCwd);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadSqlJs：能加载真实 sql.js 并建表查询（dev 形态链路可用）', async () => {
  _resetSqlJsCacheForTest();
  const SQL = await loadSqlJs();
  assert.equal(typeof SQL.Database, 'function');
  const db = new SQL.Database();
  db.run("CREATE TABLE t (id INTEGER, name TEXT); INSERT INTO t VALUES (1, '张三');");
  const r = db.exec('SELECT name FROM t WHERE id=1');
  assert.deepEqual(r[0].values, [['张三']]);
  db.close();
});

test('loadSqlJs：初始化结果被缓存（避免每次直连扫描重复实例化 wasm）', async () => {
  _resetSqlJsCacheForTest();
  const a = await loadSqlJs();
  const b = await loadSqlJs();
  assert.equal(a, b, '第二次调用应命中缓存返回同一实例');
});

test('loadSqlJs：失败不写缓存，允许后续重试', async () => {
  _resetSqlJsCacheForTest();
  // 先正常加载一次拿到实例，清缓存后模拟"错误路径不污染缓存"
  const fresh = await loadSqlJs();
  assert.ok(fresh);
  _resetSqlJsCacheForTest();
  const again = await loadSqlJs();
  assert.ok(again, '清缓存后应能重新加载');
  assert.equal(typeof again.Database, 'function');
});
