// [D46 2026-10-11 对标 sqlmap] 运维侦察枚举（-b/--statements/--procs）+ -U/--exclude 过滤单测。
// 覆盖四层：方言目录形状（null=诚实降级）→ Extractor 方法 → extractScope 模式分发与过滤 →
// CLI/REST 两侧接线。SQL 执行用假 extractor（_enumScalar 不触网），钉的是接线与过滤语义。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, isEnumMode, buildExtractScope, validateEnumArgs } from '../bin/cli.js';
import { STATEMENTS_QUERY, PROCS_QUERY } from '../src/engine/extraction/sysQueries.js';
import { VERSION_EXPR } from '../src/engine/extractionMaps.js';
import { extractByScope } from '../src/engine/extractScope.js';
import { sanitizeExtractScope } from '../src/api/scanGuard/extractScope.js';
import { Extractor } from '../src/engine/Extractor.js';

// ===== 方言目录形状 =====
test('方言目录：statements/procs 覆盖 18 方言，SQLite 与模板适配层为 null（诚实降级），主库形态完整', () => {
  const MAIN = ['MySQL', 'MariaDB', 'TiDB', 'PostgreSQL', 'SQL Server', 'Oracle'];
  for (const [name, dict] of [['statements', STATEMENTS_QUERY], ['procs', PROCS_QUERY]]) {
    assert.equal(Object.keys(dict).length, 18, `${name} 应覆盖 18 方言`);
    for (const db of MAIN) {
      assert.equal(typeof dict[db], 'string', `${name}.${db} 应有查询`);
      assert.ok(/LIMIT 20|TOP 20|ROWNUM <= 20|LIMIT 100|TOP 100|ROWNUM <= 100/.test(dict[db]), `${name}.${db} 必须带硬上界：${dict[db]}`);
    }
    for (const db of ['SQLite', 'H2', 'Derby', 'MonetDB']) {
      assert.equal(dict[db], null, `${name}.${db} 应为 null（结构性不支持）`);
    }
  }
});

test('方言目录：banner 复用 VERSION_EXPR（主库有表达式，SQLite 亦有 scalar）', () => {
  assert.equal(typeof VERSION_EXPR.MySQL, 'string');
  assert.ok(/version/i.test(VERSION_EXPR.MySQL) || /@@/.test(VERSION_EXPR.MySQL));
});

// ===== Extractor 方法（_enumScalar 打桩，不触网）=====
test('Extractor：enumerateBanner/Statements/Procs 按方言取目录，null 目录返回 null', async () => {
  const ex = new Extractor();
  const sent = [];
  ex._enumScalar = async (ctx, q, opts) => { sent.push(q); return q ? 'SCALAR' : (opts?.fallback ?? null); };
  const banner = await ex.enumerateBanner({ dbms: 'MySQL' });
  assert.equal(banner, 'SCALAR');
  assert.ok(/version/i.test(sent[0]) || /@@/.test(sent[0]));
  const stmts = await ex.enumerateStatements({ dbms: 'PostgreSQL' });
  assert.equal(stmts, 'SCALAR');
  assert.ok(sent[1].includes('pg_stat_activity'));
  // 结构性不支持：SQLite 的 statements 目录为 null → 诚实降级
  const none = await ex.enumerateStatements({ dbms: 'SQLite' });
  assert.equal(none, null);
  // 未知方言：目录全键覆盖，取 null 目录 → null（不投 MySQL 语法赌运气）
  const unknown = await ex.enumerateProcs({ dbms: 'NotADB' });
  assert.equal(unknown, null);
  const procs = await ex.enumerateProcs({ dbms: 'SQL Server' });
  assert.equal(procs, 'SCALAR');
  assert.ok(String(sent[4]).includes('INFORMATION_SCHEMA.ROUTINES')); // sent[3] 是 NotADB 那次（null）
});

// ===== extractScope 模式分发 + 过滤（假 extractor）=====
function fakeSm({ users, passwords, dbs }) {
  return {
    extractor: {
      enumerateUsers: async () => users ?? null,
      enumeratePasswords: async () => passwords ?? null,
      enumerateDatabases: async () => dbs ?? [],
      enumerateTables: async () => ['t1'],
      enumerateColumns: async () => ['c1'],
      enumerateBanner: async () => '8.0.36',
      enumerateStatements: async () => '12:SELECT 1',
      enumerateProcs: async () => 'app.p1(PROCEDURE)',
    },
  };
}
const ctx = { target: { config: {} }, dbms: 'MySQL' };

test('extractScope：banner/statements/procs 三模式分发到对应 extractor 字段', async () => {
  const sm = fakeSm({});
  const b = await extractByScope(sm, 's1', ctx, { mode: 'banner' });
  assert.equal(b.banner, '8.0.36');
  const s = await extractByScope(sm, 's1', ctx, { mode: 'statements' });
  assert.equal(s.statements, '12:SELECT 1');
  const p = await extractByScope(sm, 's1', ctx, { mode: 'procs' });
  assert.equal(p.procs, 'app.p1(PROCEDURE)');
});

test('extractScope：-U 用户过滤（user@host 与 user:hash 两种条目形态、大小写不敏感、无匹配得空串）', async () => {
  const sm = fakeSm({
    users: 'root@localhost,APP@%,admin@127.0.0.1',
    passwords: 'root@localhost:*HEX1,APP@%:*HEX2,admin@127.0.0.1:*HEX3',
  });
  const u = await extractByScope(sm, 's1', ctx, { mode: 'users', user: 'app' });
  assert.equal(u.users, 'APP@%');
  const p = await extractByScope(sm, 's1', ctx, { mode: 'passwords', user: 'ADMIN@127.0.0.1' });
  assert.equal(p.passwords, 'admin@127.0.0.1:*HEX3');
  // 密码条目无 host 形态（user:hash）也应命中
  const sm2 = fakeSm({ passwords: 'root:HEX1,app:HEX2' });
  const p2 = await extractByScope(sm2, 's1', ctx, { mode: 'passwords', user: 'App' });
  assert.equal(p2.passwords, 'app:HEX2');
  const miss = await extractByScope(sm, 's1', ctx, { mode: 'users', user: 'ghost' });
  assert.equal(miss.users, '');
});

test('extractScope：--exclude 排除指定库（与系统库过滤正交，点名排除优先于 excludeSysdbs=false）', async () => {
  const sm = fakeSm({ dbs: ['mysql', 'information_schema', 'appdb', 'noisydb'] });
  const d1 = await extractByScope(sm, 's1', ctx, { mode: 'dbs', excludeDbs: ['NoisyDB'] });
  assert.deepEqual(d1.databases, ['appdb']); // 系统库照排 + noisydb 点名排除
  const d2 = await extractByScope(sm, 's1', ctx, { mode: 'dbs', excludeDbs: ['appdb'], excludeSysdbs: false });
  // excludeSysdbs=false → mysql/information_schema 留下；appdb 仍被点名排除（正交语义）
  assert.deepEqual(d2.databases, ['mysql', 'information_schema', 'noisydb']);
});

// ===== CLI 接线 =====
test('CLI：-b/--statements/--procs 进枚举模式；-U/--exclude 挂到 extractScope', () => {
  assert.equal(isEnumMode(parseArgs(['--banner'])), true);
  assert.equal(isEnumMode(parseArgs(['--statements'])), true);
  assert.equal(isEnumMode(parseArgs(['--procs'])), true);
  const s1 = buildExtractScope(parseArgs(['-b']));
  assert.equal(s1.mode, 'banner');
  const s2 = buildExtractScope(parseArgs(['--procs']));
  assert.equal(s2.mode, 'procs');
  const s3 = buildExtractScope(parseArgs(['--users', '-U', 'app', '--exclude', 'a,b,c']));
  assert.equal(s3.mode, 'users');
  assert.equal(s3.user, 'app');
  assert.deepEqual(s3.excludeDbs, ['a', 'b', 'c']);
});

test('CLI：-U 不配 --users/--passwords → validateEnumArgs 拒绝；配了通过', () => {
  assert.ok(validateEnumArgs(parseArgs(['-U', 'app'])).includes('-U'));
  assert.equal(validateEnumArgs(parseArgs(['--users', '-U', 'app'])), null);
  assert.equal(validateEnumArgs(parseArgs(['--passwords', '-U', 'app'])), null);
});

// ===== REST 闸 =====
test('REST：extractScope 新模式 + user/excludeDbs 形状闸（junk 丢弃、clamp 生效）', () => {
  const ok = sanitizeExtractScope({ mode: 'banner' });
  assert.equal(ok.mode, 'banner');
  const filtered = sanitizeExtractScope({ mode: 'users', user: '  app  ', excludeDbs: ['a', 'b', ''] });
  assert.equal(filtered.user, 'app');
  assert.deepEqual(filtered.excludeDbs, ['a', 'b']);
  const junk = sanitizeExtractScope({ mode: 'drop tables' });
  assert.equal(junk, undefined);
  const clamp = sanitizeExtractScope({ mode: 'passwords', user: 'x'.repeat(300) });
  assert.equal(clamp.user, undefined); // 超长整体丢弃（形状闸语义）
});
