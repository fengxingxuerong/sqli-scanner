// ============================================================================
// tests/audit.test.js —— [D181] 只读安全配置审计的判据
//
// 守的是四件用户感受得到的事：
//   ① 只读：真机（PGlite 真 PG + sql.js 真 SQLite）跑完，库里的数据与 schema 一字不变；
//   ② 不猜：查询失败 / 方言未收录 ⇒ `unknown` 并带原因，**不计入 pass**；
//   ③ 判定有牙：松配置判 fail、紧配置判 pass（两个方向都要能红，否则判据空转）；
//   ④ 结论口径：`auditSentence` 必须把「未查成」说出来，不能只报通过数。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runAudit, auditSentence, rowsToObjects } from '../src/engine/audit.js';
import { CHECKS_BY_DIALECT, POSTGRES_CHECKS, SQLITE_CHECKS } from '../src/engine/auditChecks.js';

test('① rowsToObjects：驱动返回的制表符行能还原成对象（列顺序对齐）', () => {
  const objs = rowsToObjects({ columns: ['a', 'b'], rows: ['1\t2', 'x\t'] });
  assert.deepEqual(objs, [{ a: '1', b: '2' }, { a: 'x', b: '' }]);
  assert.deepEqual(rowsToObjects({ columns: [], rows: [] }), []);
});

test('② 方言未收录 ⇒ 单条 unknown + 原因（不得静默当通过）', async () => {
  // [D187] 夹具从 oracle 换成 firebird：oracle 已有检查项，不能再拿它当「未收录」样本
  const r = await runAudit({ dialect: 'firebird', query: async () => ({ rows: [], columns: [] }) });
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].status, 'unknown');
  assert.match(r.findings[0].reason, /dialect=firebird/);
  assert.deepEqual(r.summary, { total: 1, pass: 0, fail: 0, unknown: 1 });
});

test('③ 查询抛错 ⇒ 该条 unknown 且带 reason，其余照跑（不中断、不猜）', async () => {
  const r = await runAudit({
    dialect: 'sqlite',
    query: async (sql) => {
      if (/sqlite_version/.test(sql)) return { columns: ['v'], rows: ['3.45.0'] };
      throw new Error('no such pragma');
    },
  });
  assert.equal(r.summary.unknown, r.findings.length - 1);
  const version = r.findings.find((f) => f.id === 'sqlite-version');
  assert.equal(version.status, 'pass');
  const broken = r.findings.find((f) => f.status === 'unknown');
  assert.match(broken.reason, /no such pragma/);
  assert.equal(r.summary.pass, 1, '只有真查成的那条算 pass');
});

test('④ 判定有牙：同一检查项在松/紧两种取值下结论相反', async () => {
  const superCheck = POSTGRES_CHECKS.find((c) => c.id === 'pg-superuser');
  assert.equal(superCheck.judge({ rolsuper: 't' }).status, 'fail', '超级用户必须判 fail');
  assert.equal(superCheck.judge({ rolsuper: 'f' }).status, 'pass', '非超级用户必须判 pass');
  const fk = SQLITE_CHECKS.find((c) => c.id === 'sqlite-foreign-keys');
  assert.equal(fk.judge({ foreign_keys: '0' }).status, 'fail');
  assert.equal(fk.judge({ foreign_keys: '1' }).status, 'pass');
  const enc = POSTGRES_CHECKS.find((c) => c.id === 'pg-password-encryption');
  assert.equal(enc.judge({ password_encryption: 'md5' }).status, 'fail');
  assert.equal(enc.judge({ password_encryption: 'scram-sha-256' }).status, 'pass');
});

test('⑤ 每条检查项自带只读 SQL（含写操作即判红）', () => {
  // ⚠ 先剥字符串字面量再判：`has_schema_privilege('public','CREATE')` 里的 'CREATE' 是**参数**，
  // 不是写操作。首版没剥，判据被自己的误报打红——这类「判据自己被样本骗过」的形态在本仓已出现过多次。
  const stripLiterals = (sql) => sql.replace(/'(?:[^']|'')*'/g, "''");
  const forbidden = /\b(insert|update|delete|drop|alter|create|truncate|grant|revoke|copy|set\s+\w+\s*=)\b/i;
  for (const [dialect, checks] of Object.entries(CHECKS_BY_DIALECT)) {
    assert.ok(checks.length > 0, `${dialect} 的检查项不得为空`);
    for (const c of checks) {
      assert.ok(c.id && c.title && c.sql && typeof c.judge === 'function', `${dialect}/${c.id} 字段不全`);
      assert.ok(!forbidden.test(stripLiterals(c.sql)), `${dialect}/${c.id} 的 SQL 含写操作：${c.sql}`);
      assert.ok(/^(select|show|pragma)\b/i.test(c.sql.trim()), `${dialect}/${c.id} 不是只读语句：${c.sql}`);
    }
  }
  // 反向自证：把真写操作塞进夹具必须被判红（否则上面那条只是恒真）
  assert.ok(forbidden.test(stripLiterals("select 1; drop table t")), '判据对裸写操作应有牙');
  assert.ok(!forbidden.test(stripLiterals("select 'drop table t' as p")), '字符串字面量里的关键词不得误报');
});

test('⑥ auditSentence：必须把「未查成」说出来，不能只报通过数', () => {
  assert.match(auditSentence({ summary: { total: 3, pass: 2, fail: 0, unknown: 1 } }), /未查成 1/);
  assert.match(auditSentence({ summary: { total: 3, pass: 2, fail: 0, unknown: 1 } }), /不等于通过/);
  assert.equal(auditSentence({ summary: { total: 0, pass: 0, fail: 0, unknown: 0 } }), '未执行安全配置审计');
  // 全查成时不出现「未查成」（避免措辞噪音）
  assert.ok(!/未查成/.test(auditSentence({ summary: { total: 3, pass: 3, fail: 0, unknown: 0 } })));
});
