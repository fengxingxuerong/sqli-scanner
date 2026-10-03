// 凭据哈希识别与风险标注单测（--passwords 的「读到了哈希 → 这条凭据值多少」那一层）
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  STRENGTH,
  MAX_ENTRIES,
  riskOfStrength,
  classifyHash,
  analyzePasswords,
  hasNotableRisk,
} from '../src/engine/extraction/hashAnalysis.js';

// ─────────────────────────── classifyHash：逐格式 ───────────────────────────
test('classifyHash: MySQL 8 caching_sha2 识别为强', () => {
  const r = classifyHash('$A$005$abcdefghijklmnopqrstuvWXYZ0123456789abc/def');
  assert.equal(r.algo, 'mysql-caching-sha2');
  assert.equal(r.strength, STRENGTH.STRONG);
});

test('classifyHash: MySQL native（* + 40 hex）为中（有 SHA1 但无盐）', () => {
  const r = classifyHash('*' + 'A'.repeat(40));
  assert.equal(r.algo, 'mysql-native-sha1');
  assert.equal(r.strength, STRENGTH.MEDIUM);
  // 边界：40 位但非 hex 的 `*` 串不应被当成 native
  assert.equal(classifyHash('*' + 'Z'.repeat(40)).algo, 'unrecognized');
  // 边界：39 / 41 位 hex 都不该命中
  assert.equal(classifyHash('*' + 'A'.repeat(39)).algo, 'unrecognized');
});

test('classifyHash: MySQL 旧版 16 hex 为弱', () => {
  const r = classifyHash('5d2e19393cc5ef67');
  assert.equal(r.algo, 'mysql-old-16hex');
  assert.equal(r.strength, STRENGTH.WEAK);
});

test('classifyHash: PostgreSQL SCRAM-SHA-256 为强（内部含冒号也要认）', () => {
  const r = classifyHash('SCRAM-SHA-256$4096:c2FsdHNhbHQ=$c3RvcmVka2V5:c2VydmVya2V5');
  assert.equal(r.algo, 'pg-scram-sha-256');
  assert.equal(r.strength, STRENGTH.STRONG);
});

test('classifyHash: PostgreSQL md5 为弱（无盐 MD5）', () => {
  const r = classifyHash('md5' + 'a'.repeat(32));
  assert.equal(r.algo, 'pg-md5');
  assert.equal(r.strength, STRENGTH.WEAK);
});

test('classifyHash: SQL Server 0x0200/0x0100 分别强/中', () => {
  const strong = classifyHash('0x0200' + 'AB'.repeat(36));
  assert.equal(strong.algo, 'mssql-sha512');
  assert.equal(strong.strength, STRENGTH.STRONG);
  const medium = classifyHash('0x0100' + 'AB'.repeat(24));
  assert.equal(medium.algo, 'mssql-sha1');
  assert.equal(medium.strength, STRENGTH.MEDIUM);
  // 既非 0100 也非 0200 的 0x 串 → 未识别，不猜
  assert.equal(classifyHash('0x0300aabb').strength, STRENGTH.UNKNOWN);
});

test('classifyHash: bcrypt / argon2 / sha512crypt / md5crypt 判对', () => {
  assert.equal(classifyHash('$2y$10$' + 'x'.repeat(53)).algo, 'bcrypt');
  assert.equal(classifyHash('$argon2id$v=19$m=65536,t=3,p=4$abc$def').algo, 'argon2');
  assert.equal(classifyHash('$6$rounds=5000$salt$hash').strength, STRENGTH.STRONG);
  assert.equal(classifyHash('$1$salt$hash').strength, STRENGTH.WEAK);
});

test('classifyHash: LDAP scheme 与裸 hex 按长度判族', () => {
  assert.equal(classifyHash('{SSHA}abcd').algo, 'ldap-ssha');
  assert.equal(classifyHash('{SHA}abcd').algo, 'ldap-sha');
  assert.equal(classifyHash('a'.repeat(32)).algo, 'hex32-md5-or-ntlm');
  assert.equal(classifyHash('a'.repeat(40)).algo, 'hex40-sha1');
  assert.equal(classifyHash('a'.repeat(64)).algo, 'hex64-sha256');
  // 未识别的 hex 长度 → 不硬猜算法，标 unknown
  assert.equal(classifyHash('a'.repeat(20)).strength, STRENGTH.UNKNOWN);
});

test('classifyHash: 空串 = 未设置口令（独立语义，不当「未知」）', () => {
  assert.equal(classifyHash('').strength, STRENGTH.BLANK);
  assert.equal(classifyHash('   ').strength, STRENGTH.BLANK);
  assert.equal(classifyHash(undefined).strength, STRENGTH.BLANK);
});

// ─────────────────────── riskOfStrength：单一映射源 ───────────────────────
test('riskOfStrength: 四档映射（弱/空 = high，强 = low，未识别 = unknown）', () => {
  assert.equal(riskOfStrength(STRENGTH.BLANK), 'high');
  assert.equal(riskOfStrength(STRENGTH.WEAK), 'high');
  assert.equal(riskOfStrength(STRENGTH.MEDIUM), 'medium');
  assert.equal(riskOfStrength(STRENGTH.STRONG), 'low');
  assert.equal(riskOfStrength(STRENGTH.UNKNOWN), 'unknown');
});

// ───────────────────────── analyzePasswords：解析 ─────────────────────────
test('analyzePasswords: 空/非字符串入参一律返回 null（未提取 ≠ 提取为空）', () => {
  assert.equal(analyzePasswords(null), null);
  assert.equal(analyzePasswords(undefined), null);
  assert.equal(analyzePasswords(''), null);
  assert.equal(analyzePasswords('   '), null);
  assert.equal(analyzePasswords({}), null);
  assert.equal(analyzePasswords(42), null);
  // 有内容但没有一条合法 `身份:哈希` ⇒ 返回 null（而不是造一个全 0 的空结构）
  assert.equal(analyzePasswords('no-colon-here,also-none'), null);
});

test('analyzePasswords: MySQL `user@host:hash` 拆出身份/主机并计数', () => {
  const raw = [
    'root@localhost:*' + 'A'.repeat(40),
    'app@%:*' + 'B'.repeat(40),
    'legacy@:*' + 'C'.repeat(40),
  ].join(',');
  const a = analyzePasswords(raw, { dbms: 'MySQL' });
  assert.equal(a.total, 3);
  assert.equal(a.medium, 3);
  assert.deepEqual(a.entries.map((e) => e.user), ['root', 'app', 'legacy']);
  assert.deepEqual(a.entries.map((e) => e.host), ['localhost', '%', '']);
  assert.deepEqual(a.algorithms, { 'mysql-native-sha1': 3 });
  assert.equal(a.truncated, 0);
});

test('analyzePasswords: PG SCRAM 的哈希内含冒号，必须按第一个冒号切（回归）', () => {
  const raw = 'postgres:SCRAM-SHA-256$4096:c2FsdA==$a2V5MQ==:a2V5Mg==';
  const a = analyzePasswords(raw, { dbms: 'PostgreSQL' });
  assert.equal(a.total, 1);
  assert.equal(a.strong, 1);
  assert.equal(a.entries[0].user, 'postgres');
  assert.equal(a.entries[0].host, null, 'PG 身份没有 host 段');
  assert.equal(a.entries[0].algo, 'pg-scram-sha-256');
});

test('analyzePasswords: SQL Server name:0x… 不把 0x 当 host', () => {
  const a = analyzePasswords('sa:0x0200' + 'AB'.repeat(36), { dbms: 'SQL Server' });
  assert.equal(a.entries[0].user, 'sa');
  assert.equal(a.entries[0].host, null);
  assert.equal(a.strong, 1);
});

test('analyzePasswords: 空哈希记 blank（未设口令/非口令插件），且计入 high 风险', () => {
  const raw = 'root@localhost:,app@%:*' + 'A'.repeat(40);
  const a = analyzePasswords(raw, { dbms: 'MySQL' });
  assert.equal(a.total, 2);
  assert.equal(a.blank, 1);
  assert.equal(a.medium, 1);
  assert.equal(a.entries[0].strength, STRENGTH.BLANK);
  assert.equal(a.entries[0].risk, 'high');
  assert.equal(hasNotableRisk(a), true);
});

test('analyzePasswords: 全是强哈希 ⇒ hasNotableRisk=false（报告不渲染告警噪声）', () => {
  const a = analyzePasswords('a:$2y$10$' + 'x'.repeat(53) + ',b:$argon2id$v=19$m=1$s$h');
  assert.equal(a.strong, 2);
  assert.equal(hasNotableRisk(a), false);
});

test('analyzePasswords: 不把原始哈希回显进 entries（报告外发不额外扩大凭据副本）', () => {
  const secret = '*DEADBEEF'.padEnd(41, '0');
  const a = analyzePasswords('root@localhost:' + secret);
  const flat = JSON.stringify(a);
  assert.equal(flat.includes(secret), false, 'entries 不应携带原始哈希串');
  assert.equal(JSON.stringify(a.entries).includes('DEADBEEF'), false);
});

test('analyzePasswords: 无冒号条目被跳过，不影响其余条目计数', () => {
  const a = analyzePasswords('garbage,' + 'root@localhost:*' + 'A'.repeat(40));
  assert.equal(a.total, 1, 'garbage（无冒号）不应计入 total');
  assert.equal(a.medium, 1);
  assert.equal(a.entries.length, 1);
  assert.equal(a.entries[0].user, 'root');
});

test('analyzePasswords: 身份里含冒号时按第一个冒号切 ⇒ 剩下的进「未识别」而非静默丢弃', () => {
  const a = analyzePasswords('root:x:*' + 'A'.repeat(40));
  assert.equal(a.total, 1);
  assert.equal(a.unknown, 1, '哈希侧含冒号 ⇒ 未识别格式，如实标未知');
  assert.equal(a.entries[0].identity, 'root');
});

test('analyzePasswords: 超大凭据表按 MAX_ENTRIES 截断，但计数仍为全量', () => {
  const n = MAX_ENTRIES + 25;
  const raw = Array.from({ length: n }, (_, i) => `u${i}@h:*`.concat('A'.repeat(40))).join(',');
  const a = analyzePasswords(raw);
  assert.equal(a.total, n, 'total 必须是全量（截断只影响 entries 明细）');
  assert.equal(a.entries.length, MAX_ENTRIES);
  assert.equal(a.truncated, n - MAX_ENTRIES);
  assert.equal(a.medium, n);
});
