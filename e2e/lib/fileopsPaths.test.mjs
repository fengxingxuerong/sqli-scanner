// ============================================================================
// fileopsPaths.test.mjs —— [D134] 「这次实例允许我读写哪个目录」的判据自证
//
// 这些用例对应 2026-10-23 实测过的真事故：宿主 MariaDB 的
// secure_file_priv=D:\tools\mariadb\files\，而 fileWrite 套件仍往 %TEMP% 写，
// MySQL 拒绝后验收把「环境路径不匹配」记成「fileWrite 能力 FAIL」。
// 判据必须在三种取值上分别正确：NULL（禁用）/ ''（不限制）/ '/dir/'（限定）。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  isSecureFilePrivDisabled,
  normalizeDir,
  effectiveSecureDir,
  resolveTargetFile,
} from './fileopsPaths.mjs';

test('NULL 与字符串 "NULL" 都算禁用；空串是「不限制」而不是禁用', () => {
  assert.equal(isSecureFilePrivDisabled(null), true);
  assert.equal(isSecureFilePrivDisabled(undefined), true);
  assert.equal(isSecureFilePrivDisabled('NULL'), true);
  assert.equal(isSecureFilePrivDisabled('null'), true);
  assert.equal(isSecureFilePrivDisabled(''), false, "'' = 不限制目录，不能当禁用（真值判断会判反）");
  assert.equal(isSecureFilePrivDisabled('D:/tools/mariadb/files/'), false);
});

test('目录归一化：反斜杠转正斜杠、去尾部斜杠、去空白', () => {
  assert.equal(normalizeDir('D:\\tools\\mariadb\\files\\'), 'D:/tools/mariadb/files');
  assert.equal(normalizeDir('  /var/lib/mysql-files/  '), '/var/lib/mysql-files');
  assert.equal(normalizeDir(null), '');
  assert.equal(normalizeDir(undefined), '');
});

test('优先级：显式 env > 实例自报 > 兜底（空串交回调用方）', () => {
  // 显式指定（沙箱注入）永远优先——沙箱目录与宿主目录可能不同
  assert.equal(
    effectiveSecureDir({ envDir: 'D:\\proj\\.sandbox\\plugin\\', sfp: 'D:/tools/mariadb/files/' }),
    'D:/proj/.sandbox/plugin'
  );
  // 没显式指定时，**必须**采用实例自报的目录（事故根因：这里用了兜底 tmpdir）
  assert.equal(effectiveSecureDir({ sfp: 'D:\\tools\\mariadb\\files\\' }), 'D:/tools/mariadb/files');
  // 不限制目录 ⇒ 没有限定，交回兜底
  assert.equal(effectiveSecureDir({ sfp: '' }), '');
  // 禁用 ⇒ 也没有可用目录（调用方应在此之前 SKIP）
  assert.equal(effectiveSecureDir({ sfp: null }), '');
});

test('目标文件落在可用目录内（相对拼接，不丢层级）', () => {
  assert.equal(
    resolveTargetFile({ dir: 'D:/tools/mariadb/files', fallbackDir: 'C:/tmp', name: 'pwned.txt' }),
    'D:/tools/mariadb/files/pwned.txt'
  );
  assert.equal(
    resolveTargetFile({ dir: '', fallbackDir: 'C:/tmp', name: 'pwned.txt' }),
    'C:/tmp/pwned.txt'
  );
  assert.equal(
    resolveTargetFile({ dir: 'D:/x', fallbackDir: 'C:/tmp', name: 'a.txt', override: 'D:\\y\\b.txt' }),
    'D:/y/b.txt',
    '显式覆盖优先（CI 用 FILE_WRITE_DIR 指向挂载卷）'
  );
});

test('回归：宿主限定目录下不得回落到 tmpdir（事故形态，判据有牙）', () => {
  const dir = effectiveSecureDir({ sfp: 'D:\\tools\\mariadb\\files\\' });
  const target = resolveTargetFile({ dir, fallbackDir: '/tmp/mysql-fw-lab/out', name: 'pwned.txt' });
  assert.equal(target, 'D:/tools/mariadb/files/pwned.txt');
  assert.ok(!target.includes('/tmp/'), '不得再落到 tmpdir —— 那正是被 MySQL 拒绝的路径');
});
