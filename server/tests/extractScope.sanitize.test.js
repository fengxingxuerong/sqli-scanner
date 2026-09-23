// ============================================================================
// server/tests/extractScope.sanitize.test.js —— 枚举/拖库动作族的 REST 形状校验
// [E2 2026-09-23]
//
// 背景：CLI 的 `--dbs/--tables/--columns/--dump/--dump-all/--users/...` 一直是
// 「把参数解析成 config.extractScope 交给引擎」（bin/cli/config.js:314 buildExtractScope
// → ScanManager._extractByScope → engine/extractScope.js:109 的 switch），
// 而 REST 白名单**从未收录该键** → Web / 桌面 / API 三端完全没有枚举与拖库能力
// （传了被当未知字段静默丢弃，只留一条 warn，调用方拿到 200 + scanId，报告写「未检出」）。
//
// 本文件钉住三件事：
//   ① 形状校验器的正/负例（mode 白名单是引擎 switch 的判据：传错会直接 throw）；
//   ② `sanitizeStart` 端的**接线**（校验器写了但没接进 sanitizeStart = 第二种断链）；
//   ③ 标识符**不做**字符集白名单这件事被显式记录（引擎侧已有 escSql，重复收窄只会误拒合法名）。
// ============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeStart, sanitizeExtractScope } from '../src/api/scanRoutes.js';

const WRAP = (scope) => sanitizeStart({ target: { url: 'http://shop.example.com/item?id=1' }, config: { extractScope: scope } });

// ── ① 校验器：合法输入 ────────────────────────────────────────────────────

test('§A 全部 18 个 mode 都通过（与 engine/extractScope.js 的 switch 分支一致）', () => {
  const MODES = [
    'dbs', 'tables', 'columns', 'dump', 'dumpAll', 'commonTables', 'commonColumns', 'search',
    'currentDb', 'currentUser', 'hostname', 'isDba', 'users', 'passwords',
    'schema', 'privileges', 'roles', 'count',
  ];
  for (const mode of MODES) {
    const out = sanitizeExtractScope({ mode });
    assert.ok(out, `mode=${mode} 应被接受`);
    assert.equal(out.mode, mode);
  }
});

test('§A 子字段原样保留（数组去重、excludeSysdbs 布尔、keyword 字符串）', () => {
  const out = sanitizeExtractScope({
    mode: 'dump',
    dbs: ['app', 'app', 'report'],
    tables: ['users'],
    cols: ['name', 'email'],
    excludeSysdbs: false,
    keyword: 'user',
  });
  assert.deepEqual(out.dbs, ['app', 'report'], '重复项应去重');
  assert.deepEqual(out.tables, ['users']);
  assert.deepEqual(out.cols, ['name', 'email']);
  assert.equal(out.excludeSysdbs, false);
  assert.equal(out.keyword, 'user');
});

test('§A 中文/连字符/点号库表名必须被接受（不做字符集白名单，避免误拒合法标识符）', () => {
  const out = sanitizeExtractScope({ mode: 'tables', dbs: ['用户库', 'my-app', 'reporting.v2'] });
  assert.deepEqual(out.dbs, ['用户库', 'my-app', 'reporting.v2']);
});

// ── ① 校验器：负例（每类都对应一种真实故障）────────────────────────────────

test('§B 未知 mode 一律拒绝（引擎 switch 遇到会 throw，不能让它在扫描中途爆）', () => {
  assert.equal(sanitizeExtractScope({ mode: 'noSuchMode' }), undefined);
  assert.equal(sanitizeExtractScope({ mode: 'DBS' }), undefined, 'mode 大小写敏感');
  assert.equal(sanitizeExtractScope({ mode: '' }), undefined);
  assert.equal(sanitizeExtractScope({}), undefined, 'mode 缺失 = 不启用');
});

test('§B 非对象形态一律拒绝（字符串/数组/null/数字）', () => {
  for (const bad of ['dbs', 42, null, undefined, ['dbs'], true]) {
    assert.equal(sanitizeExtractScope(bad), undefined, `${JSON.stringify(bad)} 应被拒`);
  }
});

test('§B 数组元素：非字符串/空白/控制字符/超长 逐个剔除，其余保留', () => {
  const out = sanitizeExtractScope({
    mode: 'tables',
    dbs: ['ok', 123, '', '   ', 'a\u0000b', 'x'.repeat(300), 'also_ok'],
  });
  assert.deepEqual(out.dbs, ['ok', 'also_ok']);
});

test('§B 数量上限：dbs ≤ 100 / tables ≤ 500（防单次扫描无界枚举）', () => {
  const many = (n) => Array.from({ length: n }, (_, i) => `d${i}`);
  assert.equal(sanitizeExtractScope({ mode: 'tables', dbs: many(150) }).dbs.length, 100);
  assert.equal(sanitizeExtractScope({ mode: 'columns', tables: many(700) }).tables.length, 500);
});

test('§B keyword 仅接受合理长度的干净字符串；excludeSysdbs 仅接受真布尔', () => {
  assert.equal(sanitizeExtractScope({ mode: 'search', keyword: 'u' }).keyword, 'u');
  assert.equal(sanitizeExtractScope({ mode: 'search', keyword: '   ' }).keyword, undefined);
  assert.equal(sanitizeExtractScope({ mode: 'search', keyword: 'x'.repeat(200) }).keyword, undefined);
  assert.equal(sanitizeExtractScope({ mode: 'search', keyword: 'a\nb' }).keyword, undefined);
  assert.equal(sanitizeExtractScope({ mode: 'dbs', excludeSysdbs: 'true' }).excludeSysdbs, undefined,
    '字符串 "true" 不收——引擎按 === true 语义，收了等于「API 收了、引擎不生效」');
});

// ── ② 接线：校验器必须真的接在 sanitizeStart 上 ────────────────────────────

test('§C 接线：合法 extractScope 出现在 sanitizeStart 的输出 config 里', () => {
  const out = WRAP({ mode: 'dbs' });
  assert.ok(out.config.extractScope, '未接线（白名单有、透传没有 = 本仓的老病）');
  assert.equal(out.config.extractScope.mode, 'dbs');
});

test('§C 接线：非法 extractScope 被丢弃且**不污染** config（不留半截对象）', () => {
  for (const bad of [{ mode: 'nope' }, 'dbs', 1, null, { dbs: ['a'] }]) {
    const out = WRAP(bad);
    assert.equal(out.config.extractScope, undefined, `${JSON.stringify(bad)} 不应进入 config`);
  }
});

test('§C 未传 extractScope 时 config 里不得凭空出现该键（零行为变化）', () => {
  const out = sanitizeStart({ target: { url: 'http://shop.example.com/item?id=1' }, config: {} });
  assert.equal('extractScope' in out.config, false);
});

// ── ③ 记录「有意不做」的口径，防止后人误加窄字符集 ─────────────────────────

test('§D 单引号可进入标识符值（引擎侧 escSql 负责转义；REST 不重复收窄）', () => {
  const out = sanitizeExtractScope({ mode: 'tables', dbs: ["o'brien"] });
  assert.deepEqual(out.dbs, ["o'brien"], '若此处被拒，说明有人加了字符集白名单——请先读 sanitizeExtractScope 的口径注释');
});
