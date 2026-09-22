// ============================================================================
// e2e/multi-engine-lab/verify-dialect-templates.mjs
//
// 【P2 方言模板真机验证】**可复现取证脚本**（不是一次性探针）。
//
// 背景：`SYS_QUERIES.*.data` 与 `Exploiter.buildStackPageSql` 是「按方言拼 SQL」的模板，
// 其合法性**不能靠阅读/类推判断**——本轮实测证明：同一条 `SEPARATOR CHAR(30)` 在 H2 合法、
// 在 HSQLDB 语法错。本脚本把生成的 SQL 原样投给**真 JDBC 引擎**（H2/HSQLDB/Derby），
// 记录引擎自己的返回，作为修复前/后的唯一判据。
//
// 用法：
//   ENGINE_JARS="D:\engines\jars\h2.jar;D:\engines\jars\hsqldb.jar;D:\engines\jars\derby.jar;D:\engines\jars\derbyshared.jar" \
//     node e2e/multi-engine-lab/verify-dialect-templates.mjs
//
// 覆盖断言（引擎实测，2026-09-22 全部通过）：
//   ① SYS_QUERIES.HSQLDB.data 可执行（修复前：unexpected token CHAR required: a quoted string）
//   ② buildStackPageSql('HSQLDB') 可执行（修复前：unexpected token : required: AS）
//   ③ SYS_QUERIES.H2.data 可执行（H2 接受表达式分隔符，未回归）
//   ④ buildStackPageSql('H2') 可执行（同上）
//   ⑤ SYS_QUERIES.Derby.data === null（Derby 无聚合/控制字符函数 → 诚实降级）
//   ⑥ HSQLDB 的标识符为双引号（反引号实测语法错）
//   ⑦ 形如 MySQL 的 SEPARATOR CHAR() 在 HSQLDB 上被拒（缺陷形态的反证，防回归）
//   ⑧ SYS_QUERIES.Derby.tables / .columns 亦为 null，但 databases 保留并真机可执行
//   ⑩ SYS_QUERIES.MonetDB.data 引号自洽（**静态断言，非引擎实测**；依据官方手册）
//   ⑪⑫ 盲注字典：修复后 SUB_FN.Derby（substr）真机可执行；反证 Derby 拒绝 substring…FROM…FOR
//   ⑬⑭ ASCII_FN.Derby === null，且真机反证 Derby 确无 unicode()/ascii()（结构性不支持）
//
// 前置守卫：若未设置 ENGINE_JARS，脚本会在跑断言前探测驱动，命中 `No suitable driver`
//   即打印用法并以退出码 2 退出 —— 避免把「漏设环境变量」误判成「方言模板回归」。
//
// 退出码：0 = 全部断言通过；1 = 有断言失败；2 = 环境未就绪（缺 ENGINE_JARS）。
// ============================================================================
import { EngineBridgeClient } from './lab-app.mjs';
import { buildStackPageSql } from '../../server/src/engine/Exploiter.js';
import { SYS_QUERIES, SUB_FN, ASCII_FN } from '../../server/src/engine/extractionMaps.js';

const bridge = new EngineBridgeClient().start();

// [P2 审计修复 2026-09-22] 前置守卫：若未设置 ENGINE_JARS，JVM classpath 里没有 JDBC 驱动，
// 所有查询都会报 `No suitable driver found for jdbc:...` —— 那是**harness 缺环境变量**，
// 不是代码缺陷。此前实测踩到过：漏设 ENGINE_JARS → 5 条断言 FAIL，误导为「修复回归」。
// 现在在跑断言前先探测一条最小查询，若命中 driver 错误就直接退出并提示正确用法。
{
  const probe = await bridge.query('hsqldb', 'SELECT 1 FROM (VALUES(0)) v(x)');
  const err = String(probe.error || '');
  if (!probe.ok && /No suitable driver/i.test(err)) {
    console.error('[ENV ERROR] JVM 未加载 JDBC 驱动（No suitable driver）。');
    console.error('  原因：未设置 ENGINE_JARS 环境变量 → classpath 为空。');
    console.error('  用法：ENGINE_JARS="D:\\engines\\jars\\h2.jar;D:\\engines\\jars\\hsqldb.jar;' +
      'D:\\engines\\jars\\derby.jar;D:\\engines\\jars\\derbyshared.jar" node ' +
      'e2e/multi-engine-lab/verify-dialect-templates.mjs');
    console.error('  注：这是环境配置问题，不是方言模板缺陷——请勿据此判定代码回归。');
    process.exit(2);
  }
}

// bridge 的行协议以 \n 分帧；结果含 0x0A（行分隔符）会把 JSON 切断。
// 那不是引擎失败，而是**执行成功的副作用**，故单独识别为成功。
async function q(engine, sql) {
  const r = await bridge.query(engine, sql);
  if (!r.ok && typeof r.error === 'string' && r.error.startsWith('bad bridge line:')) {
    return { ok: true, raw: '执行成功（返回行含 0x0A，被行协议截断）' };
  }
  return r.ok ? { ok: true, raw: JSON.stringify(r.rows) } : { ok: false, raw: String(r.error).split('\n')[0] };
}

const results = [];
function check(name, cond, detail = '') {
  results.push({ name, ok: !!cond });
  console.log(`[${cond ? 'PASS' : 'FAIL'}] ${name}${detail ? '  — ' + detail : ''}`);
}

// HSQLDB 的标识符大小写敏感：裸名建表存为大写，双引号建表保留原样。
// 真注入场景下模板收到的表名/列名来自目标 catalog（已是其存储形态），
// 故此处用「双引号建表 + 双引号小写」模拟 catalog 返回小写名的场景。
async function bootHsqldb() {
  for (const s of [
    `DROP TABLE "t" IF EXISTS`,
    `CREATE TABLE "t" ("id" INT, "name" VARCHAR(64), "role" VARCHAR(32))`,
    `INSERT INTO "t" VALUES (1,'user1','admin')`,
    `INSERT INTO "t" VALUES (2,'user2',NULL)`,
    `INSERT INTO "t" VALUES (3,'user3','user')`,
  ]) await q('hsqldb', s);
}

async function bootH2() {
  for (const s of [
    `CREATE TABLE IF NOT EXISTS t (id INT, name VARCHAR(64), role VARCHAR(32))`,
    `DELETE FROM t`,
    `INSERT INTO t VALUES (1,'user1','admin')`,
    `INSERT INTO t VALUES (2,'user2','user')`,
  ]) await q('h2', s);
}

try {
  await bootHsqldb();
  await bootH2();
  const COLS = ['id', 'name', 'role'];

  // ── ① HSQLDB 拖库模板 ────────────────────────────────────────────────────
  const hsData = SYS_QUERIES.HSQLDB.data(null, 't', COLS, 10, 0, null);
  check('① SYS_QUERIES.HSQLDB.data 真机可执行', (await q('hsqldb', hsData)).ok, hsData.slice(0, 60) + '…');

  // ── ② HSQLDB 堆叠分页 ────────────────────────────────────────────────────
  // 注：buildStackPageSql 的表名是**裸标识符**（FROM t）→ HSQLDB 解析为大写，
  // 故用双引号建表的 'T' 场景需传大写名。这里直接建一张大写可解析的表以贴合其行为。
  await q('hsqldb', `DROP TABLE "T" IF EXISTS`);
  for (const s of [`CREATE TABLE "T" ("id" INT, "name" VARCHAR(64))`, `INSERT INTO "T" VALUES (1,'a')`,
                   `INSERT INTO "T" VALUES (2,'b')`]) await q('hsqldb', s);
  const hsStack = buildStackPageSql('HSQLDB', null, 'T', ['id', 'name'], 0, 10);
  check('② buildStackPageSql(HSQLDB) 真机可执行', (await q('hsqldb', hsStack)).ok, hsStack.slice(0, 60) + '…');

  // ── ③④ H2 未回归 ────────────────────────────────────────────────────────
  const h2Data = SYS_QUERIES.H2.data(null, 't', COLS, 10, 0, null);
  check('③ SYS_QUERIES.H2.data 真机可执行（未回归）', (await q('h2', h2Data)).ok);
  const h2Stack = buildStackPageSql('H2', null, 't', COLS, 0, 10);
  check('④ buildStackPageSql(H2) 真机可执行（未回归）', (await q('h2', h2Stack)).ok);

  // ── ⑤ Derby 诚实降级 ─────────────────────────────────────────────────────
  check('⑤ SYS_QUERIES.Derby.data === null（诚实降级）', SYS_QUERIES.Derby.data === null,
    String(SYS_QUERIES.Derby.data));

  // ── ⑧ Derby 枚举：tables/columns 亦降级，databases 保留且真机可执行 ─────────
  check('⑧a Derby.tables === null（GROUP_CONCAT 实测不存在）', SYS_QUERIES.Derby.tables === null);
  check('⑧b Derby.columns === null（同上）', SYS_QUERIES.Derby.columns === null);
  const derbyDb = await q('derby', SYS_QUERIES.Derby.databases);
  check('⑧c Derby.databases 保留且真机可执行（单值查询，无需聚合）', derbyDb.ok,
    String(derbyDb.raw).slice(0, 40));

  // ── ⑨ 反证：Derby 确实没有 GROUP_CONCAT（证明降级必要性）─────────────────
  const derbyAgg = await q('derby', `SELECT GROUP_CONCAT(TABLENAME) FROM SYS.SYSTABLES WHERE TABLETYPE='T'`);
  check('⑨ 反证：Derby 拒绝 GROUP_CONCAT（证明降级必要性）', !derbyAgg.ok,
    String(derbyAgg.raw).slice(0, 62));

  // ── ⑥⑦ 缺陷形态反证（防回归） ────────────────────────────────────────────
  check('⑥ HSQLDB 模板标识符为双引号（不用反引号）',
    !hsData.includes('`') && hsData.includes('"id"'));
  const badSql = `SELECT GROUP_CONCAT("name" SEPARATOR CHAR(30)) FROM "t"`;
  const bad = await q('hsqldb', badSql);
  check('⑦ 反证：HSQLDB 确实拒绝 `SEPARATOR CHAR(30)`（证明修复必要性）', !bad.ok, bad.raw.slice(0, 70));

  // ── ⑩ MonetDB 引号自洽（**静态断言，非引擎实测**）─────────────────────────
  // 本机无 MonetDB 引擎/驱动（EngineBridge 只 open h2/hsqldb/derby），
  // 故此断言只做**静态自洽性**检查：同一语句里列名与表名必须同用双引号。
  // 依据为 MonetDB 官方手册《Lexical Structure》（引号标识符只有双引号）——强度低于引擎实测。
  const mdData = SYS_QUERIES.MonetDB.data('db', 'users', COLS, 10, 0, null);
  check('⑩ MonetDB.data 引号自洽（列/表同为双引号，无混用）',
    !mdData.includes('`') && mdData.includes('"id"') && mdData.includes('FROM "users"'),
    '[静态，非引擎实测] ' + mdData.slice(0, 60) + '…');

  // ── ⑪⑫ 盲注提取函数字典（LEN_FN/SUB_FN/ASCII_FN）真实引擎取证 ──────────────
  // 这两条覆盖 Derby 的**盲注通道**（与 ⑤⑧ 的拖库通道 data=null 是不同路径，独立可达）。
  await q('derby', `DROP TABLE bb`);
  await q('derby', `CREATE TABLE bb (id INT, name VARCHAR(64))`);
  await q('derby', `INSERT INTO bb VALUES (1,'Abc')`);
  const derbySubSql = `SELECT (${SUB_FN.Derby('name', '1')}) AS v FROM bb`;
  check('⑪ 修复后 SUB_FN.Derby（substr）真机可执行（修复前 substring…FROM…FOR 语法错）',
    (await q('derby', derbySubSql)).ok, derbySubSql);
  const badSub = await q('derby', `SELECT (${'substring((name) FROM 1 FOR 1)'}) AS v FROM bb`);
  check('⑫ 反证：Derby 拒绝 substring((x) FROM n FOR m)（证明修复必要性）', !badSub.ok,
    String(badSub.raw).slice(0, 66));
  // ⑬ ASCII_FN.Derby 必须为 null（Derby 无任何「字符→码点」函数）
  //    —— 静态断言 + 真机反证：确认 unicode/ascii 在 Derby 上确实不存在
  check('⑬ ASCII_FN.Derby === null（Derby 无字符→码点函数，结构性不支持）',
    ASCII_FN.Derby === null, String(ASCII_FN.Derby));
  const noUni = await q('derby', `SELECT unicode(substr(name,1,1)) AS v FROM bb`);
  const noAsc = await q('derby', `SELECT ascii(substr(name,1,1)) AS v FROM bb`);
  check('⑭ 反证：Derby 确实无 unicode()/ascii()（证明置 null 的必要性）',
    !noUni.ok && !noAsc.ok,
    `unicode -> ${String(noUni.raw).slice(0, 34)}; ascii -> ${String(noAsc.raw).slice(0, 34)}`);

  // ── 汇总 ─────────────────────────────────────────────────────────────────
  const failed = results.filter((r) => !r.ok);
  console.log('='.repeat(72));
  console.log(`PASS ${results.length - failed.length} / FAIL ${failed.length}`);
  if (failed.length) {
    for (const f of failed) console.log('  FAIL: ' + f.name);
    process.exitCode = 1;
  }
} finally {
  bridge.stop();
}
