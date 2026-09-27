// modsecLive.wiring.test.js —— 真机对拍「放行 → 打穿」升级的守卫
// ============================================================================
// 2026-09-28 把 modsec-live 从「WAF 放行率」升级成「打穿率」：同一条样本要同时满足
// ① 过了 WAF ② 后端真 MySQL 真执行了注入并吐出证据。这条链上有三处会静默失效：
//   ① 判据本身太浅（echo 后端回显 payload → 任何「body 里出现 payload」形态的判据恒真）；
//   ② 真库依赖不在位时静默降级，出一份看着正常的「放行率」报告冒充绕过能力；
//   ③ CI 侧少了起库/等待/要求真库的接线 → 本地怎么跑都行，CI 里永远只测放行。
// 三者都是「脚本还在、能力已死」，只能靠「行为断言 + 源码文本」两头钉。
// ============================================================================
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../..');
const read = (rel) => readFileSync(path.join(REPO, rel), 'utf8');

const VERDICT_REL = 'e2e/waf-real/pwnVerdict.mjs';
const LIVE_REL = 'e2e/waf-real/modsec-live.mjs';
const TARGET_REL = 'e2e/waf-real/modsec-target.mjs';

const verdictSrc = read(VERDICT_REL);
const liveSrc = read(LIVE_REL);
const targetSrc = read(TARGET_REL);
const ciYml = read('.github/workflows/ci.yml');

// 判据模块导入即可（纯函数、无副作用）；不给 modsec-live 做 import —— 它会跑主流程
const { verdict, isPwn, atSql } = await import(new URL(`../../${VERDICT_REL}`, import.meta.url));

// ── 一、行为断言：判据本身 ───────────────────────────────────────────────────
test('① echo 后端回显 payload **不算**打穿（巧合陷阱：回显型判据在 echo 下恒真）', () => {
  // 靶站 echo 模式的真实响应形态：payload 原样出现在 body 里
  const r = verdict({ status: 200, text: `OK id=1' UNION SELECT 'SQLISCANNER0','SQLISCANNER1'` });
  assert.notEqual(r, 'pwn_result', 'echo 回显 payload 被判成取数成功 = 判据恒真（假绿）');
  assert.notEqual(isPwn(r), true);
  assert.equal(r, 'echo', '不是真库响应 → 应判 echo（打穿不可判定）');
});

test('② SQL 报错里回显 payload **不算**打穿（只认 MySQL 自己生成的短语）', () => {
  const r = verdict({
    status: 200,
    text: `SQLERR:You have an error in your SQL syntax; near ''SQLISCANNER0','SQLISCANNER1'' at line 1`,
  });
  assert.equal(isPwn(r), false, '报错消息里出现 payload 片段不是取数证据');
  assert.equal(r, 'reached_sql', '到了 SQL 层但没取到数 → reached_sql');
  assert.equal(atSql(r), true);
});

test('③ 结果集里出现注入标记 → pwn_result', () => {
  assert.equal(verdict({ status: 200, text: 'ROWS:1|alpha|n1|e1' }), 'reached_sql');
  assert.equal(verdict({ status: 200, text: 'ROWS:__S__8.0.28__E__|x|y|z' }), 'pwn_result');
  assert.equal(verdict({ status: 200, text: 'ROWS:SQLISCANNER0|SQLISCANNER1|x|y' }), 'pwn_result');
});

test('④ 报错取数（extractvalue / floor-rand）→ pwn_error', () => {
  assert.equal(verdict({ status: 200, text: `SQLERR:XPATH syntax error: '~8.0.28'` }), 'pwn_error');
  assert.equal(
    verdict({ status: 200, text: `SQLERR:Duplicate entry '8.0.28:1' for key 'group_key'` }),
    'pwn_error',
  );
  assert.equal(isPwn('pwn_error'), true);
});

test('⑤ WAF 拦 / 网络异常 / 空响应分别归类（不混入打穿）', () => {
  assert.equal(verdict({ status: 403, text: 'blocked' }), 'blocked');
  assert.equal(verdict({ status: 500, text: 'SQLERR:whatever' }), 'blocked', '非 2xx 一律按被拦');
  assert.equal(verdict({ status: 0, text: 'ERR:fetch failed' }), 'unknown');
  assert.equal(verdict({ status: 200, text: '' }), 'echo');
  assert.equal(isPwn(verdict({ status: 200, text: '' })), false);
});

test('⑥ isPwn / atSql 口径自洽（atSql 是超集，unknown/blocked/echo 都不算）', () => {
  for (const v of ['unknown', 'blocked', 'echo']) {
    assert.equal(isPwn(v), false, `${v} 不该算打穿`);
    assert.equal(atSql(v), false, `${v} 不该算抵达 SQL 层`);
  }
  assert.equal(atSql('pwn_result'), true);
  assert.equal(atSql('pwn_error'), true);
  assert.equal(atSql('reached_sql'), true);
});

// ── 二、接线断言：判据模块必须真的是被跑的那个 ────────────────────────────────
test('⑦ modsec-live 真的 import 判据模块（判据被内联回去 = 单测覆盖不到真逻辑）', () => {
  assert.ok(existsSync(path.join(REPO, VERDICT_REL)), '判据模块必须存在');
  assert.match(
    liveSrc,
    /import\s*\{[^}]*\bverdict\b[^}]*\}\s*from\s*'\.\/pwnVerdict\.mjs'/,
    'modsec-live.mjs 必须从 pwnVerdict.mjs 导入 verdict',
  );
  assert.ok(!/^\s*function verdict\s*\(/m.test(liveSrc), '判据不许在 modsec-live 里再内联一份');
  // 判据模块自身也得留着防假绿的两条纪律（删了注释往往意味着判据被放宽）
  assert.match(verdictSrc, /startsWith\('ROWS:'\)/, '结果集证据必须要求 ROWS: 前缀');
  assert.match(verdictSrc, /XPATH syntax error/, '报错证据必须认 MySQL 短语');
});

test('⑧ 直连通道（绕过 WAF 量上界）+ 上界自检必须在位', () => {
  assert.ok(liveSrc.includes('MODSEC_DIRECT_BASE'), '必须支持直连靶站量「可打穿上界」');
  assert.match(liveSrc, /upper\s*===\s*0/, '直连一条都打不穿时必须硬失败（否则 0 打穿会归因错）');
  assert.match(liveSrc, /\[自检失败\]\s*直连靶站/, '上界自检失败要有可读归因');
});

test('⑨ 真库降级必须是可见的失败（MODSEC_REQUIRE_DB）', () => {
  assert.ok(liveSrc.includes('MODSEC_REQUIRE_DB'), '必须支持「要求真库」开关');
  assert.match(liveSrc, /REQUIRE_DB/, 'echo 模式 + 要求真库 → 必须 return null（exit 1）');
  assert.match(liveSrc, /ROWS\|SQLERR|SQL_LAYER|SQLERR:/, '必须能识别 SQL 层响应前缀');
});

test('⑩ 靶站：真库模式 + 原样拼接注入点 + SQL 错误也回 200', () => {
  assert.ok(targetSrc.includes('MODSEC_TARGET_DB'), '靶站必须有真库模式开关');
  assert.match(targetSrc, /WHERE id = \$\{raw\}/, '注入点必须是「原样拼接」（靶点本体）');
  assert.match(targetSrc, /SQLERR:\$\{/, 'SQL 错误要带 SQLERR: 前缀回显');
  assert.match(targetSrc, /SQLERR/, '错误路径必须存在');
  // ⚠️ 关键：错误**不能**用 5xx —— 否则对拍脚本的「非 2xx = 被 WAF 拦」会把它误算成拦截
  assert.match(targetSrc, /writeHead\(200/, '整个靶站只允许 200，防与 WAF 的 403 混淆');
  assert.ok(targetSrc.includes('/__mode'), '必须暴露模式探针，供对拍脚本判定放行率/打穿率');
  assert.match(targetSrc, /SET SESSION max_execution_time/, '时间盲注样本要限时，否则 CI 拖到超时');
});

// ── 三、CI 接线：切片到 modsec-live job 内再断言（防别处同名文本让断言假绿）───
const jobStart = ciYml.indexOf('\n  modsec-live:');
const jobEnd = ciYml.indexOf('\n  tamper-waf-matrix:');
const job = ciYml.slice(jobStart, jobEnd);

test('⑪ 切片有效：modsec-live job 段可定位且非空', () => {
  assert.ok(jobStart > 0 && jobEnd > jobStart, '必须在 ci.yml 里定位到 modsec-live job 段');
  assert.ok(job.includes('owasp/modsecurity-crs:nginx'), '切片应包含真实的 ModSecurity 容器');
});

test('⑫ CI 里真库链齐全：起库 → 等就绪 → 靶站接库 → 两个档位都要求真库', () => {
  assert.match(job, /docker run -d --name mysql-waf/, 'CI 必须起 MySQL 容器给真库靶站');
  assert.match(job, /docker exec mysql-waf mysqladmin ping/, '必须等待 MySQL 就绪（不等就会出一类 ECONNREFUSED 假失败）');
  assert.match(job, /run: env MODSEC_TARGET_DB=1/, '靶站必须以真库模式启动');
  // ⚠️ 判据形态踩过的坑：曾用 `job.match(/MODSEC_REQUIRE_DB/g).length >= 2` 计数，
  //    结果被上方的**说明注释**喂饱（注释里也写了这个变量名）→ 真把 PL1 的配置删掉依然全绿。
  //    现在改成「每个档位的 env 块各自紧邻断言」，注释满足不了，这才与危害同源。
  assert.match(job, /MODSEC_LABEL: pl1\r?\n\s+MODSEC_REQUIRE_DB: "1"/, 'PL1 档必须要求真库，否则静默退回「放行率」');
  assert.match(job, /MODSEC_LABEL: pl3\r?\n\s+MODSEC_REQUIRE_DB: "1"/, 'PL3 档必须要求真库');
  assert.match(job, /docker rm -f mysql-waf/, '收摊要清掉 MySQL 容器（残留会污染后续步骤）');
});

test('⑬ 报告口径不许把「放行」说成「绕过」', () => {
  assert.match(liveSrc, /放行 ≠ 打穿/, '报告必须写明放行不等于打穿');
  assert.match(liveSrc, /降级运行/, 'echo 降级时报告必须显式标注');
  assert.match(liveSrc, /不可判定/, '降级时打穿列必须记不可判定，不能留空或写 0');
});
