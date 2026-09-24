// ============================================================================
// e2e/waf-real/selftest.mjs —— CRS 引擎自检（真断言版）
// ============================================================================
// [2026-09-18 重写] 原版只 console.log 打印 4 个用例结果 + `process.exit(0)`，
// **一处断言都没有** —— 无论 UNION 是否漏拦，run-all 永远显示 ✅ 通过。
// 实测原版输出：`UNION 注入: false rule null`（漏拦！）却仍 exit 0。
//
// 本版改为声明式用例表 + 逐条断言，任一不符即 exit 1。
//
// 关于 UNION 用例的构造（实测结论 2026-09-18）：
//   真实 CRS 规则集（REQUEST-942-SQLI.conf）对 UNION 的检测**依赖上下文**：
//     · 942100 要求 UNION 前有引号（`'`/`"`/`` ` ``）或 `having|select|union` 前缀；
//     · 942110 要求出现 `union ... select ... from`；
//     · 942460 命中「引号闭合 + union ... select」；
//     · 942190 命中「行尾引号/union 关键字」。
//   裸 `1 UNION SELECT NULL,NULL`（无引号、无 FROM）**不在覆盖范围内**，
//   这是规则集的真实边界，不是引擎 bug。故用例改用带引号闭合的形态。
// ============================================================================
import { evaluate, parseCrsFile, collectValues } from './crs-engine.js';

const CONFIG = 'e2e/waf-real/crs/REQUEST-942-SQLI.conf';
const rules = parseCrsFile(CONFIG);
console.log(`解析规则组: ${rules.length}（含链式）\n`);

// expect: 是否期望被拦截；mustRule: 期望命中的规则 id（可选，仅作信息）
const CASES = [
  { name: 'UNION 注入（引号闭合）', payload: "1' UNION SELECT NULL,NULL-- -", expect: true, mustRule: true },
  { name: 'UNION 注入（含 FROM）', payload: "1' UNION SELECT username FROM users-- -", expect: true, mustRule: true },
  { name: 'UNION ALL SELECT', payload: "1' UNION ALL SELECT 1,2-- -", expect: true, mustRule: true },
  { name: 'SLEEP 时间盲注', payload: "1' AND SLEEP(5)-- -", expect: true, mustRule: true },
  { name: '堆叠查询', payload: "1'; DROP TABLE users-- -", expect: true, mustRule: false },
  { name: '错误注入 updatexml', payload: "1' AND updatexml(1,concat(0x7e,version()),1)-- -", expect: true, mustRule: true },
  { name: '错误注入 extractvalue', payload: "1' AND extractvalue(1,concat(0x7e,version()))-- -", expect: true, mustRule: true },
  // 安全对照：必须**不**被拦（防误报）
  { name: '正常数值', payload: '1', expect: false, mustRule: false },
  { name: '正常搜索词', payload: 'keyboard', expect: false, mustRule: false },
  { name: '含空格正常串', payload: 'hello world', expect: false, mustRule: false },
];

const ev = (payload) =>
  evaluate({ uri: '/num?id=1', queryString: 'id=1', args: { id: payload }, cookies: {}, headers: {} });

let failed = 0;
for (const c of CASES) {
  const r = ev(c.payload);
  const ok = r.blocked === c.expect;
  // 期望拦截时，进一步要求必须命中某条规则（blocked 却无 ruleId 说明判定链异常）
  const ruleOk = !c.expect || c.mustRule === false || Boolean(r.ruleId);
  const pass = ok && ruleOk;
  if (!pass) failed += 1;
  const mark = pass ? 'PASS' : 'FAIL';
  const detail = `blocked=${r.blocked} rule=${r.ruleId ?? 'null'}`;
  const why = !ok ? `（期望 blocked=${c.expect}）` : !ruleOk ? '（期望命中具体规则但 ruleId 为空）' : '';
  console.log(`[${mark}] ${c.name.padEnd(24)} ${detail} ${why}`);
}

// ── 变量列表语义断言（2026-09-24）────────────────────────────────────────
// 上面那些用例断的是"载荷进不改检测面"；这几条断的是**取值口径**本身。
// 为什么值得单独断：`!COLL:sel` 与 `COLL:sel` 这两处形态上一轮直接改出过 12 条未点名分歧，
// 而回归集里**没有任何一条用例**会在"值被扣掉但名不该被扣"这一点上给我们答案 ——
// 也就是说这类语义错了，805 例未必拦得住，只能靠这里的定点断言。
console.log('\n[变量列表语义]');
let varFailed = 0;
{
  const REQ = {
    method: 'GET', uri: '/x', queryString: '', args: { id: '1', q: '2' },
    cookies: { __utmz: 'u', sid: 's' }, headers: { host: 'h' },
  };
  const v = (vars) => collectValues(vars, REQ, {}, null);
  const eq = (name, got, want) => {
    const ok = JSON.stringify(got) === JSON.stringify(want);
    if (!ok) varFailed += 1;
    console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name.padEnd(34)} 得到 ${JSON.stringify(got)} 期望 ${JSON.stringify(want)}`);
  };
  // ① 扣值不扣名：names 与 values 在 ModSecurity 里是**两个集合**，扣其中一个不能连坐。
  //    （上一版把两者折成同一个 kind 是这次分歧的来源之一。）
  eq('扣 __utm 只作用于 cookie 值', v(['REQUEST_COOKIES', '!REQUEST_COOKIES:/__utm/']), ['s']);
  eq('cookie 名不受值侧扣除影响', v(['REQUEST_COOKIES_NAMES', '!REQUEST_COOKIES:/__utm/']), ['__utmz', 'sid']);
  eq('扣名要显式写 NAMES 集合', v(['REQUEST_COOKIES_NAMES', '!REQUEST_COOKIES_NAMES:/^__utm/']), ['sid']);
  // ② 跨集合不连坐：扣 ARGS 的名字不得顺手把同名 cookie 元素扣掉
  eq('扣 ARGS 元素不连坐 cookies', v(['ARGS', 'REQUEST_COOKIES', '!ARGS:id']), ['2', 'u', 's']);
  // ③ 正向选择器维持原状（上一版顺手开放、结果变红）：裸名取全量
  eq('ARGS:id 仍取该元素', v(['ARGS:id']), ['1']);
  eq('裸 ARGS 取全量', v(['ARGS']), ['1', '2']);
  // ④ 无名元素没有"元素名"可扣，扣除项对它们必须无效（否则 URI 类规则会被静默清空）
  eq('URI 不受 ARGS 扣除影响', v(['REQUEST_URI', '!ARGS:id']), ['/x']);
}

console.log(`\n[waf-real selftest] ${CASES.length - failed}/${CASES.length} 通过（变量语义 ${varFailed === 0 ? '全过' : `${varFailed} 条失败`}）`);
if (failed > 0 || varFailed > 0) {
  console.error(`[waf-real selftest] ${failed + varFailed} 条断言失败`);
  process.exit(1);
}
process.exit(0);
