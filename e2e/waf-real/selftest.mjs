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
import { evaluate, parseCrsFile } from './crs-engine.js';

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

console.log(`\n[waf-real selftest] ${CASES.length - failed}/${CASES.length} 通过`);
if (failed > 0) {
  console.error(`[waf-real selftest] ${failed} 条断言失败`);
  process.exit(1);
}
process.exit(0);
