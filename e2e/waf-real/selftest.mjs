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
import { evaluate, parseCrsFile, collectValues, getParseStats } from './crs-engine.js';

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
  // 变换静默丢弃的**清单快照**：多一个没实现的 t:xxx 会在这里变红，
  // 少一个（补上了）也会变红 —— 两边都逼着改的人回来看这条结论。
  // 2026-09-24 实现 utf8toUnicode 后，942 侧清单归零；930 侧仍缺 cmdline / normalizepathwin，
  // 那是"930 还没接进裁判"的既有边界（见 crs-equivalence.mjs 的未接入族声明）。
  // 930 那份 conf 在本进程里没被 evaluate() 解析过，必须先 parseCrsFile ——
  // getParseStats 只读缓存，直接问它会拿到 null（上一版这条断言就是这么写崩的：
  // TypeError 让 selftest 以非零码退出，看起来像"测试坏了"，其实从没跑到过）。
  const CONF930 = 'e2e/waf-real/crs/REQUEST-930.conf';
  parseCrsFile(CONF930);
  eq('942 缺失变换清单（当前应为空）', getParseStats(CONFIG).droppedTransforms, []);
  eq('930 仍缺的两个变换', getParseStats(CONF930).droppedTransforms, ['cmdline', 'normalizepathwin']);
  // @pmFromFile 词典侧快照。为什么这一组必须存在：operator 一旦登记进 IMPLEMENTED_OPS，
  // "未实现 operator"普查就归零，而词典文件**不在磁盘上**时那三条规则照样恒不匹配 ——
  // 805 例那批是 942 的用例，对 930 一个字节都不关心。载入量 + 三个桶是这里唯一的机器判据。
  eq('930 @pmFromFile 引用数', getParseStats(CONF930).pmRefs, 3);
  eq('930 词典载入文件数', getParseStats(CONF930).pmLoaded, 2);
  eq('930 词典条目总数（v4.1.0 快照，改动即红）', getParseStats(CONF930).pmEntries, 936);
  eq('930 缺失词典（当前应为空）', getParseStats(CONF930).missingDicts, []);
  eq('930 空词典（当前应为空）', getParseStats(CONF930).emptyDicts, []);
  eq('942 缺失词典（该族不用 @pmFromFile）', getParseStats(CONFIG).missingDicts, []);
}

// ── t:utf8toUnicode 的"非空壳"断言（2026-09-24）──────────────────────────
// 为什么必须单独断：把 `utf8tounicode: () => s`（原样返回）注册进 T，普查里的
// `utf8tounicode` 同样会消失、805 例官方回归**一条都不会变红**（实测：那批用例里
// 根本没有超长编码载荷）。也就是说"清单归零"只证明注册了，证明不了它在干活。
// 下面这组是**端到端差分**：超长编码必须被拦，规范编码必须维持原判定（防过度折叠）。
console.log('\n[超长编码折叠]');
let u8Failed = 0;
{
  const PL3 = { collectAll: true, paranoiaLevel: 3 };
  const req = (p) => ({ uri: '/x?id=1', queryString: 'id=1', args: { id: p }, cookies: {}, headers: {} });
  const hits = (p) => evaluate(req(p), PL3).matchedRules;
  const check = (name, got, want) => {
    const ok = JSON.stringify(got) === JSON.stringify(want);
    if (!ok) u8Failed += 1;
    console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name.padEnd(34)} 命中 ${JSON.stringify(got)} 期望 ${JSON.stringify(want)}`);
  };
  // 声明该变换的只有 942100/942101/942120，前两条靠 @detectSQLi（本执行器不支持）
  // ⇒ 折叠效果唯一可见的落点是 942120「SQL 运算符」。
  check('overlong ||（%c1%bc×2）', hits('1%c1%bc%c1%bc1'), ['942120']);
  check('overlong <<（%c0%bc×2）', hits('%c0%bc%c0%bc1'), ['942120']);
  check('overlong !=（%c0%a1%c0%bd）', hits('%c0%a1%c0%bdversion()'), ['942120', '942431']);
  // 反向对照：规范编码的同一字符不能被折叠弄坏，也不许顺手多拦
  check('规范 ||（%7c×2）', hits('1%7c%7c1'), ['942120']);
  check('纯 ASCII 不误折（%25%20）', hits('100%25%20loaded'), []);
}

// ── @pmFromFile 的"非空壳"端到端差分（2026-09-25）─────────────────────────
// 与上面 utf8toUnicode 同一族问题，且更难：把 operator 登记进 IMPLEMENTED_OPS 之后
// "未实现 operator"普查归零，而词典文件不在磁盘上时那三条规则**照样恒不匹配** ——
// 一个数字都不会变（942 那 805 例压根不看 930）。所以"注册了"和"在干活"之间
// 只隔着一条端到端差分：词典里的路径必须被拦，不在词典里的正常路径必须不拦
// （反向对照防的是"恒返回命中"这种看起来更严的假绿）。
console.log('\n[@pmFromFile 词典匹配]');
let pmFailed = 0;
{
  const CONF930PM = 'e2e/waf-real/crs/REQUEST-930.conf';
  const OPT = { confPath: CONF930PM, collectAll: true, paranoiaLevel: 3 };
  const hitArgs = (p) =>
    evaluate({ uri: '/x', queryString: '', args: { file: p }, cookies: {}, headers: {} }, OPT).matchedRules;
  const hitFile = (f) =>
    evaluate({ uri: f, queryString: '', args: {}, cookies: {}, headers: {} }, OPT).matchedRules;
  const check = (name, got, want) => {
    const ok = JSON.stringify(got) === JSON.stringify(want);
    if (!ok) pmFailed += 1;
    console.log(`[${ok ? 'PASS' : 'FAIL'}] ${name.padEnd(32)} 命中 ${JSON.stringify(got)} 期望 ${JSON.stringify(want)}`);
  };
  check('ARGS /etc/passwd → 930120', hitArgs('/etc/passwd'), ['930120']);
  // 上游条目用"最短可辨识路径"，所以前面套几层穿越都只按**子串**命中，不依赖 normalizePathWin
  check('ARGS 多层穿越前缀仍子串命中', hitArgs('....//....//etc/passwd'), ['930120']);
  check('ARGS %2f 编码（先 urlDecodeUni）', hitArgs('..%2f..%2fetc%2fpasswd'), ['930100', '930110', '930120']);
  // 930130 读 REQUEST_FILENAME（phase:1），条目 `sys/class` 不带前置斜杠 ⇒ 检验的正是子串语义
  check('FILENAME /sys/class → 930130', hitFile('/sys/class'), ['930130']);
  check('FILENAME 大小写不敏感', hitFile('/SYS/CLASS'), ['930130']);
  // —— 安全对照：不在词典里的正常路径，一条都不许拦 ——
  check('正常 /index.html 不误触', hitFile('/index.html'), []);
  check('正常 /static/main.css 不误触', hitFile('/static/main.css'), []);
  check('正常 notes.txt 不误触', hitArgs('notes.txt'), []);
}

const extraFailed = varFailed + u8Failed + pmFailed;
console.log(
  `\n[waf-real selftest] ${CASES.length - failed}/${CASES.length} 通过（附加语义断言 ${extraFailed === 0 ? '全过' : `${extraFailed} 条失败`}）`,
);
if (failed > 0 || extraFailed > 0) {
  console.error(`[waf-real selftest] ${failed + extraFailed} 条断言失败`);
  process.exit(1);
}
process.exit(0);
