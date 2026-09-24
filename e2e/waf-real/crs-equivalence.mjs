// ============================================================================
// e2e/waf-real/crs-equivalence.mjs —— 用 CRS **官方回归用例**验收自实现执行器的保真度
//
// 为什么必须做：本仓所有 WAF 绕过数字都出自 `crs-engine.js`（自实现 SecRule 执行器），而本机
// 没有 Docker / Go，跑不了真 ModSecurity/Coraza。原来的证据只有"我们自己的靶场在我们自己的
// 执行器上跑出我们预期的结果"——这是**自证循环**：执行器若把某条规则编错了，靶场会跟着一起错，
// 数字照样好看。CRS 项目自己维护的回归集（tests/regression/tests/…，每条都带
// `log_contains: id "942100"` / `no_log_contains`，是**规则作者写的断言**）是唯一不需要 Docker
// 就能拿到的外部真值。
//
// 用法：
//   node scripts/fetch-crs-assets.mjs          # 先取用例（离线可复用，已入库）
//   node e2e/waf-real/crs-equivalence.mjs [--pl=1,2,3,4] [--top=15]
// 退出码：任一档「应拦用例逐规则一致率」低于阈值 → 1（并把分歧全量落盘）。
//
// 指标口径（三条都要看，混起来就会自欺）：
//   · 逐规则一致率 = 期望命中的那条规则我们也命中 / 应拦用例数      ← 最严，也是本门禁红线
//   · 整体检出率   = 任意规则拦住 / 应拦用例数                      ← 拦住了但归因不同算在这里
//   · 误触率       = 期望**不要**命中该规则、我们却命中了 / 不应拦用例数
//   「不应拦但被别的规则拦了」不算误触（真实 ModSecurity 同理，且我们逐条核对归因）。
// ============================================================================
import { readFileSync, readdirSync, mkdirSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import YAML from 'yaml';

const HERE = dirname(fileURLToPath(import.meta.url));
const TESTS_DIR = resolve(HERE, 'crs/tests');
const RESULTS_DIR = resolve(HERE, 'results');

const { evaluate, getParseStats } = await import(pathToFileURL(resolve(HERE, 'crs-engine.js')).href);
// 族 → **它自己那一族**的规则文件。用例与 conf 必须成对，理由见下方 EVAL_FAMILIES 的教训。
const FAMILY_CONF = { 942: 'crs/REQUEST-942-SQLI.conf', 930: 'crs/REQUEST-930.conf' };
// **对外引用的那份产物属于哪一族**：不带族后缀的报告文件（`results/crs-equivalence.md`，
// README 与各文档引用的就是它）、不带族后缀的分歧基线、README 记分板核对，三件事都只跟这一族走。
// 原先这三件事的条件都写成 `GATED ? … : …`，把"受不受门禁管"和"是不是被引用的那一族"混成了
// 一个判断 —— 于是把 930 接入门禁的那一刻，一次 930 测量就会覆盖掉 README 引用的 942 数字，
// 且 930 的报告会去比 942 的基线。现在按族拆开，两族可同时受管。
const BASE_FAMILY = '942';
// 受"基线 + 红线"门禁管的族：分歧基线**按族各一份文件**，每条分歧都要逐条点名理由。
// 930 于 2026-09-25 接入 —— 词典 operator 与 multipart FILES 取值落地后实测 97.0%
// （接前为 90.9%，再前 27.3%），距 90% 红线有 2 例余量；红线值仍来自实测分布。
const GATED_FAMILIES = ['942', '930'];

const argv = process.argv.slice(2);
const PLS = (argv.find((a) => a.startsWith('--pl='))?.slice(5) || '1,2,3,4').split(',').map(Number);
const TOP = Number(argv.find((a) => a.startsWith('--top='))?.slice(6) || 15);
// 红线：先测后定。低于此值即认为执行器与官方规则已不可信，WAF 数字不该对外引用。
const MIN_PER_RULE = Number(process.env.CRS_EQUIV_MIN || 0.9);

/**
 * 按 ModSecurity 的口径把 query / form 串拆成**原文**键值，不做任何 URL 解码。
 * 为什么不该由夹具先解一次：CRS 的规则把 `t:urlDecodeUni` 写在**自己的取值链**里，
 * 夹具若先解码，规则就会解第二遍 —— `%2527` 本应得到 `%27`，预解码后得到 `'`。
 * 也就是说旧的 `new URLSearchParams(...)` 不只是"多解一次"，而是把二次编码载荷的
 * 判定条件给改了（方向上是**更容易命中**，即假阳侧）。改前/改后两族数字见本轮记录。
 */
function rawPairs(s) {
  const out = {};
  for (const kv of String(s).split('&')) {
    if (!kv) continue;
    const i = kv.indexOf('=');
    if (i < 0) out[kv] = '';
    else out[kv.slice(0, i)] = kv.slice(i + 1);
  }
  return out;
}

/** 把一条官方用例的 input 变成执行器入参（args/cookies/headers/uri）。 */
function toReq(input) {
  const enc = input.encoded_request || input;
  const uri = enc.uri || '/';
  const [path, search = ''] = uri.split('?');
  const args = rawPairs(search);
  const headers = Object.fromEntries(
    Object.entries(enc.headers || {}).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v.join(',') : String(v)])
  );
  const cookies = {};
  for (const part of String(headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    // 与 ARGS 同口径：留原文，解码交给规则自己的 t:urlDecodeUni
    if (i > 0) cookies[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  const body = enc.data ?? enc.serialized_rule_request ?? '';
  // multipart 的文件部件单独抽成 files / fileNames（ModSecurity 的 FILES / FILES_NAMES）。
  // **有意不改 ARGS 那三行**：multipart 体今天照旧落进 args.__raw_body，抽掉它会改动 942
  // 门禁的取值面，不属本次半径 —— 补的只是"930110 读 FILES 却无值可取"这一件事。
  let files = [];
  let fileNames = [];
  const mp = typeof body === 'string' && body.length ? multipartFiles(headers['content-type'] || '', body) : null;
  if (mp) { files = mp.files; fileNames = mp.fileNames; }
  if (typeof body === 'string' && body.length) {
    const ct = headers['content-type'] || '';
    if (ct.includes('json')) {
      try { Object.assign(args, flatten(JSON.parse(body))); } catch { args.__raw_body = body; }
    } else if (/=/.test(body) && !body.includes('\n')) {
      Object.assign(args, rawPairs(body)); // 同口径：表单值也留原文
    } else {
      args.__raw_body = body; // REQUEST_BODY 变量当前不支持，保留原文以便归因分歧时看得见
    }
  }
  return {
    method: enc.method || 'GET',
    uri: path + (search ? `?${search}` : ''),
    queryString: search,
    args,
    cookies,
    headers,
    files,
    fileNames,
  };
}
/**
 * 从 multipart/form-data 体里取文件部件的 filename（→ FILES）与字段名（→ FILES_NAMES）。
 * 返回 null 表示这不是（可解析的）multipart 体，交由既有的 json / urlencoded / 原文 分支处理。
 * 边界串要正则化转义 —— 它来自 Content-Type，不转义就等于把外部输入拼进 RegExp。
 */
function multipartFiles(ct, body) {
  if (!/multipart\/form-data/i.test(ct)) return null;
  const bm = /boundary=([^;\r\n]+)/i.exec(ct);
  if (!bm) return null;
  const b = bm[1].trim().replace(/^"(.*)"$/, '$1');
  if (!b) return null;
  const sep = new RegExp(`(?:\\r?\\n)?--${b.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:--)?(?:\\r?\\n)?`, 'g');
  const files = [];
  const fileNames = [];
  for (const part of String(body).split(sep)) {
    const cd = /content-disposition:\s*([^\r\n]*)/i.exec(part);
    if (!cd) continue;
    const name = /;\s*name="([^"]*)"/i.exec(cd[1])?.[1];
    const filename = /;\s*filename="([^"]*)"/i.exec(cd[1])?.[1];
    if (filename) files.push(filename);
    if (name) fileNames.push(name);
  }
  return { files, fileNames };
}
function flatten(o, pre = '', out = {}) {
  for (const [k, v] of Object.entries(o || {})) {
    const key = pre ? `${pre}[${k}]` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
    else out[key] = Array.isArray(v) ? v.join(',') : String(v ?? '');
  }
  return out;
}

/** 解析 output 的期望：log_contains / no_log_contains（形如 `id "942100"`）。 */
function expectation(output) {
  const grab = (s) => {
    const m = /id\s*"(\d+)"/.exec(String(s || ''));
    return m ? m[1] : null;
  };
  const blockId = grab(output?.log_contains);
  const passId = grab(output?.no_log_contains);
  const wants403 = JSON.stringify(output?.status_code || '').includes('403');
  if (blockId) return { kind: 'must-hit', id: blockId, wants403 };
  if (passId) return { kind: 'must-not-hit', id: passId };
  if (wants403) return { kind: 'must-block', id: null };
  return { kind: 'unspecified', id: null };
}

// 用例目录必须与**它自己那一族的规则文件**配对评估。这里原先递归扫 crs/tests/* 却只配一份
// 942 conf：把 930 的用例拿去比 942 的规则，凭空造出 33 条"分歧"而门禁变红 ——
// 配错素材的裁判比没有裁判更坏（它会把口径错误伪装成产品缺陷）。
// 因此这里按 EVAL_FAMILIES 白名单取目录，未列入的族**显式声明为未接入**（见下方输出），
// 而不是悄悄扫进来或悄悄不扫。
// 默认只裁 942。**允许用环境变量临时把别的族拉进来量**，而不是把数字写死在注释里：
// 上一版这里印着"930 一致率 13.2%，根因是缺 normalizePathWin/cmdLine/utf8toUnicode"，
// 出自一个用完就删掉的一次性探针 —— 谁也无法复现，而且**归因是错的**：
// 2026-09-24 用下面这条命令当场重测，930 是 38 例/应拦 33，逐规则 27.3%，
// 剔除"规则 930120/930121/930130 的 @pmFromFile 未实现"这 21 例后为 75.0%，误触 0。
// ⇒ 主因是**词典 operator 没实现**（占应拦侧 21/33），缺变换只是次要因素；
//   而 13.2% 这个数本身也复现不出来（当时想必又混了口径）。
// 现在选族当场可重测，产物写到 results/crs-equivalence-930.md（不覆盖 942 那份对外引用的报告）：
//   · `npm run waf-fidelity:930`（等价于 `node …/crs-equivalence.mjs --family=930`）——
//     CI 与本地门禁走这条，因为 `CRS_EQUIV_FAMILIES=930 npm …` 这种前缀写法在 Windows 的
//     cmd 壳里不生效，而"受门禁管"必须意味着**两台机器上跑的是同一条命令**。
//   · `CRS_EQUIV_FAMILIES=930 npm run waf-fidelity` —— 临时手测仍可用（POSIX 壳）。
const EVAL_FAMILIES = (
    argv.find((a) => a.startsWith('--family='))?.slice('--family='.length) ||
    process.env.CRS_EQUIV_FAMILIES ||
    '942'
  )
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
// 一次只裁一个族：多个族的用例混在一批里，却只有一份 conf 与之配对（见上），
// 那批"分歧"里有多少来自别的族根本说不清 —— 与其算个含混的总数，不如拒跑。
if (EVAL_FAMILIES.length !== 1 || !FAMILY_CONF[EVAL_FAMILIES[0]]) {
  console.error(`❌ CRS_EQUIV_FAMILIES 需为单一族，可选：${Object.keys(FAMILY_CONF).join(' / ')}（用例与 conf 必须成对）`);
  process.exit(2);
}
const FAMILY = EVAL_FAMILIES[0];
const CONF = resolve(HERE, FAMILY_CONF[FAMILY]);
const GATED = GATED_FAMILIES.includes(FAMILY);
const files = existsSync(TESTS_DIR)
  ? readdirSync(TESTS_DIR, { withFileTypes: true })
      .filter((d) => d.isDirectory() && EVAL_FAMILIES.includes(d.name))
      .flatMap((d) => readdirSync(resolve(TESTS_DIR, d.name)).filter((f) => f.endsWith('.yaml')).map((f) => resolve(TESTS_DIR, d.name, f)))
  : [];
const idleFamilies = existsSync(TESTS_DIR)
  ? readdirSync(TESTS_DIR, { withFileTypes: true })
      .filter((d) => d.isDirectory() && !EVAL_FAMILIES.includes(d.name))
      .map((d) => d.name)
  : [];
if (!files.length) {
  console.error('❌ 没有官方回归用例（crs/tests/ 为空）。先跑：node scripts/fetch-crs-assets.mjs');
  process.exit(2);
}

// —— 展开成扁平用例集 ——
const cases = [];
let stagesUnmodeled = 0;
for (const file of files) {
  const doc = YAML.parse(readFileSync(file, 'utf8'));
  for (const t of doc?.tests || []) {
    for (const st of t.stages || []) {
      const input = st?.stage?.input;
      const output = st?.stage?.output;
      if (!input || !output) { stagesUnmodeled++; continue; }
      const exp = expectation(output);
      if (exp.kind === 'unspecified') { stagesUnmodeled++; continue; }
      cases.push({ file: file.replace(/\\/g, '/').split('/crs/tests/')[1], title: String(t.test_title ?? ''), desc: t.desc || '', input, exp });
    }
  }
}

const inputOf = (c) => {
  const enc = c.encoded_request || c;
  return String(enc.data ?? enc.serialized_rule_request ?? enc.uri ?? '');
};

evaluate({ method: 'GET', uri: '/', queryString: '', args: {}, cookies: {}, headers: {} }, { confPath: CONF }); // 先强制解析一次，普查计数才就位
const census = getParseStats(CONF) || {};
console.log('=== 自实现 CRS 执行器 × CRS 官方回归用例 ===');
console.log(`规则文件：${CONF.split(/[\\/]/).slice(-1)[0]}（族 ${FAMILY}${GATED ? '' : '，**非门禁族：只报数不判红**'}｜SecRule 行 ${census.secRuleLines}，装载 ${census.loaded}，链头 ${census.chainHeads}，解析丢弃 ${census.droppedBySplit}，元规则跳过 ${census.skippedMeta}）`);
console.log(`未实现 operator：${census.unimplemented} 条 ${JSON.stringify(census.unimplementedIds || [])}　正则编不出来：${(census.regexBad || []).length} 条 ${JSON.stringify(census.regexBad || [])}`);
// [2026-09-24] 变量侧普查：与 operator 侧同一套路，**风险方向相反**的两类必须分开报。
{
  const gaps = census.unsupportedVarIds || [];
  const byVar = {};
  for (const x of gaps) { const t = x.slice(x.indexOf(':') + 1); byVar[t] = (byVar[t] || 0) + 1; }
  console.log(`变量取不到值（该规则在这份数据上恒不命中）：${census.unsupportedVars || 0} 处 / 去重 ${gaps.length} 条 ${JSON.stringify(byVar)}`);
  console.log(`  涉及规则：${[...new Set(gaps.map((x) => x.split(':')[0]))].slice(0, 12).join(', ')}${new Set(gaps.map((x) => x.split(':')[0])).size > 12 ? ` …共 ${new Set(gaps.map((x) => x.split(':')[0])).size} 条` : ''}`);
  console.log(`排除项未实现（只多取不少取，偏保守）：${census.unhonoredExclusions || 0} 处 / 去重 ${(census.unhonoredExclusionIds || []).length} 条`);
}
if (idleFamilies.length) {
  // 这一行曾经把 idleFamilies（= FAMILY_CONF 里除本轮之外的族）标成"未接入门禁的族"，
  // 于是跑 930 时打印出"未接入门禁：942" —— 而 942 恰恰是唯一受门禁管的族，读者会拿到
  // 一个完全反向的结论。标签必须与定义一致：这里只说"未参与本轮评估"，
  // 受不受管由下一行从 GATED_FAMILIES 现算。
  console.log(`ℹ 本轮只裁族 ${FAMILY}；同批入库、未参与本轮评估的族：${idleFamilies.join(', ')}（用例与 conf 必须成对评估）`);
  console.log(`   要数字就当场重测，别引用记录里的旧值：npm run waf-fidelity -- --family=${idleFamilies[0]}`);
  // 这句必须从 GATED_FAMILIES 现算：930 接入门禁之后，无条件印"非门禁族只报数不判红"
  // 就是在给一个受管的族发免检声明 —— 而它下一行还接着打印该族的红线判定。
  const ungated = Object.keys(FAMILY_CONF).filter((f) => !GATED_FAMILIES.includes(f));
  console.log(ungated.length
    ? `   （受门禁管的族：${GATED_FAMILIES.join('/')}；仍只报数不判红的：${ungated.join('/')}）`
    : `   （FAMILY_CONF 里的族已全部受门禁管：${GATED_FAMILIES.join('/')}）`);
}
// 缺口一律由普查现算，不写死结论。上一版在这里钉着"930 的主缺口是 @pmFromFile 词典规则
// 未实现"，而 @pmFromFile 实现、词典入库之后，那两行仍会每天照印一遍**已经不成立**的事实 ——
// 结论句和行号锚点一样会漂，而且比数字更容易被读者当成现状。
{
  const gaps = [];
  if (census.unimplemented) gaps.push(`${census.unimplemented} 条 operator 未实现（${JSON.stringify(census.unimplementedIds || [])}）`);
  if ((census.missingDicts || []).length) gaps.push(`@pmFromFile 词典缺失：${[...census.missingDicts].join('、')}`);
  if ((census.emptyDicts || []).length) gaps.push(`@pmFromFile 词典为空：${[...census.emptyDicts].join('、')}`);
  const dt = [...(census.droppedTransforms || [])];
  if (dt.length) gaps.push(`变换未实现：${JSON.stringify(dt)}`);
  console.log(`   本族缺口（普查当场算，变量侧缺口另见上一行）：${gaps.length ? gaps.join('；') : 'operator / 词典 / 变换三类均无缺口'}`);
}
console.log(`官方用例：${cases.length} 条（另有 ${stagesUnmodeled} 条 stage 无 log_contains/no_log_contains，不计入）\n`);

const perPl = {};
for (const pl of PLS) {
  const r = { mustHit: 0, perRuleOk: 0, blockedAny: 0, mustNotHit: 0, fpSameRule: 0, blockedByOther: 0, mustBlock: 0, mustBlockOk: 0, divergences: [] };
  for (const c of cases) {
    // confPath 必须显式传：不传就落到 crs-engine 的默认值（942）。
    // 那样跑 930 时普查按 930 装载、判定却仍按 942 规则 ⇒ 同一份报告里两套真相。
    const got = evaluate(toReq(c.input), { paranoiaLevel: pl, collectAll: true, confPath: CONF });
    if (c.exp.kind === 'must-hit') {
      r.mustHit++;
      const hit = got.matchedRules.includes(c.exp.id);
      if (hit) r.perRuleOk++;
      if (got.blocked) r.blockedAny++;
      if (!hit) r.divergences.push({ 类型: '漏该规则', pl, 用例: c.title, 文件: c.file, 期望: c.exp.id, 我们命中: got.matchedRules.join(',') || '(无)', 输入: inputOf(c.input).slice(0, 120) });
    } else if (c.exp.kind === 'must-not-hit') {
      r.mustNotHit++;
      if (got.matchedRules.includes(c.exp.id)) {
        r.fpSameRule++;
        r.divergences.push({ 类型: '误触该规则', pl, 用例: c.title, 文件: c.file, 期望: `不命中 ${c.exp.id}`, 我们命中: got.matchedRules.join(','), 输入: inputOf(c.input).slice(0, 120) });
      } else if (got.blocked) r.blockedByOther++;
    } else if (c.exp.kind === 'must-block') {
      r.mustBlock++;
      if (got.blocked) r.mustBlockOk++;
      else r.divergences.push({ 类型: '应拦未拦', pl, 用例: c.title, 文件: c.file, 期望: 'status 403', 我们命中: got.matchedRules.join(',') || '(无)', 输入: inputOf(c.input).slice(0, 120) });
    }
  }
  r.逐规则一致率 = r.mustHit ? r.perRuleOk / r.mustHit : null;
  r.整体检出率 = r.mustHit ? r.blockedAny / r.mustHit : null;
  r.误触率 = r.mustNotHit ? r.fpSameRule / r.mustNotHit : null;
  perPl[pl] = r;
}

console.log('PL   应拦  逐规则一致  整体检出  不应拦  误触该规则  误触率   别的规则拦下');
for (const pl of PLS) {
  const r = perPl[pl];
  const pct = (v) => (v == null ? '-' : `${(v * 100).toFixed(1)}%`);
  console.log(
    `${String(pl).padEnd(4)} ${String(r.mustHit).padEnd(5)} ${pct(r.逐规则一致率).padEnd(11)} ${pct(r.整体检出率).padEnd(9)} ${String(r.mustNotHit).padEnd(7)} ${String(r.fpSameRule).padEnd(11)} ${pct(r.误触率).padEnd(8)} ${r.blockedByOther}`
  );
}

// —— 保真度主口径：**每条用例在它期望的那条规则"本该生效的 PL"上比** ——
// 上一张表里的 PL1/PL2 行是"配置档位视图"：CRS 在 PL1 本来就不跑 PL2/PL3 规则，
// 那 27.6% 不是执行器失真，而是档位正确行为。把它当保真度会得出完全错误的结论。
const al = { n: 0, perRuleOk: 0, blockedAny: 0, mustNot: 0, fp: 0, div: [] };
// "已点名的不支持项"从**普查推导**，不写死规则号：写死 942100/942101 时，换一族测量会让
// 那些"operator 恒不匹配"的规则被算成执行器失真 ⇒ 同一份报告里出现两套口径。
// 普查里 unimplementedIds 形如 `942100:@detectSQLi`，对 942 恰好就是这两条 ⇒ 门禁数字一字不变。
const KNOWN_UNSUPPORTED_IDS = new Set((census.unimplementedIds || []).map((x) => x.split(':')[0]));
const KNOWN_UNSUPPORTED_OPS = [...new Set((census.unimplementedIds || []).map((x) => x.split(':')[1]))];
for (const c of cases) {
  const pl = c.exp.id ? (census.plById?.[c.exp.id] ?? 4) : 4;
  const got = evaluate(toReq(c.input), { paranoiaLevel: pl, collectAll: true, confPath: CONF });
  const known = KNOWN_UNSUPPORTED_IDS.has(c.exp.id); // 该规则的 operator 本执行器没有 ⇒ 恒不匹配，单列不算失真
  if (c.exp.kind === 'must-hit') {
    al.n++;
    const hit = got.matchedRules.includes(c.exp.id);
    if (hit) al.perRuleOk++;
    if (got.blocked) al.blockedAny++;
    if (!hit && !known) al.div.push({ 类型: '漏该规则', pl, 用例: c.title, 文件: c.file, 期望: c.exp.id, 我们命中: got.matchedRules.join(',') || '(无)', 输入: inputOf(c.input).slice(0, 120) });
    if (!hit && known) al.knownGap = (al.knownGap || 0) + 1;
  } else if (c.exp.kind === 'must-not-hit') {
    al.mustNot++;
    if (got.matchedRules.includes(c.exp.id)) {
      al.fp++;
      al.div.push({ 类型: '误触该规则', pl, 用例: c.title, 文件: c.file, 期望: `不命中 ${c.exp.id}`, 我们命中: got.matchedRules.join(','), 输入: inputOf(c.input).slice(0, 120) });
    }
  } else if (c.exp.kind === 'must-block') {
    al.n++;
    if (got.blocked) al.blockedAny++, al.perRuleOk++;
    else al.div.push({ 类型: '应拦未拦', pl, 用例: c.title, 文件: c.file, 期望: 'status 403', 我们命中: got.matchedRules.join(',') || '(无)', 输入: inputOf(c.input).slice(0, 120) });
  }
}
const aligned = al.n ? al.perRuleOk / al.n : null;
const alignedExKnown = al.n - (al.knownGap || 0) ? (al.perRuleOk) / (al.n - (al.knownGap || 0)) : null;
console.log('\n=== 保真度主口径（按规则自身档位对齐）===');
console.log(`  应拦用例 ${al.n}：逐规则命中 ${(aligned * 100).toFixed(1)}%｜任意规则拦下 ${(al.blockedAny / al.n * 100).toFixed(1)}%`);
// 括号里的解释必须由普查生成，不能写死"@detectSQLi 需要 libinjection"：
// 那是 942 的缺口形状，同一句话印在 930 的报告上就成了假的（930 缺的是 @pmFromFile 词典）。
if (al.knownGap)
  console.log(
    `  其中 ${al.knownGap} 条属**已点名的不支持项**（规则 ${[...KNOWN_UNSUPPORTED_IDS].sort().join('/')} 用的 ${KNOWN_UNSUPPORTED_OPS.join('/')} 本执行器没有）；剔除后逐规则一致率 ${(alignedExKnown * 100).toFixed(1)}%`,
  );
console.log(`  不应拦用例 ${al.mustNot}：误触该规则 ${al.fp}（${al.mustNot ? ((al.fp / al.mustNot) * 100).toFixed(1) : '0.0'}%）｜分歧合计 ${al.div.length} 条`);

// —— 已知差距基线（只减不增）——
// 与 scripts/arch-guard.mjs 的 .arch-baseline.json 同一套纪律：**分歧必须被逐条点名**，
// 出现任何不在基线里的新分歧 → 门禁 FAIL；基线里的条目消失了也报出来（提示可以收紧）。
// 每条都给"为什么不算执行器 bug"，理由不成立的就不该进基线。
// 基线**按族分文件**：942 沿用被各处引用着的那份无名文件，其余族带族名后缀。
// 拿 942 的基线去卡 930 的测量，得到的"未点名分歧 / 已消失"全是素材错配的产物
// （读了只会误导；"门禁族"这个标签原本就是为防这件事加的 —— 现在改用文件隔离，
//  于是两族各自受管，不必二选一）。
const KNOWN_FILE = resolve(
  HERE,
  FAMILY === BASE_FAMILY ? 'crs-known-divergences.json' : `crs-known-divergences-${FAMILY}.json`
);
// 分歧的**理由只存在基线文件里**（`crs-known-divergences*.json` 的 `原因` 字段）。
// 这里原来还有一份 `KNOWN_REASONS` 表，用于生成基线时填理由 —— 已删除，因为"两处各写一份
// 理由必烂一处"不是推测而是实测：本轮新加的守卫第一次跑就抓到这份表与 JSON 已经不一致
// （表里 `942210-44`/`942500-4` 写"同上"，而 JSON 里前者早已被改成整段完整记录）。
// 现在的分工：基线文件 = 唯一真相；生成骨架时一律写"待补理由"，由
// server/tests/crsGatedFamilies.wiring.test.js 卡住（每条理由必须自包含且不许是"同上"），
// 逼着人在提交前把理由写进那份会被读到的文件里。
// 只有门禁族才比对基线（非门禁族只报数：基线路径虽已按族隔离，但"未点名分歧判红"这件事
// 只对声明受门禁管的族有意义）。
const baseline = GATED && existsSync(KNOWN_FILE) ? JSON.parse(readFileSync(KNOWN_FILE, 'utf8')) : null;
const knownTitles = new Set((baseline?.divergences || []).map((d) => d.用例));
const unexpected = al.div.filter((d) => !knownTitles.has(d.用例));
const stale = (baseline?.divergences || []).filter((d) => !al.div.some((x) => x.用例 === d.用例));
if (!baseline) {
  if (!GATED) {
    console.log(`\n[基线] 族 ${FAMILY} 不受门禁管，**不生成基线文件**（基线只在受管的族里才有意义：它的作用是"逐条点名后仍不许新增"）`);
  } else {
    mkdirSync(RESULTS_DIR, { recursive: true });
    writeFileSync(
      KNOWN_FILE,
      JSON.stringify(
        {
          _comment: 'CRS 官方回归集上**已逐条核对过原因**的分歧清单。新增未点名分歧 = 门禁 FAIL；条目消失 = 按实测收紧本文件。',
          tag: `coreruleset v4.1.0 / REQUEST-${FAMILY}`,
          divergences: al.div.map((d) => ({
            用例: d.用例,
            类型: d.类型,
            期望: d.期望,
            原因: '待补理由',
          })),
        },
        null,
        2
      )
    );
    console.log(`\n[基线] 已生成 ${KNOWN_FILE}（${al.div.length} 条）——请逐条核对理由后再提交`);
  }
} else {
  console.log(`\n[基线] 已点名分歧 ${knownTitles.size} 条｜本次新出现未点名 ${unexpected.length} 条｜基线中已消失 ${stale.length} 条`);
  for (const d of unexpected) console.log(`   ❌ 未点名：${d.类型} ${d.用例}（期望 ${d.期望} → 命中 [${d.我们命中}]）输入 ${d.输入.slice(0, 60)}`);
  for (const d of stale) console.log(`   ↻ 可收紧基线：${d.用例}（${d.类型}）已不再分歧`);
}

// —— README 记分板核对（只 WARN，不判红）——
// 起因是本次实测出来的漂移：README 写「误触 4」，门禁早已是 2。这类数字**不在 facts:check
// 的覆盖范围内**（facts 只管测试数/覆盖率），也就是说它是"静默失效"这一类的最后一个藏身处：
// 报告会随每次运行重算，而 README 那行没人再对过。
// 为什么只做 WARN：那张表里混着历史轮次的存档（"上一轮 96% → 本轮 99.3%"），
// 强行让每次测量都回填，会诱使人去改历史数字 —— 那比留着不核对更糟。
// 但"没人知道"必须变成"当场说出来"。
// 条件必须是"被 README 引用的那一族"，不是"受门禁管的族"：记分板那一行是 942 的数字，
// 930 也进门禁之后若仍按 GATED 判断，一次 930 测量会拿 33 例的口径去比 720 例的记分板，
// 天天 WARN 一遍没人能修的错误。
if (FAMILY === BASE_FAMILY) {
  const README = resolve(HERE, '..', '..', 'README.md');
  if (existsSync(README)) {
    const lines = readFileSync(README, 'utf8').split(/\r?\n/);
    const want = {
      保真度: `${(alignedExKnown * 100).toFixed(1)}%`,
      未点名: String(unexpected.length),
      已消失: String(stale.length),
      误触: String(al.fp),
    };
    const drift = [];
    lines.forEach((line, i) => {
      if (!/CRS 执行器保真度/.test(line) || !/误触|分歧|保真度/.test(line)) return;
      const pick = (re) => (line.match(re) || [])[1];
      const got = {
        保真度: pick(/保真度 \*?\*?([\d.]+%)/),
        未点名: pick(/未点名分歧 \*?\*?(\d+)/),
        已消失: pick(/已消失 (\d+)/),
        误触: pick(/误触 (\d+)/),
      };
      for (const k of Object.keys(want)) {
        if (got[k] != null && got[k] !== want[k]) drift.push(`  L${i + 1} ${k}：README=${got[k]} 本次实测=${want[k]}`);
      }
    });
    if (drift.length) {
      console.log('\n⚠ README 的保真度记分板与本次实测不符（不影响门禁结论；要么回填，要么在行内标明是历史存档）：');
      for (const d of drift) console.log(d);
    }
  }
}

const fails = [];
if (alignedExKnown < MIN_PER_RULE) fails.push(`保真度 ${(alignedExKnown * 100).toFixed(1)}% < ${(MIN_PER_RULE * 100).toFixed(0)}%`);
if (baseline && unexpected.length) fails.push(`${unexpected.length} 条未点名分歧`);
// 非门禁族：数字照出，但**不判红**。基线里的用例名全是 942 家族的，拿它去卡 930 的测量
// 只会得到"素材错配"造成的假失败（这正是本文件开头那条教训的另一种表现形式）。
if (!GATED) {
  if (fails.length) console.log(`\n（非门禁族：以下 ${fails.length} 条只报数不判红）`);
  for (const f of fails) console.log(`   · ${f}`);
  fails.length = 0;
}
// 产物命名按**族**走，不按"是否门禁"走：`results/crs-equivalence.md` 是 README / 各报告
// 引用的那一份（942 的），任何其它族的测量都必须另起文件名 —— 否则把 930 接入门禁的瞬间，
// 一次 930 运行就会把对外数字静默换成另一个口径（这正是这个文件反复在防的那类失效）。
const REPORT = `crs-equivalence${FAMILY === BASE_FAMILY ? '' : `-${FAMILY}`}`;
mkdirSync(RESULTS_DIR, { recursive: true });
writeFileSync(
  resolve(RESULTS_DIR, `${REPORT}.json`),
  JSON.stringify({ at: new Date().toISOString(), family: FAMILY, gated: GATED, cases: cases.length, unmodeled: stagesUnmodeled, threshold: MIN_PER_RULE, census, aligned: { ...al, 逐规则一致率: aligned, 剔除已知不支持: alignedExKnown }, perPl }, null, 2)
);
const md = [
  `# 自实现 CRS 执行器 × CRS 官方回归用例（保真度｜族 ${FAMILY}）`,
  '',
  `> 本报告的**全部数字只描述族 ${FAMILY}**（用例目录与 conf 成对评估），不构成"CRS 整体已对齐"。`,
  `> 生成：${new Date().toISOString()}　用例来源：coreruleset v4.1.0 tests/regression/tests/REQUEST-${FAMILY}-*（共 ${cases.length} 条可判定 stage，${stagesUnmodeled} 条无规则期望不计）`,
  `> ${GATED ? '红线' : '参考线'}：**按规则自身档位对齐后**的逐规则一致率（剔除已点名的${KNOWN_UNSUPPORTED_OPS.length ? ` ${KNOWN_UNSUPPORTED_OPS.join('/')} ` : ''}不支持项）< ${(MIN_PER_RULE * 100).toFixed(0)}% 即判 FAIL${GATED ? '' : '（本族未接入门禁，只报数不判红）'}。`,
  `> WAF 绕过数字全部出自这个执行器 —— 执行器不像 CRS，那些数字就没有意义。`,
  '',
  '## 分档结果',
  '',
  '| PL | 应拦用例 | 逐规则一致率 | 整体检出率 | 不应拦用例 | 误触该规则 | 误触率 | 被别的规则拦下 |',
  '|---|---|---|---|---|---|---|---|',
  ...PLS.map((pl) => {
    const r = perPl[pl];
    const pct = (v) => (v == null ? '-' : `${(v * 100).toFixed(1)}%`);
    return `| ${pl} | ${r.mustHit} | ${pct(r.逐规则一致率)} | ${pct(r.整体检出率)} | ${r.mustNotHit} | ${r.fpSameRule} | ${pct(r.误触率)} | ${r.blockedByOther} |`;
  }),
  '',
  '## 保真度主口径（按规则自身档位对齐）',
  '',
  `| 应拦用例 | 逐规则命中 | 任意规则拦下 | 已知不支持（${KNOWN_UNSUPPORTED_OPS.length ? KNOWN_UNSUPPORTED_OPS.join('/') : '无'}） | 剔除后一致率 | 不应拦用例 | 误触该规则 |`,
  `|---|---|---|---|---|---|---|`,
  `| ${al.n} | ${aligned == null ? '-' : (aligned * 100).toFixed(1) + '%'} | ${(al.blockedAny / al.n * 100).toFixed(1)}% | ${al.knownGap || 0} | ${alignedExKnown == null ? '-' : (alignedExKnown * 100).toFixed(1) + '%'} | ${al.mustNot} | ${al.fp} |`,
  '',
  '> 本表才是"执行器像不像 CRS"。上面那张分档表是**配置档位视图**：PL1/PL2 行数字低是正常的',
  '> （CRS 在低档本来就不跑那些规则），不要拿它当保真度。',
  '',
  '## 执行器与官方规则的差距（静态普查）',
  '',
  `- SecRule 行 ${census.secRuleLines}，装载 ${census.loaded}（链头 ${census.chainHeads}），解析丢弃 ${census.droppedBySplit}，元规则跳过 ${census.skippedMeta}`,
  `- 未实现 operator：${census.unimplemented} 条 → ${JSON.stringify(census.unimplementedIds || [])}（这些规则**恒不匹配**）`,
  `- 正则编译失败：${(census.regexBad || []).length} 条 → ${JSON.stringify(census.regexBad || [])}`,
  // 变换侧普查（2026-09-24）：`.filter(t => T[t])` 会**静默丢掉**执行器不认识的变换。
  // 取名与取值同源（declaredTransforms）⇒ 这一行归零意味着变换真进了取值链，而不只是"注册过"。
  // （上一版就栽在这个差别上：变换名里的数字把 `utf8toUnicode` 截成 `utf`，注册了也从未生效。）
  `- 静默丢掉的变换：${JSON.stringify(census.droppedTransforms || [])} —— 上面的保真度数字是**在缺这些变换的前提下**量出来的（空清单 = 无缺口）`,
  `  （utf8toUnicode 现已实现：超长 UTF-8 折叠此前从未进过取值链，而官方回归集里**没有一条**超长编码载荷，
     ⇒ 它**不会**改动上面那个一致率，所以该行为改由 selftest 的端到端差分断言兜住（注册成功但空转 = 当场红）。
     本报告结论只覆盖族 ${FAMILY}，不等于"CRS 整体已对齐"。）`,
  // 词典侧普查：@pmFromFile "实现了"不等于"在干活" —— 词典文件不在磁盘上时那几条规则
  // 依旧恒不匹配，而 operator 普查会归零（因为它只看 operator 名字）。这一行堵的就是
  // "注册成功≠在干活"的第二个变体：实现在、数据不在。
  `- @pmFromFile 词典：${census.pmRefs || 0} 处引用 / 载入 ${census.pmLoaded || 0} 个文件、合计 ${census.pmEntries || 0} 条条目；缺失 ${JSON.stringify([...(census.missingDicts || [])])}，空词典 ${JSON.stringify([...(census.emptyDicts || [])])}${(census.missingDicts || []).length ? ' —— ⚠ 缺失的那几条规则**恒不匹配**，上面的数字不含它们（跑 npm run waf-fidelity:refresh 补词典）' : ''}`,
  // 变量侧普查（2026-09-24）：**风险方向相反的两类，分开列，不合并成一个"差距"数**
  `- 变量取不到值（声明读它、本执行器读不出 ⇒ 该规则在这类输入上恒不命中）：${census.unsupportedVars || 0} 处 / 去重 ${(census.unsupportedVarIds || []).length} 条`,
  `  - 按变量：${JSON.stringify((() => { const m = {}; for (const x of census.unsupportedVarIds || []) { const t = x.slice(x.indexOf(':') + 1); m[t] = (m[t] || 0) + 1; } return m; })())}`,
  `  - ⚠ 其中 XML:/* 一家就占 ${(census.unsupportedVarIds || []).filter((x) => x.endsWith(':XML:/*')).length} 条 —— 意味着**XML 请求体整体不在本执行器的检测面内**：`,
  `    官方回归集是 query/表单 body 形态，所以上面那个一致率**不包含** XML 载荷，别把它外推到 XML 接口。`,
  `- 排除项未实现（\`!COLL:sel\` 不扣，只多取不少取，偏保守方向）：${census.unhonoredExclusions || 0} 处 / 去重 ${(census.unhonoredExclusionIds || []).length} 条`,
  '',
  `## 分歧明细（主口径：按规则自身档位对齐；前 ${TOP} 条，全量见 results/${REPORT}.json）`,
  '',
  ...(al.div.length
    ? al.div.slice(0, TOP).map((d) => `  - [${d.类型}] ${d.用例}（${d.文件}）期望 ${d.期望} → 我们命中 [${d.我们命中}]，输入 ${d.输入}`)
    : ['  - 无']),
  '',
  '### 各配置档位下的额外分歧（含"低档本来就不跑该规则"的正常情况）',
  '',
  ...PLS.flatMap((pl) => {
    const ds = perPl[pl].divergences;
    if (!ds.length) return [`- **PL${pl}** 无分歧`];
    const lines = ds.slice(0, TOP).map((d) => `  - [${d.类型}] ${d.用例}（${d.文件}）期望 ${d.期望} → 我们命中 [${d.我们命中}]，输入 ${d.输入}`);
    return [`- **PL${pl}** 共 ${ds.length} 条：`, ...lines];
  }),
  '',
].join('\n');
writeFileSync(resolve(RESULTS_DIR, `${REPORT}.md`), md);
console.log(`\n[report] ${resolve(RESULTS_DIR, `${REPORT}.md`)}`);
if (fails.length) {
  console.log(`\n❌ FAIL：${fails.join('；')} —— 执行器与官方规则的差距已超出可引用范围（分歧明细见 results/${REPORT}.md）`);
  process.exit(1);
}
if (!GATED) {
  console.log(`\nℹ 族 ${FAMILY} 未接入门禁：以上数字**只是测量**，不判红也不进对外结论（详见报告头部的族声明）。`);
  process.exit(0);
}
console.log(`\n✅ 保真度（剔除已知不支持后）${(alignedExKnown * 100).toFixed(1)}% ≥ 红线 ${(MIN_PER_RULE * 100).toFixed(0)}%`);
