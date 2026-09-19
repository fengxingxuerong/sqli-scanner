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
const CONF = resolve(HERE, 'crs/REQUEST-942-SQLI.conf');

const argv = process.argv.slice(2);
const PLS = (argv.find((a) => a.startsWith('--pl='))?.slice(5) || '1,2,3,4').split(',').map(Number);
const TOP = Number(argv.find((a) => a.startsWith('--top='))?.slice(6) || 15);
// 红线：先测后定。低于此值即认为执行器与官方规则已不可信，WAF 数字不该对外引用。
const MIN_PER_RULE = Number(process.env.CRS_EQUIV_MIN || 0.9);

/** 把一条官方用例的 input 变成执行器入参（args/cookies/headers/uri）。 */
function toReq(input) {
  const enc = input.encoded_request || input;
  const uri = enc.uri || '/';
  const [path, search = ''] = uri.split('?');
  const args = Object.fromEntries(new URLSearchParams(search).entries());
  const headers = Object.fromEntries(
    Object.entries(enc.headers || {}).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v.join(',') : String(v)])
  );
  const cookies = {};
  for (const part of String(headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) cookies[part.slice(0, i).trim()] = decodeSafe(part.slice(i + 1));
  }
  const body = enc.data ?? enc.serialized_rule_request ?? '';
  if (typeof body === 'string' && body.length) {
    const ct = headers['content-type'] || '';
    if (ct.includes('json')) {
      try { Object.assign(args, flatten(JSON.parse(body))); } catch { args.__raw_body = body; }
    } else if (/=/.test(body) && !body.includes('\n')) {
      for (const [k, v] of new URLSearchParams(body).entries()) args[k] = v;
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
  };
}
function decodeSafe(s) { try { return decodeURIComponent(String(s).trim()); } catch { return String(s).trim(); } }
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

const files = existsSync(TESTS_DIR)
  ? readdirSync(TESTS_DIR, { withFileTypes: true }).flatMap((d) =>
      d.isDirectory() ? readdirSync(resolve(TESTS_DIR, d.name)).filter((f) => f.endsWith('.yaml')).map((f) => resolve(TESTS_DIR, d.name, f)) : []
    )
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
console.log(`规则文件：crs/REQUEST-942-SQLI.conf（SecRule 行 ${census.secRuleLines}，装载 ${census.loaded}，链头 ${census.chainHeads}，解析丢弃 ${census.droppedBySplit}，元规则跳过 ${census.skippedMeta}）`);
console.log(`未实现 operator：${census.unimplemented} 条 ${JSON.stringify(census.unimplementedIds || [])}　正则编不出来：${(census.regexBad || []).length} 条 ${JSON.stringify(census.regexBad || [])}`);
console.log(`官方用例：${cases.length} 条（另有 ${stagesUnmodeled} 条 stage 无 log_contains/no_log_contains，不计入）\n`);

const perPl = {};
for (const pl of PLS) {
  const r = { mustHit: 0, perRuleOk: 0, blockedAny: 0, mustNotHit: 0, fpSameRule: 0, blockedByOther: 0, mustBlock: 0, mustBlockOk: 0, divergences: [] };
  for (const c of cases) {
    const got = evaluate(toReq(c.input), { paranoiaLevel: pl, collectAll: true });
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
for (const c of cases) {
  const pl = c.exp.id ? (census.plById?.[c.exp.id] ?? 4) : 4;
  const got = evaluate(toReq(c.input), { paranoiaLevel: pl, collectAll: true });
  const known = c.exp.id === '942100' || c.exp.id === '942101'; // @detectSQLi 未实现，单列不算失真
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
if (al.knownGap) console.log(`  其中 ${al.knownGap} 条属**已点名的不支持项**（942100/942101 的 @detectSQLi 需要 libinjection，本执行器没有）；剔除后逐规则一致率 ${(alignedExKnown * 100).toFixed(1)}%`);
console.log(`  不应拦用例 ${al.mustNot}：误触该规则 ${al.fp}（${al.mustNot ? ((al.fp / al.mustNot) * 100).toFixed(1) : '0.0'}%）｜分歧合计 ${al.div.length} 条`);

// —— 已知差距基线（只减不增）——
// 与 scripts/arch-guard.mjs 的 .arch-baseline.json 同一套纪律：**分歧必须被逐条点名**，
// 出现任何不在基线里的新分歧 → 门禁 FAIL；基线里的条目消失了也报出来（提示可以收紧）。
// 每条都给"为什么不算执行器 bug"，理由不成立的就不该进基线。
const KNOWN_FILE = resolve(HERE, 'crs-known-divergences.json');
const KNOWN_REASONS = {
  '942100': 'operator @detectSQLi 需要 libinjection 内核，本执行器没有（真 CRS 用它做整体 SQLi 判定）',
  '942101': '同上（作用于 REQUEST_BASENAME 的 @detectSQLi）',
  '942440-19': '官方用例标题就是 "False positive against Google click identifier"：期望依赖 CRS 的**参数排除集**（在别的 conf 里，本仓只 vendored 942 家族）',
  '942440-20': '同上（gclid）',
  '942210-31': '简化匹配器与 PCRE 的边角差异：该负例要靠 CRS 的 t:lengthAdjust/链内二次约束，本执行器只做逐节点 @rx',
  '942210-44': '同上',
  '942190-42': '多层嵌套函数 `right(right((select …` 需要 PCRE 递归式匹配，本执行器为逐值 @rx',
  '942200-1': '`,varname"=somedata` 期望依赖引号配对计数（@pm/多变量交叉），未实现',
  '942500-3': '`/*+optimizer hint*/` 形态：本执行器的 t:replaceComments 先于 @rx 生效，把注释吃掉了',
  '942500-4': '同上',
  '942522-7': '链节点作用在 REQUEST_BASENAME 上，本执行器 uri 取值含查询串，与 ModSecurity 的 basename 语义不同',
};
const baseline = existsSync(KNOWN_FILE) ? JSON.parse(readFileSync(KNOWN_FILE, 'utf8')) : null;
const knownTitles = new Set((baseline?.divergences || []).map((d) => d.用例));
const unexpected = al.div.filter((d) => !knownTitles.has(d.用例));
const stale = (baseline?.divergences || []).filter((d) => !al.div.some((x) => x.用例 === d.用例));
if (!baseline) {
  mkdirSync(RESULTS_DIR, { recursive: true });
  writeFileSync(
    KNOWN_FILE,
    JSON.stringify({
      _comment: 'CRS 官方回归集上**已逐条核对过原因**的分歧清单。新增未点名分歧 = 门禁 FAIL；条目消失 = 按实测收紧本文件。',
      tag: 'coreruleset v4.1.0 / REQUEST-942',
      divergences: al.div.map((d) => ({ 用例: d.用例, 类型: d.类型, 期望: d.期望, 原因: KNOWN_REASONS[d.用例] || KNOWN_REASONS[d.期望] || '待补理由' })),
    }, null, 2)
  );
  console.log(`\n[基线] 已生成 ${KNOWN_FILE}（${al.div.length} 条）——请逐条核对理由后再提交`);
} else {
  console.log(`\n[基线] 已点名分歧 ${knownTitles.size} 条｜本次新出现未点名 ${unexpected.length} 条｜基线中已消失 ${stale.length} 条`);
  for (const d of unexpected) console.log(`   ❌ 未点名：${d.类型} ${d.用例}（期望 ${d.期望} → 命中 [${d.我们命中}]）输入 ${d.输入.slice(0, 60)}`);
  for (const d of stale) console.log(`   ↻ 可收紧基线：${d.用例}（${d.类型}）已不再分歧`);
}

const fails = [];
if (alignedExKnown < MIN_PER_RULE) fails.push(`保真度 ${(alignedExKnown * 100).toFixed(1)}% < ${(MIN_PER_RULE * 100).toFixed(0)}%`);
if (baseline && unexpected.length) fails.push(`${unexpected.length} 条未点名分歧`);
mkdirSync(RESULTS_DIR, { recursive: true });
writeFileSync(
  resolve(RESULTS_DIR, 'crs-equivalence.json'),
  JSON.stringify({ at: new Date().toISOString(), cases: cases.length, unmodeled: stagesUnmodeled, threshold: MIN_PER_RULE, census, aligned: { ...al, 逐规则一致率: aligned, 剔除已知不支持: alignedExKnown }, perPl }, null, 2)
);
const md = [
  '# 自实现 CRS 执行器 × CRS 官方回归用例（保真度）',
  '',
  `> 生成：${new Date().toISOString()}　用例来源：coreruleset v4.1.0 tests/regression/tests/REQUEST-942-*（共 ${cases.length} 条可判定 stage，${stagesUnmodeled} 条无规则期望不计）`,
  `> 红线：**按规则自身档位对齐后**的逐规则一致率（剔除已点名的 @detectSQLi 不支持项）< ${(MIN_PER_RULE * 100).toFixed(0)}% 即判 FAIL。`,
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
  `| 应拦用例 | 逐规则命中 | 任意规则拦下 | 已知不支持（@detectSQLi） | 剔除后一致率 | 不应拦用例 | 误触该规则 |`,
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
  '',
  '## 分歧明细（主口径：按规则自身档位对齐；前 ' + TOP + ' 条，全量见 results/crs-equivalence.json）',
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
writeFileSync(resolve(RESULTS_DIR, 'crs-equivalence.md'), md);
console.log(`\n[report] ${resolve(RESULTS_DIR, 'crs-equivalence.md')}`);
if (fails.length) {
  console.log(`\n❌ FAIL：${fails.join('；')} —— 执行器与官方规则的差距已超出可引用范围（分歧明细见 results/crs-equivalence.md）`);
  process.exit(1);
}
console.log(`\n✅ 保真度（剔除已知不支持后）${(alignedExKnown * 100).toFixed(1)}% ≥ 红线 ${(MIN_PER_RULE * 100).toFixed(0)}%`);
