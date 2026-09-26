// ============================================================================
// e2e/multi-engine-lab/verify.mjs —— 多引擎 tamper A/B 验证（H2/HSQLDB/Derby）
// 用法：node e2e/multi-engine-lab/verify.mjs
// 前置：ENGINE_JARS 环境变量（; 分隔的三 jar 路径）、JAVA_HOME 或 java 在 PATH
// 矩阵：引擎 × { tamper off, tamper on(dash2hash) } × 场景（num/str/blind）+ safe 对照
// 断言：safe 永远零检出（误报红线）；tamper on 应 ≥ tamper off（绕过收益）
// 注意：dash2hash 已加方言门控 dbms=['MySQL','MariaDB','TiDB']——对 H2 场景，
//   引擎 dbms 未知（指纹未定），ctx.dbms 为 null 时不过滤，dash2hash 照常生效；
//   H2 的 MODE=MySQL 支持行注释（-- 与 # 均可），Derby/HSQLDB 仅支持 --。
//   ——这正是本实验要验证的：方言门控是否真实挡住了无效 tamper。
// ============================================================================
import { pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const { ScanManager } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../../server/src/engine/ScanManager.js')).href);
const { EngineBridgeClient, createMultiEngineApp, bridgePreflight } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), './lab-app.mjs')).href);
// 报告表头里的档位必须来自执行器本身，不能是我手写的字符串。
//   写死 "≈PL3" 时，`CRS_PL=1 node e2e/multi-engine-lab/verify.mjs` 会照常按 PL1 拦，
//   而产物抬头仍然印 PL3 —— 这份报告是"对外口径"，档位是它唯一的环境坐标，标错等于伪造现场。
const { EFFECTIVE_PL } = await import(pathToFileURL(resolve(dirname(fileURLToPath(import.meta.url)), '../waf-real/crs-engine.js')).href);

const JAVA_BIN = process.env.JAVA_BIN || 'java';

// [CI-FIX 2026-09-25] 前置自检：ENGINE_JARS 未设 / jar 不在 ⇒ **按设计跳过并留下原因**。
//   为什么不能"照跑然后崩"：真 JDBC 引擎缺环境时 JVM 会立刻退出，而我们随后往它 stdin 写
//   就拿到 EPIPE —— 原本 stdin 没有 'error' 监听器，于是整条 e2e 以裸堆栈失败，日志里
//   一个"为什么"都没有（CI 实测两次红正是这个形状）。跳过要跳得下原因，红要红得有现场。
{
  const pre = bridgePreflight();
  if (!pre.ok) {
    console.log(`[SKIP] multi-engine-lab 本轮零断言 —— ${pre.why}`);
    console.log('  跑法：ENGINE_JARS="<h2.jar><分隔符><hsqldb.jar><分隔符><derby.jar><分隔符><derbyshared.jar>" node e2e/multi-engine-lab/verify.mjs');
    console.log('  （分隔符用系统 path.delimiter；Linux/CI 上是 ":"，Windows 上是 ";" —— 见 lab-app.mjs 的 classpath 注释）');
    process.exit(0);
  }
}
// [LAB-FIX 2026-09-20] 加 NO_WAF=1 一档。为什么必须能关掉：本靶场默认挂 CRS，而 CRS 会把
// UNION 哨兵探针整条 403 掉 → **版本回显定库通道在这里从来没被执行过**。于是"HSQLDB/Derby
// 定不了库"这个结论一直缺少可跑的验证手段（TODO §A 第 2 条点了这件事但一直没做）。
// 关掉 WAF 才能把"探针跑不动（真缺陷）"和"探针没被送达（靶场挡的）"分开——
// 这两件事在报告里长得一模一样，都是 dbms=null。
// 报告标题会带上本档口径，避免 NO_WAF 跑出的数字被误当成带 WAF 的既有结论。
const NO_WAF = process.env.NO_WAF === '1' || process.env.NO_WAF === 'true';
// expectDbms = 定库通道的**实测基线**（2026-09-25 从 results/multi-engine-report.no-waf.json 读出来的）：
//   H2 / HSQLDB 在 num、str 两场景经回显定出库；Derby 三个场景 `dbms` 全 null —— 定不出来。
//   写 null 不是"跳过"，是钉住"当前定不出"：哪天探针改好了真报出 Derby，这条断言会红，
//   提示把基线和 README 的覆盖面一起改掉。正向漂移和负向漂移都必须出声。
const ENGINES = [
  { name: 'h2', engine: 'h2', label: 'H2 2.2.224 (MODE=MySQL)', expect: 'H2', expectDbms: 'H2' },
  { name: 'hsqldb', engine: 'hsqldb', label: 'HSQLDB 2.7.3', expect: 'HSQLDB', expectDbms: 'HSQLDB' },
  { name: 'derby', engine: 'derby', label: 'Derby 10.16.1.1', expect: 'Derby', expectDbms: null },
];

const baseConfig = { concurrency: 4, ratePerSec: 0, retry: 0, timeoutMs: 15000, enableExtract: false };

async function runScan(sm, target) {
  const t0 = Date.now();
  const scanId = await sm.start(target);
  for (;;) {
    const s = sm.scans.get(scanId);
    if (s && (s.status === 'completed' || s.status === 'error')) break;
    if (Date.now() - t0 > 120000) { sm.stop(scanId).catch(() => {}); return { status: 'timeout', vulns: [] }; }
    await new Promise((r) => setTimeout(r, 30));
  }
  const rep = sm.getReport(scanId) || {};
  return { status: sm.scans.get(scanId)?.status, vulns: rep.vulns || [], dbms: rep.dbms || null };
}
const techs = (v) => [...new Set((v || []).map((x) => x.technique))];

const SCENARIOS = [
  { name: 'num', url: '/num?id=1', must: ['boolean'] },
  { name: 'str', url: '/str?name=user1', must: ['boolean'] },
  { name: 'blind', url: '/blind?uid=1', must: ['boolean'] },
  { name: 'safe', url: '/safe?id=1', expectSafe: true },
];

// [ASSERT-FIX 2026-09-25] SCENARIOS 上的 `must` 自写下来就**没有任何一处读它** —— 文件头
//   那句"断言：safe 零检出；on ≥ off"是真的，但"每个场景至少要有布尔通道"这一条一直只是注释。
//   于是本靶场即便三个引擎全退化到只剩 error 通道，判定照样 ✅。现在把它接进判定。
// 检出类断言只挂在"实测会检出"的档上（2026-09-25 逐档量出来的，不是猜的）：
//   NO_WAF       —— 探针直达 ⇒ 9/9。
//   CRS ≈PL1     —— CRS 官方默认部署档，也是本仓 waf-real 的对外口径 ⇒ 同样 9/9（布尔通道 +
//                   h2/derby 的 error 通道）。
//   CRS ≈PL2/3/4 —— 全部 0/9。**PL1→PL2 之间有一个断崖**，不是渐变。
// 在 0 检出的档上挂"必须检出"= 永久红；反过来挂"必须为 0"= 把 CRS 的强度写成我们的能力基线。
// 所以那些档只留误报红线，并在判定行自己说清楚"本档不测检测"。
const MUST_ASSERT = NO_WAF || EFFECTIVE_PL === 1;
// 定库基线**只在无 WAF 档生效**：PL1 实测 `dbms` 仍全 null（UNION 哨兵被 CRS 吃掉，
//   回显通道压根没送达）。把它挂到 CRS 档上，红了也分不清是"探针坏"还是"没送达"——
//   这正是本文件 [LAB-FIX 2026-09-20] 那段注释要分开两档的同一个理由。
const DBMS_ASSERT = NO_WAF;

const TAMPERS = {
  off: null,
  on: { tamper: { enabled: true, plugins: ['dash2hash'], intensity: 'medium' } },
};

const bridge = new EngineBridgeClient(JAVA_BIN).start();
const results = {};
let bridgeDead = null;

// [CI-FIX 2026-09-25] 桥是否真的活着，要在跑场景**之前**问一次。
//   JVM 起不来（没 java / classpath 分隔符写错 / jar 版本不符）时，原本每个查询都失败，
//   而失败不改变任何判据 ⇒ 报告全零 + 退出码 0（本机模拟：JAVA_BIN=node ⇒ 全 0/3 且 RC=0）。
//   探针的作用还包括"给事件循环一次投递 exit/error 的机会"——桥若是启动即退，
//   deadReason 在这一次 await 之后才写得上。
await bridge.query('h2', 'SELECT 1').catch(() => {});
if (bridge.deadReason) {
  console.log(`[SKIP] multi-engine-lab 本轮零断言 —— JDBC 桥起不来：${bridge.deadReason}`);
  console.log('  这是**环境前提**问题（java / classpath / jar），不是检测能力的结论；不计通过也不计失败。');
  bridge.stop();
  process.exit(0);
}

try {
  for (const eng of ENGINES) {
    results[eng.name] = { label: eng.label, rows: {} };
    for (const [label, tamper] of Object.entries(TAMPERS)) {
      const app = createMultiEngineApp(bridge, eng.engine, { waf: !NO_WAF });
      const server = app.listen(0, '127.0.0.1');
      await new Promise((resolve, reject) => {
  server.once('listening', resolve);
  // [P0-FIX 2026-09-14] listen 失败硬退出：端口被占/权限问题时静默继续 = 扫错目标出废报告
  server.once('error', (e) => reject(new Error(`靶场监听失败（端口被占？先杀残留进程）: ${e.message}`)));
});
      const base = `http://127.0.0.1:${server.address().port}`;
      const sm = new ScanManager();
      const rows = {};
      for (const sc of SCENARIOS) {
        const cfg = { ...baseConfig };
        if (tamper) cfg.wafEvasion = { ...tamper };
        const out = await runScan(sm, { url: `${base}${sc.url}`, config: cfg });
        rows[sc.name] = { found: techs(out.vulns), status: out.status, dbms: out.dbms };
      }
      server.close();
      results[eng.name].rows[label] = rows;
      const det = SCENARIOS.filter((s) => !s.expectSafe).filter((s) => rows[s.name].found.length > 0).length;
      console.log(`[${eng.name}][tamper ${label}] 检出场景 ${det}/3`);
      for (const sc of SCENARIOS) {
        console.log(`  ${sc.name.padEnd(6)} 检出=[${rows[sc.name].found.join(',') || '-'}]  status=${rows[sc.name].status}  定库=${rows[sc.name].dbms || 'null'}`);
      }
    }
  }
  // 桥的死活要在 stop() 之前取（stop 会让 exit 事件把原因写 up）
  bridgeDead = bridge.deadReason || null;
} finally {
  bridge.stop();
}

// 检出合计：报告正文与末尾判定都要用，必须算在两者之前
// （第一版把它只写在判定块里，而报告 md 的"本档有效性"行先执行 ⇒ ReferenceError）
const sumDet = (label) =>
  ENGINES.reduce(
    (acc, eng) => acc + SCENARIOS.filter((s) => !s.expectSafe)
      .filter((s) => results[eng.name].rows[label][s.name].found.length > 0).length,
    0
  );
const offDet = sumDet('off');
const onDet = sumDet('on');

// 汇总
console.log('\n===== 多引擎 A/B 汇总 =====');
let allSafeOk = true;
const mustMiss = [];
const fpMiss = [];
for (const eng of ENGINES) {
  const r = results[eng.name];
  // [LAB-FIX 2026-09-20] 汇总里加"定库"列：本靶场此前只报技术位、不报定库结果，
  // 于是"H2/HSQLDB/Derby 到底能不能被识别出来"这个真问题在这里无法回答——
  // 之前那次 H2 结论是靠临时手写探针跑出来的，跑完就没了。写进报告才算可复查的事实。
  const fp = [...new Set(Object.values(r.rows).flatMap((rows) =>
    Object.values(rows).map((x) => x.dbms).filter(Boolean)))];
  const line = SCENARIOS.filter((s) => !s.expectSafe).map((s) =>
    `${s.name}: off=${r.rows.off[s.name].found.length} on=${r.rows.on[s.name].found.length}`).join('  ')
    + `　定库=${fp.join('/') || 'null（未识别）'}`
    + `　期望=${eng.expect || eng.name.toUpperCase()}`;
  console.log(`${eng.name.padEnd(8)} ${line}`);
  const want = String(eng.expect || eng.name).toLowerCase();
  if (fp.length && !fp.some((d) => String(d).toLowerCase() === want)) {
    console.log(`  ⚠️ ${eng.name} 定库结果与真实引擎不符：报的是 ${fp.join('/')}（这是**误判**，比定不出库更糟）`);
    // 误判一直是"印一行警告然后退 0"。可它比定不出库更该红：定不出是覆盖面缺口，
    // 报错库会直接写进交付报告的 DBMS 字段。现在两侧漂移都进判定。
    fpMiss.push(`${eng.name} 定库**误判**：真实引擎 ${eng.expect}，报的是 ${fp.join('/')}`);
  }
  if (DBMS_ASSERT) {
    // 定库基线（含"当前定不出"这条负向基线）
    if (eng.expectDbms) {
      if (!fp.some((d) => String(d).toLowerCase() === String(eng.expectDbms).toLowerCase())) {
        fpMiss.push(`${eng.name} 定库基线丢失：应报出 ${eng.expectDbms}，实测 ${fp.join('/') || 'null（未识别）'}`);
      }
    } else if (fp.length) {
      fpMiss.push(`${eng.name} 的基线写的是"定不出库"，实测报出了 ${fp.join('/')} ⇒ 这是**正向漂移**：` +
        '把 verify.mjs 里的 expectDbms 和 README 覆盖面一栏一起改掉，别只改代码');
    }
  }
  if (MUST_ASSERT) {
    // 每场景的技术位底线（此前 `must` 是死字段，没有任何一处读它）
    for (const sc of SCENARIOS.filter((s) => s.must)) {
      for (const [label, rows] of Object.entries(r.rows)) {
        const found = rows[sc.name].found;
        for (const m of sc.must) {
          if (!found.includes(m)) {
            mustMiss.push(`${eng.name}/${sc.name}[tamper ${label}] 缺 ${m} 通道（实测 [${found.join(',') || '无'}]）`);
          }
        }
      }
    }
  }
  for (const [label, rows] of Object.entries(r.rows)) {
    if (rows.safe && rows.safe.found.length > 0) {
      allSafeOk = false;
      console.log(`  ❌ ${eng.name}[${label}] safe 误报: ${rows.safe.found.join(',')}`);
    }
  }
}
console.log(`\n安全对照误拦/误报：${allSafeOk ? '无 ✅' : '有 ❌'}`);

// 落盘
import { mkdirSync, writeFileSync } from 'node:fs';
const RESULTS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), 'results');
mkdirSync(RESULTS_DIR, { recursive: true });
const genAt = new Date().toISOString();
const wafMode = NO_WAF ? 'off（NO_WAF=1）' : `on（CRS v4.1.0 ≈PL${EFFECTIVE_PL}）`;
// [口径隔离 2026-09-20] NO_WAF 档必须写**独立文件名**，不能覆盖默认那份产物。
// 原因很实际：这一档刚跑完时我差点把"关掉 WAF 测出来的数字"当成仓库里那份 CRS-on 基线提交
// ——两档的 dbms 结果本来就不同（CRS 会 403 掉 UNION 哨兵，版本回显通道压根不执行），
// 换掉之后 README/TODO 里引用的基线就悄悄变了口径，而且没有任何东西会报出来。
// 靠"记得注意"防不住，所以按文件名物理隔开。同理 **改档跑出来的产物也不能覆盖默认那份**：
// `CRS_PL=1` 与默认 PL3 是两套口径，原先它们写同一个文件名 —— 一次探索性的改档跑就把
// 入库基线换成了宽松档的数字，而抬头除了生成时间没有任何痕迹。非默认档一律另起文件。
const SUFFIX = NO_WAF ? '.no-waf' : (EFFECTIVE_PL === 3 ? '' : `.pl${EFFECTIVE_PL}`);
writeFileSync(resolve(RESULTS_DIR, `multi-engine-report${SUFFIX}.json`), JSON.stringify({ generatedAt: genAt, waf: wafMode, engines: results }, null, 2));
// 诚实边界：三档各有各"不许引什么"，逐档写死在生成端。
//   原来只有一句万能话（"仅验证布尔通道在 CRS 下的检测/绕过"），结果它既印在无 WAF 档上
//   （那档压根没有 CRS），又在 PL1 档上否认本档真的测到的东西（"不回答检测能力"）。
//   一个只在 0/9 档成立的免责声明，印到 9/9 档上就是自我抹黑。
const honesty = NO_WAF
  ? ['> 诚实边界（本档 WAF=off）：测的是**引擎覆盖面**（布尔/UNION/回显定库跑得通吗），',
     '> 与"能不能绕过 WAF"无关 —— 绕过结论只能引 CRS-on 那份产物。',
     '> 本档行内的技术位差异因此**不是**绕过收益：dash2hash 会把 `--` 改写成 `#`，',
     '> 而 Derby/HSQLDB 不认 `#`（方言门控只在 dbms 已定时生效，Derby 恰好定不出库 ⇒ 门控不挡）。',
     '> 逐请求归因没做，别把 derby 行里 union 的得失读成能力变化。']
  : EFFECTIVE_PL === 1
    ? ['> 诚实边界：本档是 CRS **官方默认部署档 PL1**，三引擎布尔通道 9/9 检出 ⇒',
       '> 可以据此说"这三库在默认 CRS 下可被检出"；但**定库不在本档口径内**',
       '> （UNION 哨兵被吃、回显通道没送达，判探针本身可用请看 `.no-waf` 那份产物）。',
       '> 也别把它外推到高 paranoid 档：PL2/PL3/PL4 实测 0/9（PL1→PL2 之间是断崖，不是渐变；',
       '> 复测：`CRS_PL=2 node e2e/multi-engine-lab/verify.mjs`，产物按档落到 `.pl2.md`，不会覆盖本文件）。']
    : ['> 诚实边界：本档挂 CRS，只回答"这一档下探针能不能送达 + safe 会不会误拦"，',
       '> 不回答检测能力（0 检出时尤其如此，见上面的"本档有效性"）。',
       '> 想问"引擎本身能不能被检出"，看 `.no-waf` 或 `.pl1` 那两份产物。'];
honesty.push(
  `> 档位取自 crs-engine 的 EFFECTIVE_PL（当前 ${EFFECTIVE_PL}）：\`CRS_PL=1..4\` 改档，抬头与文件名一起变。`,
  '> dash2hash 有方言门控（MySQL 系），H2 以 MODE=MySQL 运行故 `#` 注释可用。'
);
const md = [
  `# 多引擎 tamper A/B（H2 / HSQLDB / Derby）　—　WAF：${wafMode}`,
  '',
  `> 生成：${genAt}　｜　引擎：真实 JDBC 引擎（内存库）　｜　本档 WAF：${wafMode}`,
  '>',
  '> **口径必须先看这行**：WAF=on 时 CRS 会把 UNION 哨兵探针整条 403 掉，**版本回显定库通道',
  '> 根本不会被执行**，所以那一档里的 `dbms=null` 只说明"没定出库"，不能读成"探针在该库上跑不动"。',
  '> 要判探针本身是否可用，跑 `NO_WAF=1`（本文件 [LAB-FIX 2026-09-20]）。两档数字不可互换。',
  '',
  '| 引擎 | 场景 | tamper off | tamper on | 定库 off/on | 说明 |',
  '|---|---|---|---|---|---|',
  ...ENGINES.flatMap((eng) => SCENARIOS.filter((s) => !s.expectSafe).map((s) => {
    const r = results[eng.name];
    const offArr = r.rows.off[s.name].found;
    const onArr = r.rows.on[s.name].found;
    const off = offArr.join(',') || '-';
    const on = onArr.join(',') || '-';
    // 定库按行摊开，不只在汇总里给一个并集：Derby 三格全 null、H2 的 blind 也是 null，
    //   "哪条通道才带得出库名"这件事只有逐行才看得见（README 的覆盖面一栏就引这个）。
    const dbs = `${r.rows.off[s.name].dbms || '-'}/${r.rows.on[s.name].dbms || '-'}`;
    // ⚠ 这里原本写 `${on ? '检出' : '未检出'}`，而 `on` 是**字符串**（空时是 '-'）——
    //   '-' 也是 truthy ⇒ 九行全部印"检出"，而两列数字全是 '-'。入库的两份基线
    //   （multi-engine-report.md 与 .no-waf.md）因此自 09-20 起就在给反向结论：
    //   读表格的人以为 3 引擎 × 3 场景都检出了，实测是 0/9。判据必须看数组长度，别看拼接串。
    // 第二处同类缺陷（2026-09-25）：上一版只分红"on 非空 / on 空"两种，
    //   于是 derby/str 这一格 off=union,error,boolean → on=error,boolean（**union 被打掉了**）
    //   也印成「tamper 后检出」。tamper 的代价是逐技术位的，判据必须做集合比对。
    const lost = offArr.filter((t) => !onArr.includes(t));
    const gained = onArr.filter((t) => !offArr.includes(t));
    let note;
    if (!offArr.length && !onArr.length) note = '两侧均未检出';
    else {
      const parts = [];
      if (lost.length) parts.push(`丢失 ${lost.join(',')}`);
      if (gained.length) parts.push(`新增 ${gained.join(',')}`);
      note = parts.length ? `tamper ${parts.join('、')}` : '技术位与 tamper 前一致';
    }
    return `| ${eng.name} | ${s.name} | ${off} | ${on} | ${dbs} | ${note} |`;
  })),
  '',
  // 有效性口径：两侧都零检出时，本档**只能**验"误报红线"，验不了绕过收益 —— 这句必须印出来，
  // 否则表格里的 '-' 会被读成"检出了但没内容"（09-20 那两份基线就是这么被误读的）。
  (offDet === 0 && onDet === 0
    ? '> **本档有效性**：off 与 on 两侧都零检出 ⇒ 绕过收益**无从判定**（表头的 `on ≥ off` 是空转成立）。'
      + '本档实际只验了一条红线：safe（参数化对照）零误报。'
      + '"H2/HSQLDB/Derby 的布尔通道被检出过"这句结论，本档**不提供**证据。'
    : NO_WAF
      ? `> **本档有效性**：off 检出合计 ${offDet}、on 检出合计 ${onDet} ⇒ 覆盖面类断言成立。`
        + '但本档**没有 WAF**，所以两侧差值不是绕过收益，只是 tamper 改写 payload 的副作用（见说明列）。'
      : `> **本档有效性**：off 检出合计 ${offDet}、on 检出合计 ${onDet}`
        + (offDet === onDet
          ? ' ⇒ 两侧**持平**：本档证明"CRS 这一档下探针能送达并被检出"，但**不**证明 tamper 带来增益'
            + '（MySQL 在 PL1 上也是同一形状：off=on=8，见 acceptance.mjs 里 waf-real 那段基线注释）。'
          : ' ⇒ 绕过收益可比对。')),
  '',
  // 定库基线写进产物：README 的覆盖面一栏引的就是这件事，而它此前只出现在控制台汇总里，
  //   跑完就没 —— "Derby 定不出库"这条事实昨天是靠临时手写探针才知道的。
  (NO_WAF
    ? '> **定库基线（本档实测）**：' +
      ENGINES.map((e) => `${e.name} → ${e.expectDbms || '**未定出**（已知缺口）'}`).join('、') +
      '。README「部分通道验证」那一栏只能引这一行，不许再写"× CRS"。'
    : `> **定库基线**：本档不适用 —— CRS 把带版本回显的 UNION 探针整条拦掉，` +
      '所以那一档里的 `dbms=-` 只说明"没送达"，不说明"探不出来"。'),
  '',
  `安全对照（参数化）：${allSafeOk ? '零误报' : '存在误报（需修）'}`,
  '',
  ...honesty,
].join('\n');
writeFileSync(resolve(RESULTS_DIR, `multi-engine-report${SUFFIX}.md`), md);
console.log(`[report] ${RESULTS_DIR}${SUFFIX ? `（本档口径 WAF=${NO_WAF ? 'off' : `on/PL${EFFECTIVE_PL}`}，文件名带 ${SUFFIX}，不覆盖默认基线）` : ''}`);

// ============================================================================
// 判定与退出码（2026-09-25 补）
// ----------------------------------------------------------------------------
// 本文件头一直写着"断言：safe 永远零检出；tamper on 应 ≥ tamper off"，但**全文件没有任何
// 一处设置失败退出码** —— 无论结果怎样都退 0。后果实测到两层：
//   ① run-all 里这个靶场恒记「✅ 通过」，"通过"背后是一条断言都没落地（注册成功≠在干活）；
//   ② JVM 中途死掉时引擎侧全 0 检出，而 0 检出不与任何判据冲突 ⇒ 一份"什么都没测到"的
//      报告照样绿。（本机模拟：JAVA_BIN=node ⇒ [bridge] node: bad option: -cp ⇒ RC 仍是 0。）
// 退出码口径：0 = 断言通过；1 = 断言失败（误报红线 / 绕过收益为负）；
//            2 = 前提失效（桥在跑的过程中死了 ⇒ 数字不可用，别当结论用）。
// "前提失效"与"断言失败"必须分开：前者该去修环境，后者才是真回归。
// ============================================================================
const verdicts = [];
if (bridgeDead) verdicts.push(`前提失效：JDBC 桥运行中退出（${bridgeDead}）`);
if (!allSafeOk) verdicts.push('误报红线：safe（参数化对照）被检出');
if (!bridgeDead && onDet < offDet) verdicts.push(`绕过收益为负：tamper on=${onDet} < off=${offDet}`);
if (!bridgeDead && mustMiss.length) verdicts.push(`技术位底线丢失：${mustMiss.join('；')}`);
if (!bridgeDead && fpMiss.length) verdicts.push(`定库基线漂移：${fpMiss.join('；')}`);

// 判定行要能自己说明自己测了什么。CI 日志里只有这一行会进人的眼睛，
// 而 CRS-on 档原本印的是 `tamper 收益 on(0) ≥ off(0)=✅` —— 0≥0 空转成立，
// 读起来却像"绕过收益已验证"。空转必须当场标注，否则这条 ✅ 就是假绿的形状。
const vacuous = onDet === 0 && offDet === 0;
console.log(
  `\n[判定] 断言：safe 零误报=${allSafeOk ? '✅' : '❌'}　tamper 收益 on(${onDet}) ≥ off(${offDet})=` +
    `${onDet >= offDet ? (vacuous ? '✅（空转：两侧均 0，本档不证明绕过能力）' : '✅') : '❌'}　` +
    `桥存活=${bridgeDead ? '❌ ' + bridgeDead : '✅'}　` +
    (MUST_ASSERT
      ? `技术位底线=${mustMiss.length ? '❌ ' + mustMiss.length + ' 项' : '✅'}　` +
        `定库基线=${DBMS_ASSERT ? (fpMiss.length ? '❌ ' + fpMiss.length + ' 项' : '✅') : '本档不适用（UNION 哨兵被 CRS 吃掉，回显通道没送达）'}`
      : '检测类断言=本档不适用（WAF=on 且 PL≠1，实测 0/9；只挂误报红线，见产物"本档有效性"）')
);
if (verdicts.length) {
  console.error(`[multi-engine-lab] 失败：${verdicts.join('；')}`);
  process.exit(bridgeDead ? 2 : 1);
}
console.log('[multi-engine-lab] 全部断言通过');
