// @vitest-environment node
// ============================================================================
// src/tests/scanConfig.contract.test.ts —— 面板键 → 请求体 config 的契约
// [P0-FIX 2026-09-09]
//
// 为什么必须有：后端只认 KNOWN_CFG_KEYS，**白名单外的键被 logger.debug 静默丢弃**——既不报错也不生效。
// 于是「面板上有个开关、引擎里也实现了、中间没接」这个缺陷在本项目连续出现了三批
// （delay/reqRate/maxReq → prefilterSinglePoint/testFilter/useRegistry/freshQueries/dbms → matchString 类型）。
// 每一次都靠人记住「新开关要接进请求体」；人记不住，所以让 CI 记住。
//
// 三条断言：
//   ① 面板里能改的每个键，都必须在 SCAN_CONFIG_KEYS 登记（否则它根本不会进 body）；
//   ② SCAN_CONFIG_KEYS 的每个键，后端 KNOWN_CFG_KEYS 必须认（否则前端发了也被丢）；
//   ③ 值类型必须与后端解析口径一致（matchString 是字符串，不是布尔——布尔会让引擎按「页面含 'true'」判定）。
// ============================================================================

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { SCAN_CONFIG_KEYS, SCAN_CONFIG_VALUE_TYPES, DEFAULT_CONFIG } from '../shared/constants';
import { buildStartConfig, buildResumeConfig } from '../shared/scanConfig';

// [audit-FIX 2026-09-13] 本套件只读源码文本，不需要 DOM。原默认 jsdom 环境下
// node:url/node:path 的函数导出在本机 Node 24 上被覆盖为 undefined（fileURLToPath/
// resolve is not a function，套件直接挂起）。声明 @vitest-environment node 后恢复
// 原生实现，路径逻辑零改动。
const read = (rel: string) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

/**
 * 后端 REST 白名单：直接从 server/src/api/scanRoutes.js 源码里把 KNOWN_CFG_KEYS 抓出来。
 * 为什么抽而不拄：拄录早晚会与后端漂移（本测试要防的就是漂移）；抽源码后，后端加键忘接线
 * 会直接在前端测试里抱，而不需要两边手动同步。
 * 用源码级提取而不是 import：前端测试不该依赖后端模块图（依赖环境/环境变量）。
 */
function backendKnownCfgKeys(): string[] {
  const src = read('../../server/src/api/scanRoutes.js');
  const start = src.indexOf('KNOWN_CFG_KEYS');
  if (start < 0) throw new Error('未在 scanRoutes.js 里找到 KNOWN_CFG_KEYS——后端改名了，本测试需同步');
  // 注意：它是 `new Set([...])`，所以边界是 `]);` 而不是第一个 `]`（否则只能抽到首行几个键）
  const end = src.indexOf(']);', start);
  const seg = src.slice(start, end);
  return [...seg.matchAll(/'([a-zA-Z0-9_]+)'/g)].map((m) => m[1]);
}

describe('配置契约：面板 → 请求体 → 后端白名单', () => {
  const panelSrc = read('../components/ScanConfigPanel.tsx');
  const BACKEND_KNOWN_CFG_KEYS = backendKnownCfgKeys();

  /** 面板实际会写的键：handle*('k') / store 直写 set('k', …) / 内联 onChange({ k: … }) 三类写法 */
  const panelKeys = (() => {
    const found = new Set<string>();
    const patterns = [
      /handle[A-Za-z]*\(\s*'([a-zA-Z]+)'/g,
      /(?:setConfig|updateConfig|patchConfig)\(\s*'([a-zA-Z]+)'/g,
      /\bset\(\s*'([a-zA-Z]+)'/g,
      // [2026-09-23] 补这一类：面板里「选一个动作就整体替换某个对象键」的写法
      // （如 extractScope 的 Select：`onChange({ extractScope: … })`）。
      // 此前只认 handle*/setConfig/set()，这一种写法整类不在视野内 ——
      // 「守卫看不见它声称在管的东西」是本仓反复出现的病灶形态，故补齐。
      /onChange\(\s*\{\s*([a-zA-Z]+)\s*:/g,
      // [2026-09-23 UI-REACH] 嵌套对象配置（noSql / oob / secondOrder）的子字段走 patchNested。
      // 新增一类写入方式必须同步补 pattern，否则新接的键会被误判成「面板没有控件」而假红。
      /patchNested\(\s*'([a-zA-Z]+)'/g,
    ];
    for (const re of patterns) {
      for (const m of panelSrc.matchAll(re)) found.add(m[1]);
    }
    return [...found];
  })();

  it('面板确实被扫到了键（防止正则失效导致本测试静默空转）', () => {
    expect(panelKeys.length).toBeGreaterThan(10);
  });

  it('① 面板里能改的每个键都在 SCAN_CONFIG_KEYS 登记', () => {
    const missing = panelKeys.filter((k) => !(SCAN_CONFIG_KEYS as readonly string[]).includes(k));
    expect(missing, `这些面板键不会进请求体：${missing.join(', ')}`).toEqual([]);
  });

  it('② SCAN_CONFIG_KEYS 每个键都被后端白名单接受', () => {
    const unknown = SCAN_CONFIG_KEYS.filter((k) => !BACKEND_KNOWN_CFG_KEYS.includes(k));
    expect(unknown, `后端会静默丢弃这些键：${unknown.join(', ')}`).toEqual([]);
  });

  it('③ 每个键都声明了值类型，且面板默认值类型与声明一致', () => {
    const types = SCAN_CONFIG_VALUE_TYPES as Record<string, string>;
    for (const key of SCAN_CONFIG_KEYS) {
      expect(types[key], `键 ${key} 缺少 SCAN_CONFIG_VALUE_TYPES 声明`).toBeTruthy();
    }
    // matchString/notString 必须是字符串语义：历史上被当布尔用过，引擎于是按「页面含 'true'」判真假
    expect(types.matchString).toBe('string');
    expect(types.notString).toBe('string');
    expect(typeof (DEFAULT_CONFIG as Record<string, unknown>).matchString !== 'boolean').toBe(true);
    // [2026-09-26] 判定锚点族的类型必须与后端 guard 的解析口径一致，否则「面板能填、引擎读不到」：
    //   matchTitle/crawlForms → 严格布尔（引擎 `=== true` 才启用）；
    //   matchCode            → 对象 { true, false }（guard 走 clampInt(mc.true/false, 100-599)）；
    //   三个正则键           → 字符串（guard 走 clampStr，500 截断，非法正则引擎侧回落）。
    expect(types.matchTitle).toBe('boolean');
    expect(types.matchCode).toBe('object');
    expect(types.matchRegexp).toBe('string');
    expect(types.trueRegexp).toBe('string');
    expect(types.falseRegexp).toBe('string');
    expect(types.crawlForms).toBe('boolean');
  });

  it('buildStartConfig：DEFAULT_CONFIG 里已定义的登记键全部出现在请求体', () => {
    const body = buildStartConfig(DEFAULT_CONFIG as never);
    const lost = SCAN_CONFIG_KEYS.filter(
      (k) => (DEFAULT_CONFIG as Record<string, unknown>)[k] !== undefined && body[k] === undefined
    );
    expect(lost, `这些键在默认配置下有值却没进请求体：${lost.join(', ')}`).toEqual([]);
  });

  it('buildStartConfig：前端未建模的键原样透传（历史回显/CLI 配置不被吃掉）', () => {
    const body = buildStartConfig({ delay: 3, reqRate: 5, blindRobust: true } as never);
    expect(body.delay).toBe(3);
    expect(body.reqRate).toBe(5);
    expect(body.blindRobust).toBe(true);
  });

  it('buildStartConfig：布尔的 false 必须照发，空串必须省略', () => {
    const body = buildStartConfig({ prefilter: false, matchString: '   ', retry: 0 } as never);
    expect(body.prefilter).toBe(false, '「关掉预筛」是一个动作，false 不发就等于没发');
    expect('matchString' in body).toBe(false, '空串锚点应省略（后端 clampStr 同义），否则会污染判定');
    expect(body.retry).toBe(0, '0 是合法值，不能被当成未配置丢掉');
  });

  it('buildStartConfig：matchCode 以对象形态发（后端 guard 按 { true, false } 逐侧 clamp）', () => {
    const body = buildStartConfig({ matchCode: { true: 200, false: 500 } } as never);
    expect(body.matchCode).toEqual({ true: 200, false: 500 });
    // 两侧都清空 = 不启用 → 整个键必须省略（不能发空对象让后端拿到一个「什么都没配」的锚点）
    const off = buildStartConfig({ matchCode: undefined } as never);
    expect('matchCode' in off).toBe(false);
  });

  it('buildResumeConfig：续跑必须带上 scope（授权范围不能在最常见路径上被丢掉）', () => {
    const saved = {
      scope: ['app.example.com'],
      delay: 2,
      sessionDefault: true,
      concurrency: 8,
    } as never;
    const cfg = buildResumeConfig(saved);
    expect(cfg.scope).toEqual(['app.example.com']);
    expect(cfg.delay).toBe(2, '续跑丢限速 = 第二轮比第一轮更凶');
    expect(cfg.sessionFile).toBe('sqli-session-latest.json');
    // 快照里没有 scope 时不得凭空造一个「看起来受限制」的值
    expect('scope' in buildResumeConfig({ concurrency: 4 } as never)).toBe(false);
  });

// ④ 反向守卫 [2026-09-23]：后端**可达**但前端**无入口**的键，必须显式登记在这里。
//
// 为什么必须有：上面三条都是单向的（前端发的 ⊆ 后端认的）。反向从未被守卫过，于是
// 「后端加了一个新参数，UI 永远不会出现它」这件事 CI 完全沉默 —— 使用者看到的形态是
// 「REST 调它没反应」或「UI 上根本找不到开关」，而**没有任何一个测试会红**。
// 本项目已经把这类断链踩了三批，前三批全靠人脑记住才补上。
//
// 登记表的作用不是「允许它们缺失」，而是**把缺失变成可见且可执行的技术债**：
//   · 新键忘了接 UI → ④ 立刻红；
//   · 有人把某键接进了 UI 却没从表里移除 → ⑤ 立刻红（登记表不得腐烂）；
//   · 表里列了一个不存在的后端键 → ⑥ 立刻红。
//
// 这不是要不要补 UI 的判断（那是产品决策），而是「缺口清单必须随时准确」。
const KNOWN_MISSING_UI_KEYS = new Set([
  // 提取 / 拖库治理
  'extractConcurrency', 'dumpConcurrency', 'dumpDatabaseConcurrency', 'dumpMaxRows', 'dumpRowLimit',
  'dumpStart', 'dumpStop', 'maxColumnsGuess',
  // 时间盲注标定与采样
  'timeBlindSamples', 'timeBlindCalibrate', 'timeBlindCalibrateMin',
  'timeBlindSleepSec', 'timeProbeSleepSec', 'timeExtractSleepSec',
  // 布尔盲注二级判据 / 鲁棒性
  'boolStableDiff', 'boolStableDiffSamples', 'blindRobust',
  // 会话 / CSRF / 保活 / cookie
  // （crawlForms 已于 2026-09-26 接进「爬虫」分组 → 移出本表）
  'safeUrl', 'safeFreq', 'csrfUrl', 'csrfTokenName', 'csrfMethod', 'csrfRefreshFreq',
  'cookieJar', 'dropSetCookie', 'flushSession',
  // 参数筛选 / 已知点 / 失效值
  'skipParams', 'knownPoint', 'invalidValue', 'excludeSysdbs', 'nullConnection', 'paramDel',
  // HTTP 层行为
  'forceSsl', 'ignoreRedirects', 'hpp', 'activeWafProbe', 'trustProxyEnv', 'ssrfViaProxy', 'proxyBypassLocal',
  // 限速：delay / maxReq 已于 2026-09-23 接进「请求控制」分组 → 移出本表。
  // reqRate **有意不接**：引擎语义是「> 0 时覆盖 ratePerSec」（ScanManager.js:284 /
  // httpClient.js:820），而 ratePerSec 早就在面板上。再暴露一个限速旋钮只会让使用者分不清
  // 哪个在生效 —— 同样效果已有入口，故不算能力缺失，作为「显式承认的债」留在此处。
  'reqRate',
  // 报错模板按机制族裁剪（2026-09-23 新增的性能开关）。**默认关**（默认全量）：
  // CI 实测裁剪会让 CRS PL1 技术位 8 → 6，本仓口径是「不用检出能力换请求数」。
  // 属「调优参数」而非「能力缺失」—— 不接 UI 不会造成假阴性（关着 = 历史全量行为），
  // 故登记为此处显式承认的债，而不是强行塞进面板。
  'compactErrorTemplates',
  // [2026-09-24] 三键是「引擎一直真读、但 REST 白名单此前根本没有它们」补进来的
  // （sanitizeStart 里有完整取证注释）。登记为**已知无 UI 入口**而不是顺手接进面板：
  //   · http2 / disableKeepAlive —— 传输形态旋钮，接进面板等于向「一键扫描」人群暴露
  //     一个他们无法验证的效果（换协议后 WAF 指纹也不同，误配比不配更难查）；
  //   · xpAutoEnable —— 默认 true 只是**不改变历史行为**；它真正的用途是给 REST/CLI
  //     一个「不可逆动作的拒绝位」（MSSQL 侧 sp_configure + RECONFIGURE 是实例级永久变更）。
  //     这类开关该出现在「授权与安全护栏」分组里，而不是被塞进普通配置面板——
  //     接 UI 是产品决策，本表只负责让缺口可见。
  'http2', 'disableKeepAlive', 'xpAutoEnable',
  // [2026-09-24 接入口批次] 这 11 个是「引擎一直在读、注释一直写着可配、但四个入口都没接」
  // 那批键的收口（判据与逐个定性见 server/tests/configOrphanKeys.guard.test.js）。
  // 本批把可达性补上（defaults + REST 白名单 + 严格 clamp），**没有顺手接进面板**：
  // 它们全是提取/统计层面的调优旋钮（默认值逐个等于引擎内部兜底 ⇒ 不接不会造成假阴性），
  // 而面板的核心用户是「一键扫描」人群，多一个无法自行验证的旋钮只会让设置更难归因。
  // 接不接是产品决策，本表负责让"没有入口"这件事始终可数。
  'blindBitwise', // 位平面提取（仅 MySQL 族，改提取请求形状）
  'blindMaxLen', // 盲注单字段长度上界
  'booleanOrFallback', // 空基线 OR 型兜底对（关掉=省 2 请求/点，代价是漏报防线）
  'unionSkipGate', // union 反射门控逃生口（误报防线，刻意不给网络调用方便利开关）
  'deepDumpPageSize', // deepDump 分页聚合每页行数
  'dumpCheckpointInterval', // 拖库断点写入间隔（只影响续跑省多少请求）
  'fingerprintSleepSec', // 时间定库 sleep（与时间盲注刻意分开，定库要快）
  'fingerprintTimeThresholdMs', // 时间定库判定阈值
  'prefilterBudgetMs', // 预筛选时间预算
  'maxExtractBodyBytes', // 提取阶段响应上限（per-scan，env EXTRACT_MAX_BODY_MB 之外）
  'scanValidity', // 结论可信度守卫阈值组（含 enabled 逃生口）
  // 响应判定多指标（--string/--not-string/--code/--regexp/--titles 的同族）
  // ⚠️ matchCode / matchRegexp / trueRegexp / falseRegexp / matchTitle 已于 2026-09-26
  //    接进「payload 与响应判定调优」分组 → 移出本表（判据 ⑤ 会在忘记移除时红）。
  //    matchCode 只接了 { true, false } 精确期望形态；`true`（弱信号）形态前端类型层走不通，
  //    仍属无入口 —— 但它是**同一键的另一种取值**，不是独立键，故不单列（见 constants.ts 注释）。
  'matchText', 'predictOutput',
  // 动态块 / 错误原文留存
  'autoDynamicBlock', 'parseErrors', 'pocRedactAuth',
  // 生产护栏（高危池确认位）：productionMode / confirmDestructive 已于 2026-09-23
  // 接进「授权与安全护栏」分组 → 移出本表
  // 高级姿势（--second-order / --oob 已于 2026-09-23 接进 ScanConfigPanel 的
  // 「二阶注入」「带外通道」分组 → 从本表移出，见判据 ⑦）
  'freshQueries',
  // 2026-09-20_CFG-REACH 那批「CLI 能设、引擎真读、REST 刚收」的键
  // （testPath / testHeaders 已于 2026-09-23 接进 ScanConfigPanel 的「注入点范围」分组 → 从本表移除）
  'noCast', 'dumpWhere', 'unionCols', 'hex', 'unionFrom',
]);

  it('④ 后端可达但前端无入口的键，必须登记在 KNOWN_MISSING_UI_KEYS（防新增键静默断链）', () => {
    const uncovered = BACKEND_KNOWN_CFG_KEYS.filter(
      (k) => !(SCAN_CONFIG_KEYS as readonly string[]).includes(k) && !KNOWN_MISSING_UI_KEYS.has(k)
    );
    expect(
      uncovered,
      `这些后端键在 UI 里没有任何入口，且未登记：${uncovered.join(', ')}\n` +
        '要么把它接到 ScanConfigPanel 并登记进 SCAN_CONFIG_KEYS，要么加入 KNOWN_MISSING_UI_KEYS 显式承认这笔债。'
    ).toEqual([]);
  });

  it('⑤ 登记表不得腐烂：已接进 UI 的键必须从 KNOWN_MISSING_UI_KEYS 移除', () => {
    const stale = [...KNOWN_MISSING_UI_KEYS].filter((k) => (SCAN_CONFIG_KEYS as readonly string[]).includes(k));
    expect(stale, `这些键 UI 已经有入口了，不应再记在「无入口」清单里：${stale.join(', ')}`).toEqual([]);
  });

  it('⑥ 登记表不得虚胖：表里列的键必须是真实的后端缺口（防判据漂移/假绿）', () => {
    const backendSet = new Set(BACKEND_KNOWN_CFG_KEYS);
    const bogus = [...KNOWN_MISSING_UI_KEYS].filter((k) => !backendSet.has(k));
    expect(bogus, `登记了后端并不存在的键：${bogus.join(', ')}`).toEqual([]);
    // 缺口数量应具备规模感：若后端键被大量删除导致差集骤减，说明提取逻辑或登记表已失同步
    const actualUncovered = BACKEND_KNOWN_CFG_KEYS.filter(
      (k) => !(SCAN_CONFIG_KEYS as readonly string[]).includes(k)
    );
    expect(actualUncovered.length).toBe(
      KNOWN_MISSING_UI_KEYS.size,
      '实际缺口数与登记表条目数不一致 —— 有键接上 UI 或后端删了键，请同步本表'
    );
  });

  // ⑦ [2026-09-23 UI-REACH] **登记在 SCAN_CONFIG_KEYS ≠ 面板真的有控件**。
  //
  // 为什么非要这条：④⑤ 把「有 UI 入口」的判据定成了「键是否登记在 SCAN_CONFIG_KEYS」。
  // 于是 5 个键长期处于**假暴露**状态 —— 登记在案（故不算缺口、④ 不报）、面板里却从未渲染
  // 任何控件（故用户永远改不了它）：noSql（NoSQL/GraphQL/SSTI 整条通道）、prefix、suffix、
  // sessionFile、timeThresholdMs。判据与危害不同源（判的是「登记没登记」、危害是「有没有开关」），
  // 所以 CI 一直绿 —— 又一个「守卫看不见它声称在管的东西」的实例。
  //
  // 现在的判据直接指向危害：面板源码里必须出现对该键的**写入**（由本文件顶部的 patterns 提取）。
  it('⑦ 登记为「UI 可控」的键必须在面板里真的有控件（防「登记即视为有入口」的假暴露）', () => {
    // 先自证不空转：提取必须还能看见面板键，否则正则全失效时本判据会恒绿
    expect(panelKeys.length, '面板键提取失效 —— 本判据会恒绿，先修 patterns').toBeGreaterThan(25);
    const facade = SCAN_CONFIG_KEYS.filter((k) => !panelKeys.includes(k));
    expect(
      facade,
      `这些键登记为「UI 可控」，但 ScanConfigPanel 里没有任何控件写它 —— 界面用户根本改不了：${facade.join(', ')}\n` +
        '要么在面板里补上控件，要么从 SCAN_CONFIG_KEYS 移除并登记进 KNOWN_MISSING_UI_KEYS。'
    ).toEqual([]);
  });

  it('后端白名单提取有效（含安全关键键；防提取失效导致断言空转）', () => {
    expect(BACKEND_KNOWN_CFG_KEYS.length).toBeGreaterThan(40);
    for (const k of ['scope', 'delay', 'reqRate', 'maxReq', 'confirmDestructive', 'productionMode', 'insecureTls', 'freshQueries']) {
      expect(BACKEND_KNOWN_CFG_KEYS, `后端白名单缺 ${k}`).toContain(k);
    }
  });
});
