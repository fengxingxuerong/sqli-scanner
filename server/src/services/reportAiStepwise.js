// ============================================================================
// reportAiStepwise.js —— [D259] 分步短 prompt（把一份长报告拆成多轮短请求）
//
// 起因：D254/D255 的真网关实测证明「长 system+user 报告 prompt 挂起、短 prompt 4.1s
// 返回」（docs/llm-gateway-capability-2026-11-05.txt）。D258 的做法是**失败之后**补一次
// 短重试 —— 仍要先挂 100s，且短重试只有一发、丢掉 SRC 模板与逐条判据。
// D259 反过来：opt-in 后让**每一个请求本来就短**，把报告按章节拆成多次短调用再拼装。
//
// 本模块只做纯函数：拆章节、造短 prompt、拼装、标注缺失章节。不发 HTTP、不读报告文件，
// 事实由 ReportAI.js 组装后传入（复用那里已校准的脱敏/判据/压缩函数，避免两份真源）。
//
// 诚实边界：
//   · 每个短请求都以 `【分步` 开头，mock-hang 网关据此识别；文案一改就把短请求也挂起，
//     失败方向安全（e2e/ai-gateway-lab/mock-hang-gateway.mjs）。
//   · 单章失败 = 该章标注「需人工补全」，**绝不编造内容、不冒充全文审阅**。
//   · 「请求短」不等于「模型在短 prompt 上写得好」；本模块不做任何输出质量声明。
// ============================================================================

/** @typedef {{key:string,title:string,task:string}} WriterSection */
/** @typedef {{key:string,title:string,system:string,user:string}} StepwiseStep */
/** @typedef {{key:string,title:string,content:string,generated:boolean}} StepwiseSection */

/** 单个短请求的用户消息字符上限（与 D255 短重试预算对齐，可 env 覆盖）。 */
export const STEPWISE_MAX_CHARS = Number(process.env.AI_REPORT_STEPWISE_MAX_CHARS) > 0
  ? Number(process.env.AI_REPORT_STEPWISE_MAX_CHARS)
  : 1200;

/**
 * [D275/D278] 单章审阅内容的**硬上限**（默认 16000，D278 由 4000 上调）。
 *
 * D275 的动机：旧实现把章节 clamp 到 `STEPWISE_MAX_CHARS - 220`（默认 980 字符）再送审，
 * 然后用审阅输出替换整章 —— D266 实测 writer 章节 1021~3656 字符，审阅只看到前 980 字符，
 * 「5/5 审阅」实际是节选审阅，且替换后可能丢内容。现在超过硬上限的章节**不送审**
 * （保留原章并标 partial），绝不用节选审阅冒充全文。
 *
 * 为什么是 16000：D278 在 dsh `qodercn/dfmodel` 上用 D275 默认值真跑，`五、修复方案`
 * 章 4696 字符被 D275 的 4000 预算判成 `reviewer:fix:too-long` ⇒ 审阅 4/5、`partial=true`。
 * 4000 是「拍脑袋的预算」，不是真实章节长度；16000 给正常章节足够余量，同时仍保留
 * 硬上限：真正超长（>16000）的章节不送审并标 partial。
 */
export const STEPWISE_REVIEW_MAX_CHARS = Number(process.env.AI_REPORT_STEPWISE_REVIEW_MAX_CHARS) > 0
  ? Number(process.env.AI_REPORT_STEPWISE_REVIEW_MAX_CHARS)
  : 16000;

/**
 * [D277] 分步章节的有界并发上限（默认 1 = 串行）。
 *
 * 动机：D266 真网关实测 12 个请求串行 484s，其中 writer/reviewer 各 5 章是主要耗时；
 * 章节之间互不依赖，允许 2~4 章并行能显著缩短整场时间。但网关可能有
 * per-user concurrency limit（D255 实测 429），所以**默认串行**，显式 opt-in。
 * 上限 4：再高会把慢网关/限流网关打爆，且收益递减。
 */
export const STEPWISE_MAX_CONCURRENCY = 4;

/**
 * [D277] 解析并发度：非数字 / <1 → 1；>4 → 4；小数向下取整。
 * 非法值不报错（与其它 env 解析口径一致：宁可保守串行，不因配置笔误整场失败）。
 * @param {unknown} v 原始值（env 或测试注入）
 * @returns {number} 1..4
 */
export function normalizeStepwiseConcurrency(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n < 1) return 1;
  return Math.min(STEPWISE_MAX_CONCURRENCY, Math.floor(n));
}

/**
 * [D277] 有界并发 map：最多 `limit` 个任务同时执行，结果按输入顺序返回。
 * limit<=1 时退化为串行（与旧行为逐字等价，默认路径零变化）。
 * @template T,R
 * @param {T[]} items 输入
 * @param {number} limit 并发上限（已归一化）
 * @param {(item:T, index:number)=>Promise<R>} fn 任务
 * @returns {Promise<R[]>} 与输入同序的结果
 */
async function mapPool(items, limit, fn) {
  /** @type {R[]} */
  const out = new Array(items.length);
  if (limit <= 1) {
    for (let i = 0; i < items.length; i++) out[i] = await fn(items[i], i);
    return out;
  }
  let next = 0;
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= items.length) return;
      out[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
  return out;
}

/** 章节表：顺序即报告顺序；key 用于失败披露、守卫判据与审阅对齐。 */
/** @type {WriterSection[]} */
export const WRITER_SECTIONS = [
  { key: 'overview', title: '一、漏洞概述', task: '给出漏洞名称、危险等级、漏洞类型与影响范围。' },
  { key: 'description', title: '二、漏洞描述', task: '说明漏洞原理、注入位置（参数名+HTTP 方法+URL 路径）与数据库类型。' },
  { key: 'poc', title: '三、漏洞证明（PoC）', task: '按事实里的 poc_payload 构造完整 HTTP 请求（含 Host、Content-Type、body），逐字引用引擎响应判据；参数名必须与事实一致。' },
  { key: 'impact', title: '四、影响评估', task: '评估数据泄露、系统接管与横向渗透风险，不得夸大。' },
  { key: 'fix', title: '五、修复方案', task: '给参数化查询代码示例、WAF/最小权限/审计日志等纵深防御与验证方法。' },
];

/** 缺章占位：明确写「未由模型产出」，引用报告时一眼可见。 */
export const MISSING_SECTION = '（本节生成失败，需人工补全；未由模型产出）';

const STEP_SYSTEM = '你是渗透测试报告撰写专家。只输出本节 Markdown，不要输出其它章节。';
const REVIEW_SYSTEM = '你是安全审计专家。只输出该节修订后的 Markdown 全文。';

/**
 * opt-in 开关：默认关闭 ⇒ 原三角色流水线逐字不变（含 D258 短重试）。
 * @param {NodeJS.ProcessEnv} [env] 环境变量表（测试可注入）
 * @returns {boolean} 是否启用分步模式
 */
export function stepwiseEnabled(env = process.env) {
  return env.AI_REPORT_STEPWISE === '1';
}

/**
 * 截到预算内；从开头截，保证 `【分步` 前缀不被切掉（网关按前缀判短）。
 * @param {string} text 原始文本
 * @param {number} [budget] 字符预算
 * @returns {string} 截断后的文本
 */
function clamp(text, budget = STEPWISE_MAX_CHARS) {
  return String(text).slice(0, budget);
}

/**
 * 事实包压成单行 JSON 且在预算内（不让长模板把短请求顶回长 prompt）。
 * [D275] 旧实现直接 `JSON.stringify(...).slice(0, budget)`：超预算就切出**非法 JSON**，
 * 模型收到的 `事实：{"params":...` 缺右括号，PoC 章因此可能整段失效。现在改为
 * 结构化收缩：先丢可选字段，再截字符串/数组，保证返回的永远是合法 JSON。
 * @param {object} facts 事实包
 * @param {number} budget 该 JSON 允许占用的字符数
 * @param {string[]} [dropOrder] 超预算时优先丢弃的顶层字段
 * @returns {string} 单行合法 JSON
 */
function factsJson(facts, budget, dropOrder = []) {
  return fitJson(facts, budget, dropOrder);
}

/**
 * 递归收缩一个 JSON 值（只截字符串/数组，不改变类型），保证 stringify 合法。
 * @param {any} value 原值
 * @param {number} cap 字符串/数组保留上限
 * @param {number} [depth] 当前深度
 * @returns {any} 收缩后的值
 */
function shrinkValue(value, cap, depth = 0) {
  if (typeof value === 'string') {
    return value.length > cap ? `${value.slice(0, cap)}…(截断)` : value;
  }
  if (Array.isArray(value)) {
    const keep = cap > 160 ? 5 : cap > 60 ? 3 : 1;
    return value.slice(0, keep).map((v) => shrinkValue(v, cap, depth + 1));
  }
  if (value && typeof value === 'object') {
    if (depth >= 4) return '[嵌套过深已省略]';
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = shrinkValue(v, cap, depth + 1);
    return out;
  }
  return value;
}

/**
 * 在预算内产出合法 JSON：全量 → 丢可选字段 → 逐级收缩 → 最小事实包。
 * @param {object} value 事实对象
 * @param {number} budget 字符预算
 * @param {string[]} [dropOrder] 优先丢弃的字段
 * @returns {string} 合法 JSON 字符串
 */
export function fitJson(value, budget, dropOrder = []) {
  const full = JSON.stringify(value);
  if (full.length <= budget) return full;
  let obj = { ...value };
  for (const key of dropOrder) {
    if (!(key in obj)) continue;
    delete obj[key];
    const s = JSON.stringify(obj);
    if (s.length <= budget) return s;
  }
  for (const cap of [240, 160, 100, 60, 30, 12]) {
    const s = JSON.stringify(shrinkValue(obj, cap));
    if (s.length <= budget) return s;
  }
  // 最后兜底：只保留最小的可解析事实包，绝不返回半截 JSON
  const minimal = {
    truncated: true,
    params: typeof value?.params === 'string' ? value.params.slice(0, 40) : '',
    method: value?.method || '',
    dbms: value?.dbms || '',
  };
  const s = JSON.stringify(minimal);
  return s.length <= budget ? s : JSON.stringify({ truncated: true });
}

/**
 * [D259] analyst 的**首轮** prompt：短，但仍要求与 validateAnalysisJson 一致的 JSON 结构，
 * 并把引擎实测判据随事实带过去（否则短分析只能让 writer 编造 PoC 判据）。
 * @param {object} facts stepwiseFacts 产出的事实包
 * @returns {string} 短 prompt
 */
export function buildStepwiseAnalystPrompt(facts) {
  const payload = {
    params: facts.paramsRaw,
    method: facts.method,
    dbms: facts.dbms,
    boundary: facts.boundary || null,
    vulns: facts.vulns,
  };
  return clamp(
    '【分步·分析】分析下面的 SQL 注入扫描结果，只输出 JSON（不要 markdown），字段：'
    + '{"vulns":[{"name":"","type":"","risk":"","cvss":"","principle":"","location":"","dbms":"","exploitability":"","poc_payload":"","poc_verify":""}],"overall_risk":"","impact_summary":""}'
    + '\npoc_verify 必须引用事实里的响应判据；判据缺失写「引擎未提供，需人工确认」，禁止编造长度或关键字。'
    + '\ncvss 必须逐字引用事实里的 engineCvss；缺失写「引擎未评分」，禁止自行编造分数。'
    + '\n结论口径（verdict/未验证面/未覆盖面）以事实 boundary 为准，禁止把 inconclusive 写成未检出。'
    + `\n事实：${factsJson(payload, STEPWISE_MAX_CHARS - 480)}`,
  );
}

/**
 * [D259] writer 拆成每章一个短请求。PoC 章额外带引擎判据与原始 payload，
 * 其余章共享同一份压缩事实（分析 JSON、提取数据、参数名、方法、路径、Host 口径）。
 * @param {object} facts stepwiseFacts 产出的事实包
 * @returns {StepwiseStep[]} 按章节顺序的短请求
 */
function buildStepwiseWriterSteps(facts) {
  const common = {
    url: facts.url,
    urlPath: facts.urlPath,
    host: facts.host,
    method: facts.method,
    dbms: facts.dbms,
    params: facts.params,
    startedAt: facts.startedAt,
    analysis: facts.analysis,
    extracted: facts.extracted,
    boundary: facts.boundary || null,
  };
  return WRITER_SECTIONS.map((s) => {
    const extra = s.key === 'poc' ? { vulns: facts.vulns } : {};
    const dropOrder = s.key === 'poc'
      ? ['extracted', 'startedAt']
      : ['extracted', 'startedAt', 'url', 'host'];
    return {
      key: s.key,
      title: s.title,
      system: STEP_SYSTEM,
      user: clamp(
        `【分步·章节】写「${s.title}」一节，只输出该节 Markdown，不要输出其它章节。\n${s.task}\n`
        + '仅基于事实，不编造未发现的信息；参数名必须与事实逐字一致。\n'
        + '结论口径（verdict/未验证面/未覆盖面）以事实 boundary 为准，禁止把 inconclusive 写成未检出。\n'
        + `事实：${factsJson({ ...common, ...extra }, STEPWISE_MAX_CHARS - 340, dropOrder)}`,
      ),
    };
  });
}

/**
 * [D259] 单章短审阅：输入是**这一章**而不是整篇 draft（整篇塞回去就是长 prompt 了）。
 * [D275] 不再把章节 clamp 到 980 字符：内容超过 STEPWISE_REVIEW_MAX_CHARS 时返回 null
 * （调用方跳过审阅并标 partial），绝不「审阅节选后替换整章」。
 * @param {StepwiseSection} section 已生成的章节
 * @param {number} [maxChars] 单章内容预算
 * @returns {StepwiseStep|null} 短审阅请求；超预算时 null
 */
function buildStepwiseReviewerStep(section, maxChars = STEPWISE_REVIEW_MAX_CHARS) {
  const content = String(section.content || '');
  if (content.length > maxChars) return null;
  return {
    key: section.key,
    title: section.title,
    system: REVIEW_SYSTEM,
    user: `【分步·章节】审阅并修订「${section.title}」一节，只输出该节修订后的 Markdown 全文。\n`
      + '检查：夸大/编造、PoC 可复现、修复建议、合规（等保 2.0 / 数据安全法）。\n'
      + '不得删掉结论口径（verdict/未验证面/未覆盖面）的边界声明。\n'
      + `本节：${content}`,
  };
}

/**
 * [D259] 只对成功生成的章节发审阅请求；失败章节不送审（否则等于审阅占位文本）。
 * [D275] 超过审阅预算的章节也不送审（由调用方标 `reviewer:<key>:too-long`）。
 * @param {StepwiseSection[]} sections 章节列表
 * @param {number} [maxChars] 单章内容预算
 * @returns {StepwiseStep[]} 短审阅请求列表
 */
export function buildStepwiseReviewerSteps(sections, maxChars = STEPWISE_REVIEW_MAX_CHARS) {
  return sections
    .filter((s) => s.generated)
    .map((s) => buildStepwiseReviewerStep(s, maxChars))
    .filter(/** @type {(s: StepwiseStep|null) => s is StepwiseStep} */ ((s) => s !== null));
}

/**
 * [D259] 按固定章节顺序拼装；缺失章节用显式占位，不静默省略。
 * @param {StepwiseSection[]} sections 章节列表
 * @returns {string} 完整 Markdown 报告
 */
export function assembleStepwiseReport(sections) {
  return sections
    .map((s) => `### ${s.title}\n\n${s.generated ? s.content : MISSING_SECTION}`)
    .join('\n\n');
}

/**
 * [D259] 空值回退收成一处：事实包原本散落二十多个 `||`，每个都会被
 * --experimental-test-coverage 记成分支；收敛后调用点不再产生分支。
 * @param {any} v 原值
 * @param {any} fallback 回退值
 * @returns {any} 原值或回退值
 */
function orDefault(v, fallback) {
  return v || fallback;
}

/** @typedef {{url:string,urlPath:string,host:string,analysis:string,shortPayload:(p:any)=>string,formatBasis:(b:any)=>string,summarizeTrace:(v:any)=>any,valueForPrompt?:(v:any)=>string,boundary?:object}} StepwiseDerived */

/**
 * [D259] 提取数据事实：把 `?:` 与 `&&` 收在一处（分支可被链路单测直接覆盖）。
 * @param {object|null|undefined} data 引擎提取的数据
 * @returns {object|null} 结构化事实
 */
function extractedFacts(data) {
  if (!data) return null;
  return {
    databases: orDefault(data.databases, []),
    tables: Object.keys(orDefault(data.tables, {})).length,
    rows: Object.values(orDefault(data.rows, {})).filter((r) => Array.isArray(r) && r.length).length,
    currentDb: orDefault(data.currentDb, undefined),
    currentUser: orDefault(data.currentUser, undefined),
  };
}

/**
 * [D259] writer / analyst 共用的事实包：与 ReportAI.js 的 buildWriterPrompt 同源，
 * 依赖（脱敏结果、判据函数）由调用方注入，本模块保持纯函数、可直接单测。
 * @param {object} report 引擎报告
 * @param {StepwiseDerived} derived 由 ReportAI.js 计算的同源字段与函数
 * @returns {object} 事实包
 */
export function buildStepwiseFacts(report, derived) {
  const points = orDefault(report.points, []);
  const vulns = orDefault(report.vulns, []).slice(0, 5);
  const target = orDefault(report.target, {});
  const valueOf = typeof derived.valueForPrompt === 'function'
    ? derived.valueForPrompt
    : (v) => String(v ?? '');
  return {
    url: derived.url,
    urlPath: derived.urlPath,
    host: derived.host,
    method: orDefault(target.method, 'GET'),
    dbms: orDefault(report.dbms, '未知'),
    params: orDefault(points.map((p) => `${p.param}（${p.location}，原始值 ${valueOf(p.originalValue)}）`).join(', '), '未知'),
    paramsRaw: orDefault(points.map((p) => p.param).filter(Boolean).join(','), '未知'),
    startedAt: orDefault(report.startedAt, ''),
    analysis: derived.analysis,
    extracted: extractedFacts(report.data),
    boundary: orDefault(derived.boundary, null),
    vulns: vulns.map((v) => ({
      technique: v.technique,
      risk: orDefault(v.riskLevel, 'Low'),
      dbms: orDefault(v.dbms, '未知'),
      evidence: String(orDefault(v.evidence, '')).slice(0, 120),
      payload: derived.shortPayload(orDefault(orDefault(v.payloads, [])[0], '')),
      basis: derived.formatBasis(derived.summarizeTrace(v)),
      engineCvss: orDefault(v.cvss, null),
    })),
  };
}

/** @typedef {{facts:object,timeoutMs:number,stepwiseTimeoutMs:number,maxPromptChars:number,reviewMaxChars?:number,sectionCount:number,concurrency?:number,callLLM:(cfg:object,system:string,user:string,timeoutMs:number)=>Promise<string>,getRoleConfig:(idx:number)=>object,legacyFallback:()=>Promise<object>}} StepwiseDeps */

/**
 * [D259] 发一个短请求；失败只返回 ok:false，由调度层标注缺章（不伪造内容）。
 * 依赖由调用方注入，本模块无副作用、可在链路单测里直接替换。
 * @param {StepwiseDeps} deps 注入依赖
 * @param {object} cfg 角色配置
 * @param {StepwiseStep} step 短请求
 * @param {number} timeoutMs 每阶段超时
 * @returns {Promise<{ok:boolean,content:string,error?:any}>} 该步结果
 */
async function runStepwiseCall(deps, cfg, step, timeoutMs) {
  try {
    const content = await deps.callLLM(cfg, step.system, step.user, Math.min(timeoutMs, deps.stepwiseTimeoutMs));
    return { ok: true, content };
  } catch (e) {
    if (e?.budgetExhausted) throw e; // [D263] 总预算耗尽立即终止，不再逐章空转
    return { ok: false, content: '', error: e };
  }
}

/**
 * [D275] 角色级调用器：持有当前 cfg；只有 429/5xx 才换 key/端点重试一次，
 * 并把新 cfg 留给后续章节（旧实现循环外取一次 cfg，第一章 429 冷却 key 后，
 * 后续每章都拿同一个已冷却 cfg 继续撞墙）。
 *
 * 空内容/超时不换 key：沿用当前 cfg（与旧行为一致，避免「每章空响应烧掉一把 key」）。
 * @param {StepwiseDeps} deps 注入依赖
 * @param {number} roleIdx 角色索引（1=writer，2=reviewer）
 * @returns {(step:StepwiseStep,timeoutMs:number)=>Promise<{ok:boolean,content:string,error?:any}>} 调用器
 */
function makeRoleCaller(deps, roleIdx) {
  let cfg = null;
  const pick = () => {
    if (!cfg) cfg = deps.getRoleConfig(roleIdx);
    return cfg;
  };
  return async (step, timeoutMs) => {
    let active;
    try {
      active = pick();
    } catch (e) {
      // 全部 key 已冷却：本步失败即可，由上层标缺章/未审阅；不能让异常逃逸成整场崩溃
      return { ok: false, content: '', error: e };
    }
    const first = await runStepwiseCall(deps, active, step, timeoutMs);
    if (first.ok || !first.error?.retryableWithAnotherKey) return first;
    try {
      active = deps.getRoleConfig(roleIdx);
    } catch {
      return first; // 全部 key 冷却中：保留首轮失败原因，由上层标缺章/未审阅
    }
    cfg = active;
    return runStepwiseCall(deps, active, step, timeoutMs);
  };
}

/**
 * [D259] 逐章短审阅：只送已成功生成的章节，输入是单章而非整篇 draft。
 * [D277] 支持有界并发（deps.concurrency，默认 1）；失败披露与输出顺序仍按章节顺序，
 * 不随完成先后漂移。
 * @param {StepwiseDeps} deps 注入依赖
 * @param {StepwiseSection[]} sections 章节
 * @param {number} timeoutMs 每阶段超时
 * @param {string[]} failedSteps 失败步骤（原地追加）
 * @returns {Promise<{sections:StepwiseSection[],okCount:number}>} 审阅后的章节与成功数
 */
async function reviewStepwiseSections(deps, sections, timeoutMs, failedSteps) {
  const review = makeRoleCaller(deps, 2);
  /**
   * 单章审阅任务：用显式返回类型让 TS 按 kind 收窄（否则 got 被推成可选）。
   * @param {StepwiseSection} s 章节
   * @returns {Promise<{s:StepwiseSection,kind:'skip'|'too-long'}|{s:StepwiseSection,kind:'reviewed',got:{ok:boolean,content:string,error?:any}}>} 结果
   */
  const reviewOne = async (s) => {
    if (!s.generated) return { s, kind: 'skip' };
    const step = buildStepwiseReviewerStep(s, deps.reviewMaxChars ?? STEPWISE_REVIEW_MAX_CHARS);
    if (!step) return { s, kind: 'too-long' };
    const got = await review(step, timeoutMs);
    return { s, kind: 'reviewed', got };
  };
  const results = await mapPool(sections, deps.concurrency ?? 1, reviewOne);
  const out = [];
  let okCount = 0;
  for (const r of results) {
    if (r.kind !== 'reviewed') {
      if (r.kind === 'too-long') {
        // [D275] 超审阅预算：不送审、保留原章、如实标 partial —— 不用节选审阅替换全文
        failedSteps.push(`reviewer:${r.s.key}:too-long`);
      }
      out.push(r.s);
      continue;
    }
    if (!r.got.ok) { failedSteps.push(`reviewer:${r.s.key}`); out.push(r.s); continue; }
    okCount++;
    out.push({ key: r.s.key, title: r.s.title, content: r.got.content, generated: true });
  }
  return { sections: out, okCount };
}

/**
 * [D259] 分步模式的步骤 2/3：逐章撰写 → 逐章审阅 → 按固定顺序拼装。
 * 全部章节都失败时调用 deps.legacyFallback() 回退原整篇流水线，并如实登记。
 * 为什么放在本模块而不是 ReportAI.js：全量 coverage 是多进程合并，只在少数测试
 * 进程执行的新分支会进分母不进分子；本模块被链路单测直接 import，覆盖可归因。
 * @param {StepwiseDeps} deps 注入依赖
 * @returns {Promise<any>} {draft,finalReport,reviewNote,stepwise}
 */
export async function runStepwiseStages(deps) {
  const failedSteps = [];
  /** @type {StepwiseSection[]} */
  const sections = [];
  // [D275] 角色级调用器：429/5xx 后换 key/端点，并把新 cfg 留给后续章节
  // [D277] concurrency>1 时多章共享该调用器：429 换 key 是「尽力而为」，
  // 并发下可能多冷却一个 key，但不会把失败记成成功（失败仍逐章披露）。
  const write = makeRoleCaller(deps, 1);
  const steps = buildStepwiseWriterSteps(deps.facts);
  const wrote = await mapPool(steps, deps.concurrency ?? 1, (step) => write(step, deps.timeoutMs));
  for (let i = 0; i < steps.length; i++) {
    const got = wrote[i];
    sections.push({ key: steps[i].key, title: steps[i].title, content: got.content, generated: got.ok });
    if (!got.ok) failedSteps.push(`writer:${steps[i].key}`);
  }
  const info = {
    enabled: true,
    mode: 'sections',
    fallback: /** @type {string|null} */ (null),
    writerSteps: deps.sectionCount,
    reviewedSections: 0,
    maxPromptChars: deps.maxPromptChars,
    reviewMaxChars: deps.reviewMaxChars ?? STEPWISE_REVIEW_MAX_CHARS,
    concurrency: deps.concurrency ?? 1,
    failedSteps,
    partial: true,
  };
  if (sections.every((s) => !s.generated)) {
    const legacy = await deps.legacyFallback();
    return { ...legacy, stepwise: { ...info, fallback: 'legacy' } };
  }
  let review = { sections, okCount: 0 };
  try {
    review = await reviewStepwiseSections(deps, sections, deps.timeoutMs, failedSteps);
  } catch (e) {
    if (e?.budgetExhausted) throw e; // [D263] 总预算耗尽不再吞成「reviewer 不可用」
    failedSteps.push('reviewer:unavailable');
  }
  const total = sections.filter((s) => s.generated).length;
  const complete = failedSteps.length === 0 && review.okCount === total;
  info.reviewedSections = review.okCount;
  info.partial = !complete;
  return {
    draft: assembleStepwiseReport(sections),
    finalReport: assembleStepwiseReport(review.sections),
    reviewNote: complete
      ? `✅ 已经过安全审阅角色校验（分章节短请求 ${review.okCount}/${total}）`
      : `⚠️ 安全审阅角色部分完成（${review.okCount}/${total} 章节），其余未审阅`,
    stepwise: info,
  };
}

export default {
  stepwiseEnabled,
  buildStepwiseAnalystPrompt,
  buildStepwiseFacts,
  buildStepwiseReviewerSteps,
  assembleStepwiseReport,
  runStepwiseStages,
  normalizeStepwiseConcurrency,
  STEPWISE_MAX_CONCURRENCY,
};
