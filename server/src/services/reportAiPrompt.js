// =====================================================================
// reportAiPrompt.js —— LLM 报告 prompt 构建 / 脱敏 / trace 判据族
//
// [D327] 自 ReportAI.js 纯搬移（第 138-476 行）：无网关/重试/缓存状态依赖，
// 只经 reportAiFacts.js 的 buildBoundaryFacts / boundaryPromptBlock 取事实。
// 原 ReportAI.js 改为导入 + re-export summarizeTrace（保持对外 API 兼容）。
// 动机：ReportAI.js 1178 行距 arch 1200 硬上限 22 行，且 prompt 构建自成一族。
//
// ⚠️ MASK_ENABLED 保持**模块加载时求值**（与原文件一致）：测试通过
// delete process.env.AI_REPORT_MASK + 动态 import 控制脱敏，求值时机不得改。
// 判据注释按原文保留（D205/D275 的脱敏外发教训不因搬移丢失）。
// =====================================================================
import { buildBoundaryFacts, boundaryPromptBlock } from './reportAiFacts.js';

// ── 构建 LLM Prompt（按角色分 prompt）──────────────────────────────────────
// [P0-FIX] evidence prompt 注入防护：目标站响应可能含恶意 payload 字符串，
// 直接拼入 prompt 存在 LLM prompt 注入风险。对 evidence 做 JSON 字符串包裹 +
// 截断 + system prompt 增加抗注入指令。
function safeEvidence(ev) {
  // 截断超长证据（防 prompt 膨胀 + 成本），包裹为 JSON 字符串（引号转义）
  const truncated = String(ev || '').slice(0, 500);
  return JSON.stringify(truncated);
}

/**
 * [D205] 把 summarizeTrace 的结果渲染成 prompt 里的一行人读判据。
 * @param {null|object} b summarizeTrace 的返回值
 * @returns {string} 人读判据；无 trace 时返回明确说明（不让 LLM 自由发挥）
 */
function formatBasis(b) {
  if (!b) return '（引擎未提供响应判据，禁止编造判据）';
  const parts = [];
  if (b.trueLens.length) parts.push(`真条件响应长度 ${b.trueLens.join('/')}B`);
  if (b.falseLens.length) parts.push(`假条件 ${b.falseLens.join('/')}B`);
  if (b.lenDelta !== null) parts.push(`长度差 ${b.lenDelta}B`);
  if (b.firstDiffOffset !== null && b.firstDiffOffset >= 0) parts.push(`首个差异偏移 ${b.firstDiffOffset}`);
  if (b.changedSnippet) parts.push(`差异片段 ${JSON.stringify(b.changedSnippet)}`);
  if (b.z !== null) parts.push(`z=${b.z}`);
  return parts.length ? parts.join('；') : '（引擎未提供响应判据，禁止编造判据）';
}

function buildAnalystPrompt(report) {
  const boundary = buildBoundaryFacts(report);
  const vulns = (report.vulns || []).map((v) => ({
    technique: v.technique,
    dbms: v.dbms || '未知',
    riskLevel: v.riskLevel || 'Low',
    description: v.description || '',
    evidence: safeEvidence(v.evidence),
    // [D205] 真实判据（真/假样本长度、长度差、首个差异偏移、差异片段）——无 trace 时为 null
    basis: summarizeTrace(v),
    // [D275] 引擎确定性 CVSS（vulnEnrich 已回填）；模型必须引用，不得自行编造
    engineCvss: v.cvss || null,
    // 截断 payload（防 analyst JSON 输出过大导致 writer prompt 超 token）
    payloads: (v.payloads || []).map(p => shortPayload(p)),
  }));
  // PoC 需要实际参数名 + HTTP 方法 + URL 路径（host 与参数值在脱敏态替换为占位符）
  const points = (report.points || []).map(p => ({
    param: p.param,
    location: p.location,
    originalValue: valueForPrompt(p.originalValue),
    method: report.target?.method || 'GET',
  }));
  const safeUrl = maskUrl(report);
  // URL 路径（不含 host，供 PoC 构造用）—— 参数值脱敏为 ***，路径按 AI_REPORT_MASK 决定是否脱敏
  const urlPath = urlPathForPrompt(report, { maskQueryValues: true });
  return `你是漏洞分析师。分析以下 SQL 注入扫描结果，输出 JSON 格式的结构化漏洞分析。

## 扫描结果
目标: ${safeUrl}
URL 路径（PoC 用）: ${urlPath}
HTTP 方法: ${report.target?.method || 'GET'}
数据库: ${report.dbms || '未知'}
漏洞数: ${vulns.length}

## 注入点信息
${points.map((p, i) => `${i + 1}. 参数: ${p.param}（${p.location}）原始值: ${p.originalValue} 方法: ${p.method}`).join('\n')}

${boundaryPromptBlock(boundary)}

## 漏洞列表（含实际 payload，已截断过长 payload）
${vulns.map((v, i) => `${i + 1}. [${v.riskLevel}] ${v.technique} DB:${v.dbms}
   证据: ${v.evidence || '无'}
   响应判据（引擎实测）: ${formatBasis(v.basis)}
   引擎 CVSS（必须引用）: ${v.engineCvss ? JSON.stringify(v.engineCvss) : '（引擎未评分，写「引擎未评分」，禁止自行编造分数）'}
   实际 Payload:
${(v.payloads || []).map((p, j) => `   ${j + 1}. ${p}`).join('\n')}`).join('\n')}

## 输出要求（纯 JSON，不要 markdown）
{
  "vulns": [
    {
      "name": "漏洞名称",
      "type": "SQL注入子类型",
      "risk": "高危/中危/低危",
      "cvss": "必须逐字引用上面「引擎 CVSS」的 score + vector + note；引擎未评分时写「引擎未评分」，禁止自行编造分数",
      "principle": "漏洞原理 2-3 句",
      "location": "注入参数名+HTTP方法+URL路径",
      "dbms": "数据库类型",
      "exploitability": "利用难度评估",
      "poc_payload": "从实际 payload 中选取一条最简洁可复现的（若原始 payload 过长被截断，输出自己构造的等价最短可复现 payload）",
      "poc_verify": "怎么判断这条 PoC 生效：必须引用上面「响应判据（引擎实测）」里的具体数字/片段（响应长度、长度差、差异偏移、差异片段文字）；判据缺失就写「引擎未提供，需人工确认」，禁止编造页面长度或关键字"
    }
  ],
  "overall_risk": "总体风险评级",
  "impact_summary": "影响概述"
}`;
}

// 截断超长 payload（保留可读性同时防 prompt 膨胀）
function shortPayload(p) {
  const s = String(p || '');
  if (s.length <= 160) return s;
  return s.slice(0, 160) + '…(已截断)';
}

// 分析 JSON 输出太长时压缩（防 writer prompt 超 token）：只保留每漏洞关键字段 + 简短 poc_payload
function compressAnalysisForWriter(analysis) {
  try {
    const parsed = JSON.parse(analysis);
    const compressed = {
      vulns: (parsed.vulns || []).map((v) => ({
        name: v.name || '',
        type: v.type || '',
        risk: v.risk || '',
        cvss: v.cvss || '',
        location: v.location || '',
        dbms: v.dbms || '',
        poc_payload: shortPayload(v.poc_payload),
        // [D205] 验证判据必须随分析一起传给 writer，否则 PoC 章节只能靠猜
        poc_verify: String(v.poc_verify || '').slice(0, 300),
      })),
      overall_risk: parsed.overall_risk || '',
      impact_summary: String(parsed.impact_summary || '').slice(0, 300),
    };
    return JSON.stringify(compressed);
  } catch {
    return analysis; // 解析失败时原样传递（不阻塞）
  }
}

/**
 * [D205] PoC 里 Host 行该写什么：脱敏态给占位符并**显式标注**（否则 LLM 会把占位符当真值写进报告），
 * 非脱敏态给真实 host。
 * @param {object} report 引擎报告
 * @returns {string} Host 行内容
 */
function hostForPrompt(report) {
  if (MASK_ENABLED) return '<目标Host>（脱敏占位符，真实 host 需人工回填；设 AI_REPORT_MASK=0 可原样输出）';
  try { return new URL(report.target?.baseUrl || '').host; } catch { return '<目标Host>'; }
}

function buildWriterPrompt(report, analysis) {
  const boundary = buildBoundaryFacts(report);
  const safeUrl = maskUrl(report);
  const data = report.data;
  const extracted = data ? {
    databases: data.databases || [],
    tables: Object.keys(data.tables || {}).length,
    rows: Object.values(data.rows || {}).filter((r) => Array.isArray(r) && r.length).length,
    currentDb: data.currentDb || undefined,
    currentUser: data.currentUser || undefined,
  } : null;
  // 注入点参数名（供 PoC 构造用）；参数值在脱敏态替换为占位符
  const points = (report.points || []).map(p => `${p.param}（${p.location}，原始值 ${valueForPrompt(p.originalValue)}）`).join(', ');
  // URL 路径（含参数占位，供 PoC 构造用）—— query 值在脱敏态始终遮掉；路径按 AI_REPORT_MASK 决定
  const urlPath = urlPathForPrompt(report, { maskQueryValues: false });
  const pocHost = hostForPrompt(report);
  const httpMethod = report.target?.method || 'GET';
  return `你是渗透测试报告撰写专家。根据漏洞分析结果，生成符合漏洞盒子提交标准的完整报告。

## 目标信息
URL: ${safeUrl}
URL 路径: ${urlPath}
HTTP 方法: ${httpMethod}
数据库类型: ${report.dbms || '未知'}（引擎指纹结果；写「未知」前先看这里有没有值）
注入参数: ${points || '未知'}
扫描时间: ${report.startedAt || ''}

${boundaryPromptBlock(boundary)}

## 漏洞分析（来自分析师角色）
${compressAnalysisForWriter(analysis)}

## 提取数据
${extracted ? JSON.stringify(extracted, null, 2) : '未提取数据'}

## 报告要求（漏洞盒子 SRC 平台提交标准）
按以下结构输出（Markdown 格式）：

### 一、漏洞概述
- 漏洞名称、危险等级、漏洞类型、影响版本

### 二、漏洞描述
- 漏洞原理、注入位置（参数名+HTTP方法+URL路径）、数据库类型

### 三、漏洞证明（PoC）
**重要：每个漏洞的 PoC 必须使用分析师 JSON 中的 poc_payload 字段构造完整 HTTP 请求。**
- PoC 格式（请求行 URL 参数值替换为 poc_payload）：
  \`\`\`http
  ${httpMethod} ${urlPath.replace(/=[^&]*/g, '=<POC>')} HTTP/1.1
  Host: ${pocHost}
  User-Agent: Mozilla/5.0
  \`\`\`
- 将 <POC> 替换为分析师 JSON 中的 poc_payload 内容（URL 编码后）
- **参数名必须与「注入参数」逐字一致**（引擎给的是 uid 就写 uid，禁止改写成 username/user 之类的同义词——10-30 实测模型会自作主张改名，报告因此无法复现）
- 每个漏洞给出对应的 PoC HTTP 请求（含 Content-Type 与完整 body，不能只给 payload）
- **响应判据必须引用分析师 JSON 中每条漏洞的 poc_verify**（响应长度差/差异片段/状态码）；poc_verify 为空时写「判据需人工确认」，禁止自己编「页面长度 >N 字节」这类未实测的门槛
- 附带提取的数据证据（如库名、表名、版本号等）
- 只有在分析师明确标注「证据不足」时才标注「需手动验证」

### 四、影响评估
- 数据泄露风险、系统接管风险、横向渗透风险

### 五、修复方案
- 即时修复（参数化查询代码示例）
- 纵深防御（WAF/最小权限/审计日志）
- 验证方法

注意：仅基于扫描结果分析，不编造未发现的信息。使用专业中文。PoC 中的 payload 必须来自分析师 JSON 中的 poc_payload 字段。`;
}

function buildReviewerPrompt(report, draftReport) {
  const boundary = buildBoundaryFacts(report);
  return `你是安全审计专家。审阅以下 AI 生成的漏洞报告，检查安全性和完整性，补充遗漏项。

## 待审阅报告
${draftReport}

${boundaryPromptBlock(boundary)}

## 审阅要求
1. 检查是否有夸大/编造的风险
2. 检查 PoC 是否可复现
3. 补充遗漏的修复建议（如 WAF 规则配置、数据库权限收敛）
4. 补充合规建议（如等保 2.0 / 数据安全法相关条款）
5. 输出审阅意见 + 最终修订版报告（Markdown）

注意：保持原报告结构，仅补充和修正；不得删掉「结论口径」里的边界声明。`;
}

// [D205] 脱敏开关：默认脱敏（内网路径/主机名不外发第三方）。
// 指向**本机/自建**网关（如 dsh 127.0.0.1:8326）时设 AI_REPORT_MASK=0，
// host 与 path 原样进 prompt，LLM 才能写出可直接复现的 PoC
// （默认态下 host 是 <目标Host> 占位、路径是 /***，PoC 天然不可复现——D205 实测过）。
const MASK_ENABLED = process.env.AI_REPORT_MASK !== '0';

/**
 * [D275] 脱敏态下 prompt 里的目标地址：**连 host 一起遮掉**。
 * 旧实现返回 `${protocol}//${u.host}/***`，只遮路径不遮 host —— 与文档承诺的
 * 「host 写成 `<目标Host>`」不符，内网主机名/端口仍会外发。这里改成固定占位符。
 * @param {object} report 引擎报告
 * @returns {string} 目标地址（脱敏态为占位符）
 */
function maskUrl(report) {
  if (MASK_ENABLED) return '<目标Host>/***';
  try {
    const u = new URL(report.target?.baseUrl || '');
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch { return '***'; }
}

/**
 * [D275] 脱敏态下参数值的占位符。旧实现把 `originalValue` 原样写进 analyst/writer
 * prompt，query 里的 token/session 等敏感值会随报告外发；参数**名**保留（PoC 需要），
 * 参数**值**在脱敏态一律替换。
 * @param {unknown} value 原始参数值
 * @returns {string} 可进 prompt 的值
 */
function valueForPrompt(value) {
  if (MASK_ENABLED) return '***';
  return String(value ?? '');
}

/**
 * [D205/D275] 供 prompt 使用的 URL 路径：脱敏态给 `/***`，不脱敏态给真实 pathname。
 * query 值在脱敏态**始终**替换为 `***`（参数名保留，PoC 仍能按名构造）；旧实现让
 * writer 用 `maskQueryValues:false` 保留原值，导致 `?token=abc` 原样外发。
 * @param {object} report 引擎报告
 * @param {{maskQueryValues?: boolean}} [opts] maskQueryValues=true 时即使未脱敏也遮 query 值
 * @returns {string} 路径（含 query）
 */
function urlPathForPrompt(report, opts = {}) {
  try {
    const u = new URL(report.target?.baseUrl || '');
    const maskValues = MASK_ENABLED || opts.maskQueryValues === true;
    const search = maskValues ? u.search.replace(/=[^&]*/g, '=***') : u.search;
    if (!MASK_ENABLED) return `${u.pathname}${search}`;
    const hasPath = u.pathname.split('/').filter(Boolean).length > 0;
    return `${hasPath ? '/***' : '/'}${search}`;
  } catch { return '/'; }
}

/**
 * [D205] 把引擎的布尔判定 trace 压成「给 LLM 看的最小判据集」。
 * 报告里 `evidence` 只有统计比值（真≈基线0.67、z=2.83），LLM 据此只能编造判据
 * （实测把「302 Location 差异」写成「页面长度 >500 字节」）。trace 里有**真实**的
 * 真/假样本长度、长度差、首个差异偏移与差异片段，这才是可复现的判据。
 * @param {object} vuln 单条命中项
 * @returns {null|{trueLens:number[],falseLens:number[],lenDelta:number|null,firstDiffOffset:number|null,changedSnippet:string,trueRatio:number|null,falseRatio:number|null,z:number|null,minStable:number|null}} 无 trace 时返回 null
 */
/**
 * 只保留有限数（NaN/undefined 进 prompt 会变成「NaN」这种噪声，比缺字段更糟）。
 * @param {unknown} v 任意值
 * @returns {number|null} 有限数或 null
 */
function numOrNull(v) {
  return Number.isFinite(v) ? /** @type {number} */ (v) : null;
}

/**
 * @param {Array<{len?: number}>|undefined} samples 采样列表
 * @returns {number[]} 有限长度数组
 */
function sampleLens(samples) {
  // Number.isFinite 不做类型窄化，显式断言成 number[]（null 已在 numOrNull 处处理，这里只丢脏值）
  return /** @type {number[]} */ ((samples || []).map((s) => s.len).filter((n) => Number.isFinite(n)));
}

/**
 * 取「有明显差异」的那一对（idx 0 可能两边完全一样，取第一条有差异的）。
 * @param {Array<{lenDelta?: number, firstDiffOffset?: number}>|undefined} diffs 差异列表
 * @returns {object|null} 差异项或 null
 */
function pickDiffer(diffs) {
  return (diffs || []).find((d) => d && (d.lenDelta !== 0 || (d.firstDiffOffset ?? -1) >= 0)) || null;
}

/**
 * [D205] 把引擎的布尔判定 trace 压成「给 LLM 看的最小判据集」。
 * 报告里 `evidence` 只有统计比值（真≈基线0.67、z=2.83），LLM 据此只能编造判据
 * （实测把「302 Location 差异」写成「页面长度 >500 字节」）。trace 里有**真实**的
 * 真/假样本长度、长度差、首个差异偏移与差异片段，这才是可复现的判据。
 * @param {object} vuln 单条命中项
 * @returns {null|{trueLens:number[],falseLens:number[],lenDelta:number|null,firstDiffOffset:number|null,changedSnippet:string,trueRatio:number|null,falseRatio:number|null,z:number|null,minStable:number|null}} 无 trace 时返回 null
 */
export function summarizeTrace(vuln) {
  const trace = vuln?.trace;
  const pair = trace?.pairs?.[0];
  if (!pair) return null;
  const differ = pickDiffer(pair.diffs);
  return {
    trueLens: sampleLens(pair.trueSamples),
    falseLens: sampleLens(pair.falseSamples),
    lenDelta: numOrNull(differ?.lenDelta),
    firstDiffOffset: numOrNull(differ?.firstDiffOffset),
    changedSnippet: differ?.changedSnippet ? String(differ.changedSnippet).slice(0, 200) : '',
    trueRatio: numOrNull(pair.trueRatio),
    falseRatio: numOrNull(pair.falseRatio),
    z: numOrNull(pair.z),
    minStable: numOrNull(trace.minStable),
  };
}
export {
  safeEvidence, formatBasis, buildAnalystPrompt, shortPayload, compressAnalysisForWriter,
  hostForPrompt, buildWriterPrompt, buildReviewerPrompt, maskUrl, valueForPrompt,
  urlPathForPrompt,
};
