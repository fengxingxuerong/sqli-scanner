// ==================== 声明式 Payload 注册表（对标 sqlmap XML <test> 元素） ====================
// sqlmap 用 XML 描述每条 payload 的 level/risk/dbms/clause 依赖；本项目用 JSON 声明等价数据。
//
// [E5-2 2026-09-23] **数据与逻辑分家**：681 条条目已外置到 `payloads/registry.json`（每条一行，
// 便于 diff 与机械校验），本文件只保留逻辑 —— 高危池门禁 / selectPayloads 筛选 / 版本过滤 /
// boundary 排序。切换前后逐条等价（业务字段），证明手段：
//   · `scripts/migrate-payload-registry.mjs` 负责导出与自检（含「行内注释 → note」迁移）；
//   · `tests/payloadRegistry.fingerprint.test.js` 用内容指纹长期钉住数据（改一个字符就红）。
// 瘦身效果：167.2 KB / 982 行 → 15.9 KB / 268 行；数据债并未消失，只是从「代码」搬到「数据」，
// 因此已把 `.json` 一并纳入 `scripts/arch-guard.mjs` 的字节判据（否则等于把债藏进盲区）。
//
// 与旧版 PAYLOADS（payloads.js）的关系：
//   - PAYLOADS 为扁平「dbms → technique → 模板数组」结构，继续原样工作（向后兼容，零回归）；
//   - PAYLOAD_REGISTRY 为声明式扁平列表，模板从 PAYLOADS 核心向量提取，加上 level/risk/clause/boundary
//     元数据，供 selectPayloads() 按 sqlmap 语义筛选。
//
// 每条声明对应 sqlmap 的一个 <test>：id / dbms / technique / level / risk / clause / boundary /
// template（真模板）+ falseTemplate（假模板，布尔对）/ where（注入位置）。
//
// 分级约定（对标 sqlmap）：
//   level 1-5：复杂度/边界探测深度（1 默认，5 全量）
//   risk  1-3：破坏性（1 仅安全向量；2 含 OR 变体/时间；3 含注释符变体/极限向量）
//   where: 'value'=值位置注入（谓词值），'position'=位置注入（ORDER BY / LIMIT 列位置）
//
// 版本分支（[P2-2] 对标 sqlmap 版本感知）：
//   条目可声明 minVersion/maxVersion（数字或 {major,minor}）标注适用版本区间，
//   selectPayloads 按 ctx.dbmsVersion（指纹阶段解析）过滤；版本未知 → 不过滤（保守投放）。

import { AsyncLocalStorage } from 'node:async_hooks';
import { versionAtLeast, versionBelow } from './dbmsVersion.js';
import { DESTRUCTIVE_PAYLOADS } from './payloads/destructive.js';
// [E5-2 2026-09-23] 数据外置：681 条声明式条目改从 registry.json 加载（原先内联在本文件 98-817 行）。
// 条目上方的行内注释已按 id 迁移到各条的 note 字段（生成器：scripts/migrate-payload-registry.mjs）。
import registryData from './payloads/registry.json' with { type: 'json' };

// ============================================================================
// [P0-FIX 2026-09-09] 高危（destructive）池投放策略 —— productionMode 硬门
// ----------------------------------------------------------------------------
// 为什么要这一层：注册表里 id 带 `-dest-` 的条目（以及模板与 payloads/destructive.js 同源的条目）
// 就是 INTO OUTFILE 写文件 / LOAD_FILE·pg_read_file 任意文件读 / xp_cmdshell·COPY TO PROGRAM·
// load_extension 命令执行 / sp_configure 永久改服务器配置 / GET_LOCK·BENCHMARK·RANDOMBLOB DoS /
// OPENROWSET·UTL_HTTP 外连。此前**只看 risk**：用户把 risk 拖到 3（前端一个滑条），下一轮扫描就把
// 这些模板打进客户生产库 ——「开关有名无实」的反面：开关有实无门。而扇平路径又完全不投放（同一个
// risk=3 两种后果），两者都不可接受。现统一为：生产环境下投放高危池必须 confirmDestructive===true。
//
// 策略传递通道：Detection 侧调用方（ErrorDetector / TimeBlindDetector）只传 dbms/technique/level/risk/
// testFilter/testSkip 六个字段给 selectPayloads，而这两个检测器属于禁改文件 → 无法从签名上接新参数。
// 故用 AsyncLocalStorage 做「一次扫描一个策略」的上下文注入（ScanManager._run 建立），
// 而不是进程级可变全局：并发扫描各拿各的 policy，不会 A 扫描的 confirm 泄漏给 B 扫描。
//
// 兼容性红线：**无显式参数且无扫描上下文时不施加门禁**（保持旧筛选语义）——否则直调
// selectPayloads 的现有单测（tests/unit/registryFilter.test.js：risk=3 应返回全量）会被误伤。
// 真实扫描路径总是经过 ScanManager._run，因此总是带策略 → 默认 fail-closed。
// ============================================================================

// destructive.js 里的模板集（注册表的 -dest- 条目即由它同源生成，用内容而不是只靠 id 字串判定）
const DESTRUCTIVE_TEMPLATES = new Set(
  Object.values(DESTRUCTIVE_PAYLOADS).flatMap((byTech) => Object.values(byTech).flat())
);
const DESTRUCTIVE_ID_RE = /(?:^|-)dest-/;

// 判定一条注册表条目是否属于高危池（id 带 -dest- 或模板与 destructive 池同串）。
// falseTemplate 一并查：高危池目前无假对，但防后续补条目时绕过判定。
export function isDestructivePayload(entry) {
  if (!entry || typeof entry !== 'object') return false;
  if (DESTRUCTIVE_ID_RE.test(String(entry.id || ''))) return true;
  for (const tpl of [entry.template, entry.falseTemplate]) {
    if (typeof tpl === 'string' && DESTRUCTIVE_TEMPLATES.has(tpl)) return true;
  }
  return false;
}

const destructivePolicyStore = new AsyncLocalStorage();

/**
 * 在指定高危池策略下执行 fn（ScanManager._run 包裹整个扫描流水线的入口）。
 * @param {{productionMode?:boolean, confirmDestructive?:boolean}} policy
 * @param {() => any} fn
 */
export function runWithDestructivePolicy(policy, fn) {
  return destructivePolicyStore.run({ ...(policy || {}) }, fn);
}

/** 读取当前上下文的高危池策略（非扫描上下文返回 null） */
export function currentDestructivePolicy() {
  return destructivePolicyStore.getStore() || null;
}

/**
 * 解析本次筛选的高危池放行结论。返回 null = 不施加门禁（无策略上下文且调用方未显式传参）。
 * @param {{productionMode?:boolean, confirmDestructive?:boolean}} args selectPayloads 入参
 */
function resolveDestructiveGate(args = {}) {
  const explicit = args.productionMode !== undefined || args.confirmDestructive !== undefined;
  const policy = destructivePolicyStore.getStore();
  if (!explicit && !policy) return null;
  const productionMode =
    args.productionMode !== undefined ? args.productionMode !== false : policy?.productionMode !== false;
  const confirmDestructive =
    args.confirmDestructive !== undefined
      ? args.confirmDestructive === true
      : policy?.confirmDestructive === true;
  // 生产模式：必须显式确认；脱离生产护栏（productionMode=false）：保持旧语义（risk>=3 即投放）
  return { allowed: !productionMode || confirmDestructive, productionMode, confirmDestructive };
}

/** @type {Array<{id:string, dbms:string[], technique:string, level:number, risk:number,
 *  clause:string[], boundary:string[], template:string, falseTemplate?:string, where:string,
 *  minVersion?:number|{major:number,minor?:number}, maxVersion?:number|{major:number,minor?:number},
 *  note?:string}>} */
export const PAYLOAD_REGISTRY = registryData;

// id 唯一性自检（声明期校验，防止手写重复 id 静默吞掉条目）
{
  const seen = new Set();
  for (const p of PAYLOAD_REGISTRY) {
    if (seen.has(p.id)) {
      throw new Error(`[payloadRegistry] 重复 payload id: ${p.id}`);
    }
    seen.add(p.id);
  }
}

/**
 * 按 level/risk/dbms/clause/boundary/testFilter/testSkip 筛选 payload（对标 sqlmap 的
 * level/risk/dbms/clause 过滤语义 + --test-filter / --test-skip id 过滤）。
 *
 * testFilter / testSkip 语义（对标 sqlmap --test-filter / --test-skip）：
 *   - 逗号分隔的 id 子串列表，大小写不敏感；
 *   - testFilter：entry.id 包含任一子串才保留（白名单）；
 *   - testSkip：entry.id 包含任一子串则排除（黑名单）；
 *   - 二者可组合：先 filter 白名单，再 skip 黑名单。
 *
 * @param {{dbms?: string, technique?: string, level?: number, risk?: number,
 *          clause?: string[], boundary?: string,
 *          testFilter?: string, testSkip?: string,
 *          dbmsVersion?: { major?: number|null, minor?: number|null, patch?: number|null, raw?: string },
 *          productionMode?: boolean, confirmDestructive?: boolean}} opts
 * @returns {typeof PAYLOAD_REGISTRY} 筛选后的条目（原对象引用，不拷贝）
 */
export function selectPayloads({ dbms, technique, level, risk, clause, boundary, testFilter, testSkip, dbmsVersion, productionMode, confirmDestructive } = {}) {
  // [P0-FIX 2026-09-09] 高危池硬门（显式参数 > 扫描上下文策略 > 不施加）
  const gate = resolveDestructiveGate({ productionMode, confirmDestructive });
  // 解析 testFilter：逗号分隔 → 小写子串数组（空值过滤）
  const filterIds = testFilter
    ? String(testFilter).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
    : [];
  // 解析 testSkip：逗号分隔 → 小写子串数组（空值过滤）
  const skipIds = testSkip
    ? String(testSkip).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
    : [];

  return PAYLOAD_REGISTRY.filter((p) => {
    if (dbms && !p.dbms.includes(dbms)) return false;
    if (technique && p.technique !== technique) return false;
    if (level && p.level > level) return false;
    if (risk && p.risk > risk) return false;
    if (clause && clause.length && !p.clause.some((c) => clause.includes(c))) return false;
    if (boundary && !p.boundary.includes(boundary)) return false;
    // [P1-FIX 2026-09-05] 版本分支：条目可用 minVersion / maxVersion 声明适用区间
    //   · minVersion：目标版本 >= 该值才投放（如 MSSQL STRING_AGG 需 2017+）
    //   · maxVersion：目标版本 < 该值才投放（如 MySQL<5.7 的 password 列）
    //   版本未知（dbmsVersion 为 null 或 major 为 null）→ 不过滤（保守：不因未知砍 payload）
    if (dbmsVersion && dbmsVersion.major != null) {
      if (p.minVersion != null && !versionAtLeast(dbmsVersion, p.minVersion)) return false;
      if (p.maxVersion != null && !versionBelow(dbmsVersion, p.maxVersion)) return false;
    }
    // testFilter：白名单 — id 须包含任一 filter 子串（filterIds 为空时跳过此检查）
    if (filterIds.length > 0 && !filterIds.some((f) => p.id.toLowerCase().includes(f))) return false;
    // testSkip：黑名单 — id 包含任一 skip 子串则排除
    if (skipIds.some((s) => p.id.toLowerCase().includes(s))) return false;
    // [P0-FIX 2026-09-09] productionMode 硬门：未确认则高危池模板不投放（不抛错、不中断扫描）。
    // 实战后果：一次误配置就把 RCE/写文件 payload 送进生产库，或反过来让使用者以为 risk 生效了
    // 而实际没测——两种都是事故。抑制本身必须进报告，见 ScanManager._noteConstraint。
    if (gate && !gate.allowed && isDestructivePayload(p)) return false;
    return true;
  });
}

/**
 * [P0-FIX 2026-09-09] 统计「若不考虑高危池硬门，本配置会投到多少条高危模板」。
 * 供 ScanManager 判断是否需要往 report.summary.constraints 记一条抑制说明——
 * 避免「risk=3 但 level=1 本来就投不到」时记一条假约束（误导读的人去改无关开关）。
 * 与 selectPayloads 共用 level/risk/testFilter/testSkip 语义（不看 dbms/clause/boundary：
 * 取保守上界，宁可多记一条也不能漏记）。
 * @param {{level?:number, risk?:number, testFilter?:string, testSkip?:string}} [opts]
 * @returns {number}
 */
export function countDestructiveCandidates({ level, risk, testFilter, testSkip } = {}) {
  const filterIds = testFilter
    ? String(testFilter).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
    : [];
  const skipIds = testSkip
    ? String(testSkip).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean)
    : [];
  let n = 0;
  for (const p of PAYLOAD_REGISTRY) {
    if (!isDestructivePayload(p)) continue;
    if (level && p.level > level) continue;
    if (risk && p.risk > risk) continue;
    if (filterIds.length > 0 && !filterIds.some((f) => p.id.toLowerCase().includes(f))) continue;
    if (skipIds.some((s) => p.id.toLowerCase().includes(s))) continue;
    n += 1;
  }
  return n;
}

/**
 * [G1 接线 2026-09-13] 按探测闭合前缀（point.boundary）对注册表条目做「兼容族优先」稳定排序。
 *
 * 背景（对标 sqlmap boundary×payload 笛卡尔积的等价落地）：
 *   sqlmap 用 boundaries.xml × payloads/*.xml 生成「闭合形态 × 载荷族」全积并按 level 门投放；
 *   本架构的注册表条目自带 `boundary` 元数据（声明该模板适用的闭合引号形态），但历史上
 *   selectPayloads 无消费者、检测器按声明顺序全量盲发——兼容形态与无关形态混排，命中即停的
 *   检测器（Boolean 主轮有 break）浪费请求在无关变体上。
 *
 * 兼容单位是「引号族」而非「精确前缀」：
 *   模板仅内嵌最小闭合引号（如 `{ORIG}' AND '1'='1`），引号自平衡——因此单引号族条目对
 *   `')` / `'))` / `%'` 等一切单引号系上下文语法均有效（括号/通配符由模板外原样保留），
 *   实测依据 TimeBlindDetector [real-MySQL FIX 2026-09-07] 选族重排同思路。
 *
 * 排序而非硬过滤（与 sqlmap 的关键差异，刻意为之）：
 *   probeBoundary 在 WAF 拦截探测 payload 时会回退空串（见 Detector.probeBoundary 注释），
 *   硬过滤会让「探测被拦 → boundary 误判」直接灭绝对应闭合族的全部变体 → 漏检。
 *   排序优先保证：命中即停的通道更早命中（省请求）；误判时全集仍在（零回归）。
 *
 * @template T
 * @param {T[]} entries 注册表条目数组
 * @param {string} [boundary] 探测出的闭合前缀（'' / `'` / `')` / `'))` / `"` / `")` / `` ` `` / `\`）
 * @returns {T[]} 排序后数组（无引号族可判定 / 全兼容 / 全不兼容 / 输入<2 条时原样返回）
 */
export function orderEntriesByBoundary(entries, boundary) {
  if (!Array.isArray(entries) || entries.length < 2) return entries;
  // 引号族判定：取探测前缀中首个引号字符。`%'`/`%")` 的 % 是 LIKE 通配符不是闭合符；
  // `\`（反斜杠转义）与 ''（空=无闭合）族不可判定 → 原序返回（不改变现有行为）。
  const m = typeof boundary === 'string' ? boundary.match(/['"`]/) : null;
  if (!m) return entries;
  const quote = m[0];
  const isCompatible = (e) =>
    Array.isArray(e?.boundary) && e.boundary.some((b) => typeof b === 'string' && b.includes(quote));
  const compat = [];
  const rest = [];
  for (const e of entries) (isCompatible(e) ? compat : rest).push(e);
  if (compat.length === 0 || rest.length === 0) return entries;
  return [...compat, ...rest];
}

/**
 * 列出所有声明的 payload（统计/调试用）。
 * @returns {typeof PAYLOAD_REGISTRY}
 */
export function listRegistry() {
  return PAYLOAD_REGISTRY;
}

/**
 * 附加上下文筛选（不变式）：条件省略时默认宽松（全部命中），与 selectPayloads 语义一致。
 * 首个参数可传完整 ctx（含 dbms/technique/config.level/config.risk/clause），兼容检测器直接调用：
 *   selectPayloadsForCtx(ctx, { clause: ['where'] })
 * @param {object} ctx 检测上下文（dbms / technique / config）
 * @param {object} extra 额外筛选条件（并入 dbms/technique/level/risk/clause/boundary）
 * @returns {typeof PAYLOAD_REGISTRY}
 */
export function selectPayloadsForCtx(ctx = {}, extra = {}) {
  const cfg = ctx.config || {};
  return selectPayloads({
    dbms: extra.dbms ?? ctx.dbms,
    technique: extra.technique ?? ctx.technique,
    level: extra.level ?? (Number(cfg.level) > 0 ? Number(cfg.level) : undefined),
    risk: extra.risk ?? (Number(cfg.risk) > 0 ? Number(cfg.risk) : undefined),
    clause: extra.clause,
    boundary: extra.boundary,
    dbmsVersion: extra.dbmsVersion ?? ctx.dbmsVersion,
    testFilter: extra.testFilter ?? cfg.testFilter,
    testSkip: extra.testSkip ?? cfg.testSkip,
  });
}