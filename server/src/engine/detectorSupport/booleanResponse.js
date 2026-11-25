// =====================================================================
// booleanResponse.js — BooleanBlindDetector 的响应比对纯函数族
//
// [D325] 自 BooleanBlindDetector.js 纯搬移：14 个方法均无实例状态依赖，
// 原类保留 _xxx 薄委托（测试与类内调用点 det._similar(...) 全部不变）。
// 拆分动机：原文件 1196 行贴 arch 1200 硬上限（差 4 行），下一批 detector
// 改动即触发基线豁免决策。豁免一次锚就松一次，故趁无功能变更主动拆。
//
// 判据注释按原文保留（含历次误报根因），不因搬移丢失教训。
// =====================================================================
import { chunkSimilarity } from '../../core/statsHelper.js';

// 空白字符判定（对齐 JS /\s/ 语义，避免每次 new RegExp）：
// 热路径 isMeaningfulDiff 逐字符调用本判定，旧实现 `/\s/.test(ch)` 每次调用都走正则引擎
// （大 body 全等时逐字符扫全串，100KB 级 = 10 万次正则 test ≈ 数 ms）。
// 改为 charCode 快速判定：ASCII 空白直判；罕见 Unicode 空白走 Set（与 /\s/ 完全一致）。
const WS_RARE = new Set([0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff]);

// —— 动态数值归一化（[P1-FIX 2026-09-08] 安全点误报根治）——
// 场景：页面含秒级时间戳/计数器（如 `<!-- generated at 1788758518 -->`）。基线 5 次采样
// 通常落在同一秒内 → 动态块识别学到「无动态块」→ 回落默认比对；后续真/假采样跨秒时，
// 时间戳数字变化让 LCP 在首部崩塌、分块相似率也被稀释 → 真/假被判「偏离基线」→ 安全点误报。
// 判据（保守，仅兜底）：两串长度相同，且把每段「≥8 位连续数字」替换成同一占位符后文本
// 完全一致 → 差异仅来自动态数值，判相似。零额外请求。
// 阈值取 8 位的理由：Unix 秒级时间戳 10 位 / 毫秒 13 位被归一化；而列表编号、行号、ID 等
// 短数字（1-5 位）保留语义——它们常是真假条件的真实差异（如 user_1 / user_2），一概归一化
// 会把真注入信号吞掉（blindRobust 高抖动用例即此形态）。
const LONG_NUM_RUN_RE = /\d{8,}/g;
function numericNormalized(s) {
  return s.replace(LONG_NUM_RUN_RE, '\u0000');
}
export function isWsChar(ch) {
  const c = ch.charCodeAt(0);
  if (c < 0x80) return c === 0x20 || (c >= 0x09 && c <= 0x0d);
  if (c >= 0x2000 && c <= 0x200a) return true; // en quad..hair space（\s 含 2000-200a）
  return WS_RARE.has(c);
}

export function bodyOf(r) {
  if (!r || r.__error || !r.resp) return '';
  return String(r.resp?.data ?? '');
}

// —— 二级判据：组间稳定差异（[P0-FIX 2026-09-10] 布尔通道系统性漏报根治）——
// 根因：现代页面真假差异常仅占全文 5~15%（大模板 + 一小块内容差），假值页被 similar 判成
// 「≈基线」→ legacy/robust 的「假≠基线」条件恒为假 → 整个布尔通道失效（页面越像越漏报，与真实形态相反）。
// 改判据不依赖「假≠基线」，而是要求：
//   ① 真组内部稳定（每个真样本在差异片段处内容一致）
//   ② 假组内部稳定（每个假样本在差异片段处内容一致）
//   ③ 真/假差异片段可复现（所有真样本一致、所有假样本一致，且二者不同）
// 随机 nonce/时间戳因组内不自相似（每次 nonce 不同）→ ①② 证伪 → 排除，误报率保持 0；
// 差异片段本身是 8+ 位数字（时间戳/计数器）则按 numericNormalized 判无效（动态噪声过滤，保留短数字真实信号）。
// 仅当原判据失效且真/假确有差异时进入（不放宽进入条件、不改原判定逻辑，零回归）。
// @param {string[]} tBodies 真条件响应体样本（≥1；robust 复用已采样数组，legacy 补足到 N）
// @param {string[]} fBodies 假条件响应体样本（≥1）
// @returns {{first:number,last:number,tSpan:string,fSpan:string}|null} 命中返回差异片段信息，否则 null
export function stableDiffJudge(tBodies, fBodies) {
  if (!tBodies || !fBodies || tBodies.length === 0 || fBodies.length === 0) return null;
  const t0 = tBodies[0];
  const f0 = fBodies[0];
  const span = diffSpan(t0, f0);
  if (!span) return null; // 无差异（原判定已拦 meaningfulDiff；此处兜底）
  const { first, last } = span;
  const tSpan = t0.slice(first, last);
  const fSpan = f0.slice(first, last);
  if (tSpan === fSpan) return null; // 差异片段相同 → 无信号
  // ① 真组内部稳定：每个真样本在差异片段处内容一致
  for (const ti of tBodies) {
    if (ti.slice(first, last) !== tSpan) return null;
  }
  // ② 假组内部稳定：每个假样本在差异片段处内容一致
  for (const fi of fBodies) {
    if (fi.slice(first, last) !== fSpan) return null;
  }
  // ③ 动态噪声过滤：差异仅由 8+ 位数字（时间戳/计数器）构成则判无效
  if (numericNormalized(t0) === numericNormalized(f0)) return null;
  return { first, last, tSpan, fSpan };
}

/**
 * [P0-FIX 2026-09-11] 反射回显甄别：差异片段若来自「页面把注入值原样回显」，
 * 不构成注入证据（waf-real echo 安全对照误报根因，请求级追踪 2/2 复现）。
 * 机理：echo 类页面把参数值渲染进响应（key = <value>），真/假 payload（如
 * `abc AND 1=1` vs `abc AND 1=2`）都被放行时，唯一差异就是回显的 payload 自身——
 * 组间稳定差异三条件全满足（差异可复现、组内一致、非数值噪声），但它只是反射。
 * 判据（保守，只杀确定形态）：真/假差异片段各自「出现在对方 payload 的回显里」——
 * 即 tSpan 是 truePayload 的（去空格）子串且 fSpan 是 falsePayload 的子串。
 * SQL 执行差异（如行数变化导致的表格/文案差异）不会恰好等于 payload 文本本身。
 * @param {string} tSpan 真组差异片段
 * @param {string} fSpan 假组差异片段
 * @param {string} truePayload
 * @param {string} falsePayload
 * @returns {boolean} true = 反射回显（该对应跳过）
 */
export function isReflectedDiff(tSpan, fSpan, truePayload, falsePayload) {
  if (!tSpan || !fSpan || !truePayload || !falsePayload) return false;
  const norm = (s) => String(s).replace(/\s+/g, '');
  const tp = norm(truePayload);
  const fp = norm(falsePayload);
  const ts = norm(tSpan);
  const fs = norm(fSpan);
  if (!ts || !fs) return false;
  return tp.includes(ts) && fp.includes(fs);
}

// 两串差异片段起止下标（半开区间 [first, last)）：最长公共前缀之后到最长公共后缀之前。
// 完全相同（含等长同串）或仅长度不同、无内部内容差异（如 abc vs abcd）返回 null。供稳定差异判据定位「到底差在哪一块」。
export function diffSpan(a, b) {
  const m = Math.min(a.length, b.length);
  let first = 0;
  while (first < m && a[first] === b[first]) first++;
  if (first === m && a.length === b.length) return null; // 完全相同
  let last = m;
  while (last > first && a[last - 1] === b[last - 1]) last--;
  if (first === last) return null; // 仅长度不同、无内部内容差异 → 视为无信号
  return { first, last };
}

// 差异片段预览（截断 + 空值占位），供 evidence 展示
export function sdPreview(s, max = 40) {
  const str = String(s == null ? '' : s);
  if (str.length === 0) return '(空)';
  return str.length > max ? `${str.slice(0, max)}…` : str;
}

// 响应片段（截断控制 trace 体积，便于人工审计"页面主体变化"）
export function excerpt(s, max = 160) {
  return String(s == null ? '' : s).slice(0, max);
}

// 首个不同字符下标（-1 表示完全相同）
export function firstDiffOffset(a, b) {
  const m = Math.min(a.length, b.length);
  for (let i = 0; i < m; i++) if (a[i] !== b[i]) return i;
  if (a.length !== b.length) return m;
  return -1;
}

// 状态码粗筛（P2-P8 CPU 比对下沉）：两者状态码均可知且不同 → 响应明显不同，
// 调用方可跳过 body 精细比对（大 body 省 LCP/分块 hash）。
export function statusDiffer(a, b) {
  return a?.status != null && b?.status != null && a.status !== b.status;
}

// 响应头数值化 content-length（无头/非数值返回 null；axios 头可能是数组，取首值）
export function contentLengthOf(res) {
  const h = res?.headers;
  if (!h) return null;
  const raw = h['content-length'] ?? h['Content-Length'];
  if (raw == null) return null;
  const n = Number(Array.isArray(raw) ? raw[0] : raw);
  return Number.isFinite(n) && n >= 0 ? n : null;
}

// content-length 短路（T3，P2-P8 状态码粗筛的同构扩展）：两响应均带数值 content-length
// 且差异超出容差（与 similar 长度容差同参：max(24, 较小者 12%)）→ 直接判「不同」，
// 调用方跳过 body 全文 LCP/分块比对，省大 body CPU 全扫。
// 头缺失/不可解析时返回 false（回落 body 比对，mock/老网关行为不变）。
export function lengthDiffer(a, b) {
  const la = contentLengthOf(a);
  const lb = contentLengthOf(b);
  if (la == null || lb == null) return false;
  return Math.abs(la - lb) > Math.max(24, Math.min(la, lb) * 0.12);
}

// 排除纯空白差异，要求有实质不同。
// P2-P8 零分配流式比对：语义等价 a.replace(/\s+/g,'') !== b.replace(/\s+/g,'')，
// 但不对大 body 产生两份整串拷贝（省 CPU 与 GC 压力）。
export function isMeaningfulDiff(a, b) {
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > 1) return true;
  let i = 0;
  let j = 0;
  while (i < la || j < lb) {
    while (i < la && isWsChar(a[i])) i++;
    while (j < lb && isWsChar(b[j])) j++;
    if ((i < la ? a[i] : null) !== (j < lb ? b[j] : null)) return true;
    i++;
    j++;
  }
  return false;
}

// 与任一基线样本相似（容忍动态内容的轻微抖动）
export function similarToBaseline(body, baselines) {
  return baselines.some((b) => similar(body, b));
}

// 相似判定：长度差在容差内，且最长公共前缀覆盖较短者 85% 以上。
// P1-P1 轻量布尔指标：大 body（> 64KB）时以「长度差」为主判定（长度差超容差即不相似，直接返回），
// 避免对超大响应体做逐字符 LCP 扫描，省 CPU；小 body 才做精确 LCP（行为不变，零回归）。
// P1-D4 响应相似度升级：LCP 未达标但「分块相似率 ≥ 0.85」时兜底判相似——
// 首部动态内容（时间戳/anti-CSRF token）会让 LCP 崩塌，分块比对不受首块差异影响，提升召回。
export function similar(a, b) {
  if (a === b) return true;
  const la = a.length;
  const lb = b.length;
  const lenDelta = Math.abs(la - lb);
  // 大 body 快速路径：长度差超出容差 → 直接判定不相似，跳过 LCP
  if (lenDelta > Math.max(24, lb * 0.12)) return false;
  // 大 body 且长度差在容差内 → 用「首尾+中间采样」近似判定（省逐字符扫描）
  if (la > 65536 || lb > 65536) {
    const head = 256;
    const tail = 256;
    if (a.slice(0, head) !== b.slice(0, head)) return false;
    // ★FIX [P0]：尾部比较不限于 la===lb，各自取末尾 256 字符；
    // 增加中间采样点（50% 处取 256 字符），覆盖差异在 body 中间的情况。
    // 旧实现仅 la===lb 时才比尾部、且只比头尾 → 大 body 中间差异漏报。
    if (a.slice(-tail) !== b.slice(-tail)) return false;
    const midA = a.slice(Math.floor(la / 2), Math.floor(la / 2) + head);
    const midB = b.slice(Math.floor(lb / 2), Math.floor(lb / 2) + head);
    if (midA !== midB) return false;
    return true;
  }
  const m = Math.min(la, lb);
  // [P1-FIX 2026-09-08] 空串退化防护：一方为空时 m=0，LCP 判定 `0 >= 0*0.85` 恒真
  // → 空响应被判「与任何基线相似」。典型后果：JSON API 的假条件返回 `[]`（2B）与
  // 真条件完整 JSON 无法区分 → 布尔盲注恒漏检。空串只与空串相似。
  if (m === 0) return la === lb;
  let common = 0;
  while (common < m && a[common] === b[common]) common++;
  if (common >= m * 0.85) return true;
  // P1-D4：LCP 不达标时用分块相似率兜底（首部动态内容场景）
  // P1-FIX 2026-09-08：最后兜底「动态数值归一化」——等长且仅数字段不同（秒级时间戳）
  // 时判相似，抑制安全点误报（详见 numericNormalized 注释）。
  if (la === lb && numericNormalized(a) === numericNormalized(b)) return true;
  return chunkSimilarity(a, b) >= 0.85;
}
