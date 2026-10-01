// =====================================================================
// similarity.js — 响应相似度判定：分块比对（chunkedSimilar）/ 动态块过滤构建器
// （buildDynamicSimilarFn / buildDynamicSimilarGated，检测与提取两层共用入口）。
// 自 Detector.js 拆出（纯搬移）：chunkedSimilar/buildDynamicSimilar 由
// Detector.prototype 挂载（this 语义不变）；两个独立构建器保持具名导出。
// =====================================================================
import {
  chunkSimilarity, chunkHashes, dynamicBlockFilter, buildTokenBagSimilarFn,
} from '../../core/statsHelper.js';

/**
 * [P0 导出] 排除动态块的相似判定构建器（独立函数）。
 * 供 Detector.buildDynamicSimilar 与 Extractor 提取阶段（_dynJudge）共用，
 * 保证检测与提取两层的动态内容感知逻辑不漂移。
 * @param {string[]} baselines 同一注入点的多次基线响应体
 * @returns {function|null} (a, b) => boolean 相似判定；无动态块时返回 null
 */
export function buildDynamicSimilarFn(baselines) {
  const { dynamicIdx } = dynamicBlockFilter(baselines);
  if (!dynamicIdx || dynamicIdx.size === 0) return null;
  return (a, b) => {
    const sa = String(a ?? '');
    const sb = String(b ?? '');
    if (sa === sb) return true;
    if (Math.abs(sa.length - sb.length) > Math.max(24, Math.max(sa.length, sb.length) * 0.12)) return false;
    const ha = chunkHashes(sa);
    const hb = chunkHashes(sb);
    const n = Math.max(ha.length, hb.length, 1);
    let same = 0;
    let total = 0;
    for (let k = 0; k < n; k++) {
      if (dynamicIdx.has(k)) continue; // 跳过动态块
      total++;
      if ((ha[k] ?? 0) === (hb[k] ?? 0)) same++;
    }
    return total === 0 ? true : same / total >= 0.85;
  };
}

/**
 * [P1-FLAKY 2026-09-27] 门控版构建器——检测层（buildDynamicSimilar 方法）与提取层
 * （blindExtractor._dynJudge）共用的**单一入口**。此前提取层直接调 buildDynamicSimilarFn
 * 绕过门控，HTML 动态页上提取真值判定仍用位移敏感的 positional 过滤器（与检测层不对称）。
 *
 * 语义：config.autoDynamicBlock !== true → null（回退现状）；
 * 基线为 HTML 形态且动态块占比 ≥0.3（位移确实在发生）→ 标签边界 token 袋骨架判定
 * （变长内容被关在单个 token 里不再传播位移，块洗牌由无序 bag 天然免疫）；
 * 其余（动态占比低的静态页 / 非 HTML）→ positional 动态块过滤（现状，零行为变化）。
 *
 * @param {string[]} baselines 同一注入点的多次基线响应体
 * @param {object} config 检测配置（含 autoDynamicBlock 开关）
 * @returns {function|null} 排除动态块后的相似判定 (a, b) => boolean；关闭/无动态块返回 null
 */
export function buildDynamicSimilarGated(baselines, config) {
  if (!config || config.autoDynamicBlock !== true) return null;
  // 位移退化度量：动态块占基线最大块数的比例
  const bodies = (baselines ?? []).map((b) => String(b ?? '')).filter((b) => b.length > 0);
  if (bodies.length >= 2) {
    const { dynamicIdx } = dynamicBlockFilter(bodies);
    const maxChunks = Math.ceil(Math.max(...bodies.map((b) => b.length)) / 64);
    const htmlShaped = bodies.every(
      (b) => ((b.match(/</g) ?? []).length * 100) / Math.max(b.length, 1) >= 2
    );
    if (htmlShaped && maxChunks > 0 && dynamicIdx.size / maxChunks >= 0.3) {
      const tokFn = buildTokenBagSimilarFn(bodies);
      if (tokFn) return tokFn;
    }
  }
  return buildDynamicSimilarFn(baselines);
}

  /**
   * 分块比对相似度（对标 sqlmap 页面比较引擎）：先走长度容差 + 最长公共前缀（快速路径），
   * LCP 未达标时用分块相似率兜底——首部动态内容（时间戳/anti-CSRF token）不再让整串 LCP 崩塌。
   * P2-P8 CPU 比对下沉：大 body（>64KB）用首尾采样近似判定，避免逐字符 LCP 扫描（与
   * BooleanBlindDetector._similar 对齐）——首尾采样能确认相似时直接返回（省整串分块 hash）；
   * 首/尾不匹配（可能含动态首块）时回落分块相似率兜底，语义不弱化。
   * @param {string} a 基准响应体
   * @param {string} b 待比对响应体
   * @returns {boolean} 是否判相似
   */
export function chunkedSimilar(a, b) {
    if (a === b) return true;
    const la = a.length;
    const lb = b.length;
    if (Math.abs(la - lb) > Math.max(24, Math.max(la, lb) * 0.12)) return false;
    if (la === 0 || lb === 0) return la === lb;
    if (la > 65536 || lb > 65536) {
      // 大 body 快速路径：首尾各取 256 字符采样；均匹配（同长度时含尾段）→ 判相似（省整串 hash）；
      // 任一不匹配 → 不能轻率判相似，回落分块相似率兜底（动态首块场景不变）。
      const m = Math.min(la, lb);
      const head = 256;
      const tail = 256;
      const headOk = a.slice(0, head) === b.slice(0, head);
      const tailOk = la !== lb || a.slice(m - tail) === b.slice(m - tail);
      if (headOk && tailOk) return true;
      return chunkSimilarity(a, b) >= 0.85;
    }
    const m = Math.min(la, lb);
    let common = 0;
    while (common < m && a[common] === b[common]) common++;
    if (common >= m * 0.85) return true;
    return chunkSimilarity(a, b) >= 0.85;
  }

  /**
   * 自动动态块识别（深化 chunkedSimilar）：对基线两两比对，标记「高频差异块下标」为动态块，
   * 返回排除动态块后的相似判定函数（长度容差 + 非动态块相似率 ≥ 0.85）。
   * config.autoDynamicBlock === true 才启用；关闭或无动态块时返回 null（回落现状分块比对，默认路径不变）。
   *
   * [P1-FLAKY 2026-09-27] HTML 动态页切换「标签边界 token 袋」判定（noisy 布尔漏检根治）：
   * fixed-offset 分块对内容位移不鲁棒——变长动态段之后的所有块边界错位，过滤器在
   * 「全动态（similar 恒真，检测靠二级判据兜底）」与「半动态（噪声虚高 → 门槛抬高 →
   * 漏检）」两态间翻硬币（load-repro 实测 noise=0.40/0.00 两态）。故当基线为 HTML 形态
   * 且动态块占比 ≥ 30%（位移确实在发生）时，切换为标签边界 token 袋骨架判定
   * （变长内容被关在单个 token 里不再传播位移，块洗牌由无序 bag 天然免疫）；
   * 动态占比低（常见静态页，现有路径工作良好）或非 HTML 时维持现状，零行为变化。
   * @param {string[]} baselines 同一注入点的多次基线响应体
   * @param {object} config 检测配置（含 autoDynamicBlock 开关）
   * @returns {function|null} 排除动态块后的相似判定 (a, b) => boolean；关闭/无动态块返回 null
   */
export function buildDynamicSimilar(baselines, config) {
    return buildDynamicSimilarGated(baselines, config);
  }
