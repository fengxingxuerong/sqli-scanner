// ============================================================================
// marker.js —— tamper 体系「提取标记 / 占位符」共享工具
//
// 【背景 / 为什么需要它】
//   引擎的 UNION 提取链路依赖三个标记模式在 tamper 后仍能被响应侧匹配：
//     · __S__ / __E__     —— Extractor 标量提取标记
//     · SQLISCANNER<N>    —— injection.js UNION 列探测标记
//     · 7331999<N><N><N>  —— applyTampers 内部占位符（保护标记不直接跑链）
//   编码类 tamper（charencode / chardoubleencode / charunicodeencode …）会把
//   所有字符（包括数字）编码掉，占位符一旦被编码就还原失败 → applyTampers
//   回退到「无保护重新跑链」→ 标记被编码 → UNION 提取**静默失败**（比漏报更危险）。
//
// 【修复策略（P0-D3）】
//   把「哨兵暂存-还原」下沉为共享工具：
//     · applyTampers：把标记抠成占位符（保持原逻辑），跑链前**不再**依赖
//       占位符数字形态本身可穿越 tamper——而是让**每个插件**都用本工具
//       把「标记 + 占位符」一起抠出、变换、放回。数字占位符一旦被编码，
//       也由编码类插件自己的 stash/restore 保住原样。
//     · 编码类插件（charencode / chardoubleencode / charunicodeencode…）：
//       transform 前先 stash 标记与占位符（哨兵字符 \u0001/\u0002 直接透传，
//       不编码），编码完 restore 回去——任何插件单独或链式使用都安全。
//
// 【使用约定】
//   · 插件内部**只引用**本模块的 stash/restore，不复制正则；
//   · stash 的哨兵字符（\u0001/\u0002）**必须**在插件自己的编码逻辑里跳过
//     （它们是单字符，逐字符编码器会命中）；本模块提供 isStashChar 辅助判断。
// ============================================================================

// 引擎与响应之间的提取标记（绝对不可被 tamper 变形）
export const MARKER_RE = /__S__|__E__|SQLISCANNER\d+/g;

// applyTampers 内部占位符（保护标记用的纯数字形态，_PH_PREFIX + 3 位索引）
export const PH_PREFIX = '7331999';
export const PLACEHOLDER_RE = new RegExp(`${PH_PREFIX}\\d{3}`, 'g');

// 哨兵字符（任一插件变换逻辑里应原样透传）
export const STASH_START = '\u0001';
export const STASH_END = '\u0002';
// 哨兵包裹的索引
export const STASH_RE = /\u0001(\d+)\u0002/g;

/** 是否为哨兵字符（供编码类插件在逐字符循环里快速跳过） */
export function isStashChar(ch) {
  return ch === STASH_START || ch === STASH_END;
}

/**
 * 抠出文本中所有匹配 re 的子串，替换为「哨兵 + 索引」。
 * @param {string} text 待处理文本
 * @param {RegExp} re 全局正则（调用方复用同一 re 实例，注意 g 标志）
 * @returns {[string, string[]]} [staged 文本, 抠出的原始子串数组]
 */
export function stash(text, re) {
  const slots = [];
  const staged = String(text ?? '').replace(re, (m) => {
    slots.push(m);
    return `${STASH_START}${slots.length - 1}${STASH_END}`;
  });
  return [staged, slots];
}

/**
 * 把哨兵还原回原始子串（配合 stash 使用）。
 * @param {string} text 含哨兵的文本
 * @param {string[]} slots stash 返回的原始子串数组
 * @returns {string}
 */
export function restore(text, slots) {
  return String(text ?? '').replace(STASH_RE, (_, idx) => slots[Number(idx)] ?? '');
}

/**
 * 一步到位：同时保护「提取标记 + 占位符」。
 * 供编码类插件 transform 开头调用。
 * @param {string} payload
 * @returns {[string, string[]]} [staged, slots]（slots 按「先标记后占位符」顺序）
 */
export function stashAll(payload) {
  // 注意：两次 stash 用**独立的 slots 数组**，最后拼接还原顺序与 stash 顺序相反。
  // 简化：先抠标记、再抠占位符，中间态合到同一 slots 数组由 restore 统一还原。
  const slots = [];
  let staged = String(payload ?? '').replace(MARKER_RE, (m) => {
    slots.push(m);
    return `${STASH_START}${slots.length - 1}${STASH_END}`;
  });
  staged = staged.replace(PLACEHOLDER_RE, (m) => {
    slots.push(m);
    return `${STASH_START}${slots.length - 1}${STASH_END}`;
  });
  return [staged, slots];
}

// 「哨兵 + 数字 + 哨兵」块整体匹配（mapSegments 分段用）
const _SEGMENT_RE = /(\u0001\d+\u0002)/;

/**
 * 按哨兵块分段处理文本：
 *   非哨兵段调用 transformFn(seg)，哨兵段原样返回，最后拼回。
 * 供「整体编码」类插件（base64encode 等）使用 —— 它们无法逐字符跳过哨兵，
 * 分段处理既保住标记语义，又不破坏每段的编码语义。
 *
 * @param {string} text 已 stash 的文本（含哨兵）
 * @param {(seg:string)=>string} transformFn 对非哨兵段的变换
 * @returns {string}
 */
export function mapSegments(text, transformFn) {
  const segments = String(text ?? '').split(_SEGMENT_RE);
  return segments
    .map((seg) => {
      if (/^\u0001\d+\u0002$/.test(seg)) return seg;   // 哨兵块原样
      if (seg === '') return '';
      return transformFn(seg);
    })
    .join('');
}
