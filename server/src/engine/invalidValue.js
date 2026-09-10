// ============================================================================
// invalidValue.js — 失效值替换（对标 sqlmap --invalid-bignum / --invalid-logical /
// --invalid-string）
//
// 实战背景：布尔盲注的 payload 以参数「有效值」为前缀（如 ?id=1 AND 1=1）。真实站点上
// 这个有效值会命中 CDN/应用层缓存或与静态页同形 → 真/假响应无差异 → 判定「不可注入」。
// sqlmap 的解法：把有效值替换成随机大数 / 逻辑表达式 / 随机字符串，让每次请求都绕开缓存。
//
// 语义（与 sqlmap 对齐，但真值语义保守化）：
//   · bignum  → 随机大整数（1e6~1e9），数值上下文缓存穿透首选；
//   · logical → `n=n`（随机 n）——sqlmap 用 `1=2` 形态，但那会让基线请求恒假，
//     破坏「基线 ≈ 真页面」的判定前提；这里取恒真等值式，缓存穿透 + 语义安全兼得；
//   · string  → 随机小写字母串（数值上下文会注入失败，与 sqlmap 一致，由使用者自担）。
// ============================================================================

const MODES = new Set(['bignum', 'logical', 'string']);

/** 是否为合法的失效值替换模式 */
export function isValidInvalidMode(mode) {
  return MODES.has(String(mode || ''));
}

const randBigNum = () => String(Math.floor(1_000_000 + Math.random() * 900_000_000));
const randLogical = () => {
  const n = Math.floor(1_000 + Math.random() * 900_000);
  return `${n}=${n}`;
};
const ALPHA = 'abcdefghijklmnopqrstuvwxyz';
const randString = () =>
  Array.from({ length: 8 }, () => ALPHA[Math.floor(Math.random() * ALPHA.length)]).join('');

/**
 * 把参数有效值替换为「失效值」（缓存/静态页噪声规避）。
 * @param {string} orig 原始有效值
 * @param {string} mode 'bignum' | 'logical' | 'string'
 * @returns {string} 失效值（mode 非法时原样返回，绝不抛错）
 */
export function invalidize(orig, mode) {
  const m = String(mode || '');
  if (m === 'bignum') return randBigNum();
  if (m === 'logical') return randLogical();
  if (m === 'string') return randString();
  return String(orig ?? ''); // 未启用/非法模式：零行为变化
}

/**
 * 对注入点集合应用失效值替换（检测前调用一次）。
 * 直接改写 point.originalValue → 探测/检测/提取全链路（fillPayload 的 {ORIG}、
 * probeBoundary 基线、盲注提取 base）统一生效，与 sqlmap 单点替换语义一致。
 * @param {Array<{originalValue?:string}>} points 注入点
 * @param {object} config 扫描配置
 * @returns {number} 实际替换的点数
 */
export function applyInvalidValues(points, config) {
  const mode = config && config.invalidValue;
  if (!isValidInvalidMode(mode) || !Array.isArray(points)) return 0;
  let n = 0;
  for (const p of points) {
    if (p && typeof p.originalValue === 'string' && p.originalValue !== '') {
      p.originalValue = invalidize(p.originalValue, mode);
      n++;
    }
  }
  return n;
}
export default { invalidize, applyInvalidValues, isValidInvalidMode };
