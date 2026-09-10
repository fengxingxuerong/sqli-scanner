// ============================================================================
// knownPoint.js — 已知注入点直通（手工验证后的点直接进入利用/检测主循环）
//
// 实战背景：手工测试已确认某参数可注入（闭合形态、技术位都摸清了），但引擎仍会：
//   ① 预筛选探针（3 请求/点）——已知可注入点不需要「有没有迹象」的判定；
//   ② 闭合探测（probeBoundary 13 候选并发 13 请求）——闭合形态已由使用者给定；
//   ③ 全技术位扫描——只测已确认的技术位即可。
// config.knownPoint = { param, quote?, paren?, techniques? }：
//   · param       参数名（必填，匹配 InjectionPoint.param）；
//   · quote/paren 闭合形态（如 quote="'"、paren="）"），提供后跳过闭合探测；
//   · techniques  技术位白名单（union/error/boolean/time/stacked/oob/inline/second_order），
//                 提供后作为扫描级技术过滤（与 config.techniques 取交集）。
// ============================================================================

const TECHS = new Set([
  'union', 'error', 'boolean', 'time', 'stacked', 'oob', 'inline', 'second_order',
]);

/** 校验 knownPoint 配置形状（param 必填非空） */
export function normalizeKnownPoint(kp) {
  if (!kp || typeof kp !== 'object') return null;
  const param = kp.param != null ? String(kp.param).trim() : '';
  if (!param) return null;
  const out = { param };
  if (kp.quote != null) out.quote = String(kp.quote);
  if (kp.paren != null) out.paren = String(kp.paren);
  if (Array.isArray(kp.techniques) && kp.techniques.length) {
    const techs = kp.techniques.map(String).filter((t) => TECHS.has(t));
    if (techs.length) out.techniques = [...new Set(techs)];
  }
  return out;
}

/**
 * 对注入点集合应用已知点标记（预筛选/闭合探测之前调用）。
 * 匹配的点打 knownPoint=true（预筛选保守保留、闭合探测短路、基线请求仍发以学习页面特征）。
 * @param {Array<{param?:string}>} points 注入点
 * @param {object} config 扫描配置
 * @returns {number} 命中的点数
 */
export function applyKnownPoints(points, config) {
  const kp = normalizeKnownPoint(config && config.knownPoint);
  if (!kp || !Array.isArray(points)) return 0;
  let n = 0;
  for (const p of points) {
    if (p && typeof p.param === 'string' && p.param === kp.param) {
      p.knownPoint = true;
      if (kp.quote != null || kp.paren != null) {
        // 闭合形态由使用者给定：直接写死，probeBoundary 短路返回，不再发 13 候选探测
        p.boundary = `${kp.quote || ''}${kp.paren || ''}`;
        p.knownBoundary = true;
      }
      n++;
    }
  }
  return n;
}
export default { normalizeKnownPoint, applyKnownPoints };
