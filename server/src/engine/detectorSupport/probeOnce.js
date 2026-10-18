// ============================================================================
// detectorSupport/probeOnce.js —— [D106] 专用验证器共用的单发探针
// ----------------------------------------------------------------------------
// xmlParamName（D105 算术位移）与 orderByKey（D106 序数差分）两个验证器都遵循同一
// 探针纪律：发送 → 判可用性（unusableOf）→ 不可用即 inconclusive（绝不把网络抖动
// 当信号）→ 返回响应与正文供判定。此模式原先在两文件各写四遍，触发去重门禁
// （129 token 跨文件克隆），抽为单一实现。
// ============================================================================

/**
 * 单发探针 + 可用性判定。
 * @param {{ unusableOf: (res: any) => string | null }} detector
 * @param {(value: string) => Promise<any>} send
 * @param {string} value 探针值（注入进键名/元素名）
 * @param {string} label 不可用原因前缀（写进 inconclusiveReason）
 * @returns {Promise<{ ok: true, res: any, body: string } | { ok: false, why: string }>}
 */
export async function probeOnce(detector, send, value, label) {
  const res = await send(value);
  const why = detector.unusableOf(res);
  if (why) return { ok: false, why: `${label}不可用：${why}` };
  return { ok: true, res, body: String(res?.data ?? '') };
}

/**
 * 把探针结果归入 DetectionResult 的公共部分（xmlParamName/orderByKey 共用）：
 * inconclusive ⇒ 置未决并返回 false；none ⇒ false；vuln ⇒ 置 vulnerable/dbms 并返回 true。
 * @param {import('../models.js').DetectionResult} result
 * @param {{ status: string, reason?: string }} out
 * @param {string | null | undefined} dbms
 * @returns {boolean} 是否命中
 */
export function applyProbeOutcome(result, out, dbms) {
  if (out.status === 'inconclusive') {
    result.inconclusive = true;
    result.inconclusiveReason = out.reason;
    return false;
  }
  if (out.status !== 'vuln') return false;
  result.vulnerable = true;
  result.dbms = dbms || null;
  return true;
}

export default probeOnce;
