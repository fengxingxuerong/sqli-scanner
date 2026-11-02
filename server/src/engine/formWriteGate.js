// ============================================================================
// formWriteGate.js —— 自动发现表单的写请求门控（[P1-SAFE 2026-11-02]，D247 自 TargetParser.js 逐字迁出）
//
// 表单爬取会把页面上的每个 form 变成注入点；旧实现确认只做了「爬不爬」，
// 没做「这个 action 会不会改数据」。POST/PUT/PATCH/DELETE 一律视为写请求：
//   · confirmFormWrites!==true → 不建点（报告 summary.constraints 显式说明）；
//   · logout/delete/remove/update 等高风险路径 → 即使确认也跳过（默认安全）。
//
// 迁出缘由：TargetParser.js 1241 行超 arch 门禁 1200 上限（新债拦截）；
// 本函数族零 TargetParser 内部依赖（parser 实例由调用方传入），逐字搬移零行为变化。
// 行为判据：server/tests/targetParser.formWriteGate.test.js。
// ============================================================================

const FORM_WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const FORM_HIGH_RISK_PATH_RE =
  /(^|\/)(logout|signout|sign-out|delete|remove|destroy|update|edit|reset|revoke|unsubscribe|withdraw|注销|删除|退出)(\/|$|[.?#-])/i;

/** 取表单 action 的 pathname（解析失败时退回原串，用于风险路径匹配）。 */
function formActionPath(action) {
  try {
    return new URL(String(action || '')).pathname;
  } catch {
    return String(action || '');
  }
}

/**
 * 判断一个自动发现表单是否应跳过；返回原因码（null = 可建点）。
 * 抽成纯函数的目的：`_pushFormPoints` 的圈复杂度已贴软上限，分支不能再内联。
 * @param {object} form
 * @param {object} config
 * @returns {string|null}
 */
function formWriteSkipReason(form, config) {
  const method = String(form && form.method || 'GET').toUpperCase();
  if (FORM_HIGH_RISK_PATH_RE.test(formActionPath(form && form.action))) return 'high-risk-action';
  if (FORM_WRITE_METHODS.has(method) && config && config.confirmFormWrites !== true) {
    return 'form-writes-unconfirmed';
  }
  return null;
}

/** 把一次表单跳过登记到 target（最多 20 条，供 summary.constraints 汇总）。 */
function noteFormDiscoverySkip(target, form, reason) {
  if (!target || typeof target !== 'object') return;
  target.formDiscoveryGate = target.formDiscoveryGate || { skipped: 0, items: [] };
  target.formDiscoveryGate.skipped += 1;
  if (target.formDiscoveryGate.items.length < 20) {
    target.formDiscoveryGate.items.push({
      action: String(form && form.action || '').slice(0, 300),
      method: String(form && form.method || 'GET').toUpperCase(),
      reason,
    });
  }
}

/**
 * 计算一个表单的注入点元信息；被门控跳过时返回 null 并登记原因。
 * @param {object} parser TargetParser 实例（需 _urlWithValues / _inferStoreKind）
 * @param {object} form
 * @param {object} target
 * @returns {{loc:string,actionUrl:string,csrf:string|null,isStore:boolean,storeKind:string|null}|null}
 */
function buildFormPointMeta(parser, form, target) {
  const config = (target && target.config) || {};
  const method = String(form && form.method || 'GET').toUpperCase();
  const skipReason = formWriteSkipReason(form, config);
  if (skipReason) {
    noteFormDiscoverySkip(target, form, skipReason);
    return null;
  }
  const loc = method === 'POST' ? 'body' : 'url';
  return {
    loc,
    actionUrl: loc === 'url' ? parser._urlWithValues(form.action, form.values) : form.action,
    csrf: form.csrfTokenName || null,
    isStore: form.method === 'POST',
    storeKind: form.method === 'POST' ? parser._inferStoreKind(form.values) : null,
  };
}

export { buildFormPointMeta };
