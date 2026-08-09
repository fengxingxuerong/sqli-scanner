import { WAF_RULES } from './wafRules.js';

// 大小写不敏感地取响应头值
function getHeader(headers, key) {
  if (!headers || typeof headers !== 'object') return undefined;
  const target = String(key).toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === target) return v;
  }
  return undefined;
}

// 单条 matcher 匹配判定
function matchOne(matcher, response) {
  if (!matcher || typeof matcher !== 'object') return false;
  if (matcher.type === 'header') {
    const v = getHeader(response.headers, matcher.key);
    if (v == null) return false;
    return matcher.test ? matcher.test.test(String(v)) : true; // 无 test 仅要求该头存在
  }
  if (matcher.type === 'body') {
    return !!matcher.test && matcher.test.test(String(response.body ?? ''));
  }
  if (matcher.type === 'status') {
    return !!matcher.test && matcher.test.test(String(response.status ?? ''));
  }
  return false;
}

// matcher 命中依据描述（用于 evidence 字段，便于审计）
function describeMatcher(matcher) {
  if (matcher.type === 'header') {
    return matcher.test ? `header: ${matcher.key}~${matcher.test}` : `header: ${matcher.key}`;
  }
  if (matcher.type === 'body') return `body~${matcher.test}`;
  if (matcher.type === 'status') return `status~${matcher.test}`;
  return matcher.type || 'unknown';
}

/**
 * WAF 指纹识别器（纯函数，无副作用、零额外发包）。
 * 仅比对指纹阶段已抓取的 baseline 响应（status / headers / body）。
 */
export class WafIdentifier {
  constructor(rules = WAF_RULES) {
    this.rules = rules;
  }

  /**
   * 识别响应中的 WAF 厂商。
   * @param {{status:number, headers:object, body:string}} response 指纹阶段基线响应
   * @returns {Array<{vendor:string, confidence:number, evidence:string}>} 按 confidence 降序；无特征返回 []
   */
  identify(response) {
    const resp = response || {};
    const candidates = [];
    for (const [vendor, rule] of Object.entries(this.rules)) {
      const evidences = [];
      let hits = 0;
      for (const m of rule.matchers || []) {
        if (matchOne(m, resp)) {
          hits += 1;
          evidences.push(describeMatcher(m));
        }
      }
      if (hits > 0) {
        // 命中即 0.8+，每多一个 matcher 命中 +0.1（封顶 0.99）；多特征交叉提升置信度
        const confidence = Math.min(0.99, 0.8 + (hits - 1) * 0.1);
        candidates.push({ vendor, confidence, evidence: evidences.join('; ') });
      }
    }
    // 按置信度降序
    candidates.sort((a, b) => b.confidence - a.confidence);
    return candidates;
  }
}

export default WafIdentifier;
