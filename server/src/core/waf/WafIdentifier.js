import { WAF_RULES } from './wafRules.js';
import { detectGenericBlock } from './blockSignatures.js';

// 高置信 WAF 阈值：置信度 >= 此值才允许自动 tamper 重跑（防低置信/单特征误触发导致请求爆炸）。
export const WAF_HIGH_CONFIDENCE = 0.8;

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
   * 两层判据：① wafRules.js 的 62 家厂商签名（高置信，可驱动 autoRetry）；
   *           ② blockSignatures.js 的通用拦截页特征（vendor='generic_block'，置信度封顶 0.6，
   *              只说明「被拦了」，不说明「被谁拦」）。
   * @param {{status:number, headers:object, body:string}} response 指纹阶段基线响应
   * @returns {Array<{vendor:string, confidence:number, evidence:string, source?:string, alsoMatched?:string[]}>} 按 confidence 降序；无任何特征返回 []
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

    // —— 通用拦截页识别：接在厂商签名之后、unknown 兜底之前（同样复用基线响应，零额外发包）——
    // 为什么必须补这一层：62 家厂商签名是静态快照，国产云 WAF 月更页面 / CDN 透传规则 /
    // 自建 ModSecurity 改写过的拒绝页必然漏；「识别不出」过去被当成「不存在」，引擎于是
    // 继续用裸 payload 撞同一面墙。通用签名至少能把「本站在拦截我们」这件事说出口。
    const generic = detectGenericBlock(resp);
    if (generic) {
      if (candidates.length > 0) {
        // 厂商优先：已能命名厂商时，通用命中只作为该条的附注（alsoMatched = 命中的通用特征 id），
        // 不新增候选条目——避免同一结论以 0.55 的低置信重复出现在排序/聚合里去干扰展示与门控。
        candidates[0].alsoMatched = generic.matchedIds;
      } else {
        // 无厂商可命名：以 generic_block 候选返回，evidence 写明 status + 命中的特征 id（可复核）。
        // confidence ≤ 0.6 < WAF_HIGH_CONFIDENCE(0.8)，故永不触发 autoRetry 的整站 tamper 重跑。
        candidates.push({
          vendor: generic.vendor,
          confidence: generic.confidence,
          evidence: generic.evidence,
          source: 'generic_block',
          hint: generic.hint,
          family: generic.family,
        });
      }
    }
    return candidates;
  }

  /**
   * 是否应触发 WAF 自动 tamper 重跑（P1-D5 门控，纯函数）：
   * ① config.wafEvasion.autoRetry 显式开启（默认 false 保持现状）
   * ② 存在高置信 WAF 候选（confidence >= WAF_HIGH_CONFIDENCE）
   * ③ 用户未显式配置 tamper（enabled 或 plugins 非空即视为用户显式接管，不自动覆盖）。
   * 满足三者才返回 true；否则 false（不自动重跑）。
   * @param {Array<{vendor:string, confidence:number}>} candidates WafIdentifier.identify 结果
   * @param {object} config 扫描配置（含 wafEvasion）
   * @returns {boolean}
   */
  shouldAutoRetry(candidates, config) {
    const we = (config && config.wafEvasion) || {};
    if (!we.autoRetry) return false;
    const tamper = we.tamper || {};
    const userExplicit = !!tamper.enabled || (Array.isArray(tamper.plugins) && tamper.plugins.length > 0);
    if (userExplicit) return false;
    const arr = Array.isArray(candidates) ? candidates : [];
    return arr.some((c) => c && c.confidence >= WAF_HIGH_CONFIDENCE);
  }

  /**
   * [sqlmap 对标] 主动 WAF 探测：被动指纹识别无果时，主动发送 WAF 触发 payload
   * 观察拦截响应以识别 WAF 厂商。仅当 config.activeWafProbe 为 true 且被动识别
   * 返回空结果时由调用方触发。
   *
   * 探测流程：
   *   1) GET /?id=1（良性请求）→ 基线响应
   *   2) GET /?id=1 AND 1=1 UNION SELECT NULL,NULL,NULL（WAF 触发）→ 观察拦截
   *   3) GET /?id=1' OR '1'='1（WAF 触发）→ 观察拦截
   *   4) 比较：良性请求成功但触发请求被拦截（403/406/503）→ WAF 存在
   *   5) 在被拦截响应上复用 wafRules.js 匹配器识别厂商
   *   6) 无厂商匹配但行为差异显著（body 长度缩减 >50%）→ 标记 "unknown WAF"（confidence 0.5 不变，
   *      但额外标注 source:'none'：无任何签名证据；调用侧据此在 blockPolicy 里一票否决发包形态变更）
   *
   * @param {object} target 目标对象（含 baseUrl 或 url）
   * @param {object} httpClient 统一 HttpClient 实例
   * @returns {Promise<{detected:boolean, vendor:string|null, confidence:number}>}
   */
  async activeProbe(target, httpClient) {
    const baseUrl = (target && (target.baseUrl || target.url)) || '';
    if (!baseUrl) return { detected: false, vendor: null, confidence: 0 };

    // 构建 ?id=<value> 的探测 URL
    const buildUrl = (idValue) => {
      try {
        const u = new URL(baseUrl);
        u.searchParams.set('id', idValue);
        return u.toString();
      } catch { return null; }
    };

    const BLOCKED_STATUSES = new Set([403, 406, 503]);
    const isBlocked = (res) => !!res && BLOCKED_STATUSES.has(res.status);

    // 将 axios/undici 响应归一化为 identify() 需要的 { status, headers, body }
    const toResponse = (res) => ({
      status: res?.status,
      headers: res?.headers ?? {},
      body: String(res?.data ?? ''),
    });

    try {
      // 1) 良性请求 → 基线
      const benignUrl = buildUrl('1');
      if (!benignUrl) return { detected: false, vendor: null, confidence: 0 };
      const benignRes = await httpClient.request({ method: 'GET', url: benignUrl });
      // 良性请求本身被拦截 → 无法区分 WAF 与正常行为，不判定
      if (isBlocked(benignRes)) return { detected: false, vendor: null, confidence: 0 };

      // 2) WAF 触发请求 1：UNION SELECT
      const trigger1Url = buildUrl('1 AND 1=1 UNION SELECT NULL,NULL,NULL');
      const trigger1Res = trigger1Url
        ? await httpClient.request({ method: 'GET', url: trigger1Url }).catch(() => null)
        : null;

      // 3) WAF 触发请求 2：引号 OR
      const trigger2Url = buildUrl("1' OR '1'='1");
      const trigger2Res = trigger2Url
        ? await httpClient.request({ method: 'GET', url: trigger2Url }).catch(() => null)
        : null;

      // 4) 比较：良性成功但触发被拦截 → WAF 存在
      const trigger1Blocked = isBlocked(trigger1Res);
      const trigger2Blocked = isBlocked(trigger2Res);

      if (trigger1Blocked || trigger2Blocked) {
        // 5) 在被拦截响应上复用 wafRules.js 匹配器识别厂商
        for (const triggerRes of [trigger1Res, trigger2Res]) {
          if (!triggerRes) continue;
          if (!isBlocked(triggerRes)) continue;
          const candidates = this.identify(toResponse(triggerRes));
          if (candidates.length > 0) {
            const best = candidates[0];
            // source 透传：让调用方能区分「厂商签名命中」与「仅通用拦截页命中」（generic_block）。
            // 注意本分支只在被动识别为空时才跑，此时 identify() 已含通用层→ 不会再把有证据的拦截
            // 降级成无名的 'unknown'。
            return { detected: true, vendor: best.vendor, confidence: best.confidence, source: best.source || 'wafRules' };
          }
        }
        // 6) 被拦截但无厂商匹配 → unknown WAF（有硬证据：触发请求被拦而良性请求没被拦）
        return { detected: true, vendor: null, confidence: 0.6, source: 'behavior' };
      }

      // 行为兜底：无显式拦截但 body 长度缩减 > 50% → 疑似 WAF
      const benignLen = String(benignRes?.data ?? '').length;
      for (const triggerRes of [trigger1Res, trigger2Res]) {
        if (!triggerRes) continue;
        const triggerLen = String(triggerRes.data ?? '').length;
        if (benignLen > 0 && triggerLen < benignLen * 0.5) {
          // 裸 unknown 兜底：只有「正文变短了」这一条间接线索，没有任何拦截状态码/文案证据。
          // 置信度维持 0.5 不变（既有语义，autoRetry 门控本就要求 >= 0.8，0.5 不会触发重跑；
          // 降值无收益反而会让「行为差异」与「无信号」失去可比性）。真正需要防的是另一条路径：
          // 调用侧 `probeResult.vendor || 'unknown'` 会把无厂商结论写成 vendor='unknown'，若那时被
          // 当成可信任命中就会拿 wafRecommend 的 _default 链重跑全站。为此显式标注 source:'none'，
          // 并把否决权固化到 blockPolicy.decideBlockPolicy（vendor==='unknown' → action 只能 'none'）。
          return { detected: true, vendor: null, confidence: 0.5, source: 'none', evidence: 'behavior-only: body length shrunk >50%, no block status' };
        }
      }

      return { detected: false, vendor: null, confidence: 0 };
    } catch {
      return { detected: false, vendor: null, confidence: 0 };
    }
  }
}

export default WafIdentifier;
