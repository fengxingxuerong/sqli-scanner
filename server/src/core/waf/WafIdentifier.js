import { WAF_RULES } from './wafRules.js';
import { detectGenericBlock } from './blockSignatures.js';
// [2026-09-29 收敛] 响应头读取口径全仓唯一：core/getHeader.js。本文件原私有版最弱
// （无 .get 方法支持、数组值原样透出），同一响应可能与 scanValidityGuard 结论不一致。
import { getHeader } from '../getHeader.js';

// 高置信 WAF 阈值：置信度 >= 此值才允许自动 tamper 重跑（防低置信/单特征误触发导致请求爆炸）。
export const WAF_HIGH_CONFIDENCE = 0.8;

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
    const resp = /** @type {any} */ (response || {});
    /** @type {any[]} 候选结构随厂商/通用/兜底三类分支演进，逐字段声明会不断失配 */
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
   * [sqlmap 对标] 主动 WAF 探测：被动指纹识别无果时，主动发送多向量探测请求
   * 观察拦截行为以识别 WAF。仅当 config.activeWafProbe 为 true 且被动识别
   * 返回空结果时由调用方触发。
   *
   * 探测流程（[D44 2026-10-11] 升级为 wafw00f 式多向量差分）：
   *   1) GET /?id=1（良性请求）→ 基线响应
   *   2) 四个探测向量（多向量是 wafw00f 的核心经验：只发 SQLi 只能回答「拦不拦 SQLi」，
   *      分不清「SQLi 专项规则」与「全站拦截」，也少一路证据）：
   *        sqli-union / sqli-quote（既有）+ xss / lfi（新增，对标 wafw00f 的 xssAttack/lfiAttack）
   *   3) 每向量三分类：被拦（403/406/429/503）/ 连接级阻断（请求直接网络失败——
   *      旧实现 .catch(()=>null) 把断连型 WAF 整个吞掉，这是真缺口）/ 正常响应
   *   4) 差分信号：① 状态码漂移 ② Server 头漂移（benign vs 被拦响应，wafw00f genericdetect
   *      同款判据）③ 正文长度缩减 >50%（软信号）
   *   5) 在被拦响应上复用 wafRules.js + 通用拦截页签名识别厂商
   *   6) 无厂商匹配但有硬证据（向量被拦/连接级阻断）→ "unknown WAF"（source:'behavior'，
   *      confidence 0.6；调用侧 blockPolicy 据此一票否决发包形态变更）
   *
   * @param {object} target 目标对象（含 baseUrl 或 url）
   * @param {object} httpClient 统一 HttpClient 实例
   * @returns {Promise<{detected:boolean, vendor:string|null, confidence:number, source?:string, evidence?:string, vectorsBlocked?:string[], connectionBlocked?:boolean}>}
   *   source 取值：wafRules（厂商签名）/ generic_block（通用拦截页）/ behavior（仅行为差分）/
   *   none（无任何证据）—— 调用方 blockPolicy 依此决定是否允许变更发包形态。
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

    // [D44] 429 补进拦截码集（与 scanValidityGuard.BLOCK_STATUSES 同口径——限频也是中间设备在拦）
    const BLOCKED_STATUSES = new Set([403, 406, 429, 503]);
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
      const benignServer = getHeader(benignRes?.headers, 'server');
      const benignLen = String(benignRes?.data ?? '').length;

      // 2)+3) 多向量探测与三分类（网络失败不再吞成 null——那是连接级阻断的证据）
      const vectors = [
        { id: 'sqli-union', value: '1 AND 1=1 UNION SELECT NULL,NULL,NULL' },
        { id: 'sqli-quote', value: "1' OR '1'='1" },
        { id: 'xss', value: '<script>alert(1)</script>' },
        { id: 'lfi', value: '../../../../etc/passwd' },
      ];
      /** @type {string[]} 被状态码拦下的向量 */
      const vectorsBlocked = [];
      /** @type {string[]} 连接级阻断的向量（请求直接网络失败） */
      const connectionBlocked = [];
      /** @type {any[]} 被拦响应（供厂商识别复用） */
      const blockedResponses = [];
      /** @type {string[]} Server 头漂移证据 */
      const serverShifts = [];
      let shrunkenVector = false;

      for (const vec of vectors) {
        const probeUrl = buildUrl(vec.value);
        if (!probeUrl) continue;
        let res = null;
        try {
          res = await httpClient.request({ method: 'GET', url: probeUrl });
        } catch (err) {
          // [D44] 请求级网络失败且基线正常 → 疑似连接级阻断（wafw00f genericdetect 判据①：
          // "Blocking is being done at connection/packet level"）。**先重试一次再分类**：
          // 偶发抖动不该成为 WAF 证据（本仓红线：宁可少一档置信，不做不实指控）。
          try {
            res = await httpClient.request({ method: 'GET', url: probeUrl });
          } catch {
            connectionBlocked.push(vec.id);
          }
          continue;
        }
        if (isBlocked(res)) {
          vectorsBlocked.push(vec.id);
          blockedResponses.push(res);
          // [D44] Server 头差分（wafw00f genericdetect 判据②：拦截面可能换出口/设备，头会变）
          const srv = getHeader(res?.headers, 'server');
          if (benignServer && srv && String(srv) !== String(benignServer)) {
            serverShifts.push(`${String(benignServer)}→${String(srv)}（${vec.id}）`);
          }
          continue;
        }
        // 行为兜底：无显式拦截但 body 长度缩减 > 50% → 软信号
        const len = String(res?.data ?? '').length;
        if (benignLen > 0 && len < benignLen * 0.5) shrunkenVector = true;
      }

      const signals = [];
      if (vectorsBlocked.length) signals.push(`status-shift vectors: ${vectorsBlocked.join(',')}`);
      if (connectionBlocked.length) signals.push(`connection-level: ${connectionBlocked.join(',')}`);
      if (serverShifts.length) signals.push(`server-header shift: ${serverShifts.join(' | ')}`);

      // 5) 在被拦响应上复用 wafRules.js 匹配器识别厂商（保留既有语义：identify() 已含通用层）
      for (const blockedRes of blockedResponses) {
        const candidates = this.identify(toResponse(blockedRes));
        if (candidates.length > 0) {
          const best = candidates[0];
          return {
            detected: true,
            vendor: best.vendor,
            confidence: best.confidence,
            source: best.source || 'wafRules',
            evidence: signals.join('; ') || 'active probe',
            vectorsBlocked,
            connectionBlocked: connectionBlocked.length > 0,
          };
        }
      }

      // 6) 被拦/连接级阻断但无厂商匹配 → unknown WAF（有硬证据）
      if (vectorsBlocked.length > 0 || connectionBlocked.length > 0) {
        return {
          detected: true,
          vendor: null,
          confidence: 0.6,
          source: 'behavior',
          evidence: signals.join('; ') || 'behavior-only: probes blocked without vendor signature',
          vectorsBlocked,
          connectionBlocked: connectionBlocked.length > 0,
        };
      }

      // 行为兜底：无显式拦截但 body 长度缩减 > 50% → 疑似 WAF
      if (shrunkenVector) {
        // 裸 unknown 兜底：只有「正文变短了」这一条间接线索，没有任何拦截状态码/文案证据。
        // 置信度维持 0.5 不变（既有语义，autoRetry 门控本就要求 >= 0.8，0.5 不会触发重跑；
        // 降值无收益反而会让「行为差异」与「无信号」失去可比性）。真正需要防的是另一条路径：
        // 调用侧 `probeResult.vendor || 'unknown'` 会把无厂商结论写成 vendor='unknown'，若那时被
        // 当成可信任命中就会拿 wafRecommend 的 _default 链重跑全站。为此显式标注 source:'none'，
        // 并把否决权固化到 blockPolicy.decideBlockPolicy（vendor==='unknown' → action 只能 'none'）。
        return {
          detected: true, vendor: null, confidence: 0.5, source: 'none',
          evidence: 'behavior-only: body length shrunk >50%, no block status',
          vectorsBlocked, connectionBlocked: false,
        };
      }

      return { detected: false, vendor: null, confidence: 0, vectorsBlocked, connectionBlocked: false };
    } catch {
      return { detected: false, vendor: null, confidence: 0 };
    }
  }
}

export default WafIdentifier;
