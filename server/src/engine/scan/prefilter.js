// =====================================================================
// scan/prefilter.js —— 注入点预过滤家族（"哪些点值得完整检测"）
//
// [大文件拆分 2026-09-20] 从 ScanManager.js 抽出（原 9 个实例方法，~390 行）。
//
// 为什么这一簇可以被安全外移（与 scan/detect.js 那次的差别）：
//   · 5 个方法**完全不引用 this**（_staticSentinel / _normalizeForStatic /
//     _probeBaselineRttMs / _timeProbeValues / _normEcho / _prefilterSimilar）；
//   · 其余几个只互相调用（簇内聚）+ 一个 `_mapPool` 外部依赖 —— 后者改为
//     **参数注入**（mapPoolImpl），不外传 this。
//   · 对比：scan/detect.js 当年评估时引用主函数 37 个变量，属高风险；本簇 0-1。
//
// 这簇的共同职责：在发起昂贵的完整检测之前，用**廉价探针**判断一个注入点是否
// 值得测。全部采用「探到异常才保留」的保守判定 —— 任何探测失败/超时/不可判定
// 都返回"保留"，绝不因探测失败漏检。这条红线在下面每个函数里都要守住。
//
// 依赖方向：本模块只依赖底层（injection/egressOpts/payloads/defaults/logger），
// 不反向依赖 ScanManager，避免循环。
//
// [P0-FIX 2026-09-09 随搬移保留] 预筛/静态跳过/输入校验短路都是「探到异常才保留」的
// 保守判定：它们过去用 `res == null` 表示「探测没拿到结果 → 不跳」。sendInjection 现在
// 把失败降级成带 __netErr 的对象（不再是 null），若继续用 null 判断，两次失败的探测会被
// 看成「两侧同构 → 该点无信号 → 跳过完整检测」——那是**直接新增假阴性**。
// 故本模块统一用 `isUnusableResponse(res)` 判定可用性，**不要**改回 `res == null`。
// =====================================================================
import { buildInjectionRequest, sendInjection, applyPrefixSuffix } from '../injection.js';
import { isUnusableResponse } from '../egressOpts.js';
import { ERROR_SIG } from '../payloads.js';
import { defaults } from '../../config/defaults.js';
import { logger } from '../../core/logger.js';

/**
 * 哨兵值构造：数字 +1001（1→1002）、非数字字符串加 _sst 后缀（abc→abc_sst）。
 *
 * 用途：把一个"看起来正常但必然改变语义"的值注入参数，若响应与基线完全一致，
 * 说明该参数对响应无影响（静态参数）→ 可跳过完整检测。
 * @param {string} orig 原始值
 * @returns {string} 哨兵值
 */
export function staticSentinel(orig) {
  if (/^-?\d+(\.\d+)?$/.test(orig)) {
    const n = Number(orig);
    if (Number.isFinite(n)) return String(n + 1001);
  }
  return `${orig}_sst`;
}

/**
 * 静态判定用正文规范化：仅折叠连续空白并去首尾。
 *
 * 刻意**不做**任何更宽松的归一化（不去标点、不转小写）—— 时间戳/CSRF token
 * 等任何其它差异都必须被视为"动态"，否则会把动态参数误判成静态而漏检。
 * @param {any} body 响应正文
 * @returns {string} 规范化后的正文
 */
export function normalizeForStatic(body) {
  return String(body ?? '')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * 回显剥离：把本次注入值（原样 / URL 编码 / HTML 实体）从正文剔掉后再比对。
 *
 * 用途：部分目标的错误页会原样回显非法输入（如 `Invalid id: 1'`），不剔则
 * 永远得不到"同构"判定。只用于跳过判定的比对侧，不改变检测器看到的原始响应。
 * @param {any} body 响应正文
 * @param {string} value 本次注入的值
 * @returns {string} 剥离后的正文（值短于 2 字符时原样返回，防误剔）
 */
export function normEcho(body, value) {
  let s = String(body ?? '');
  const raw = String(value ?? '');
  if (!s || raw.length < 2) return s;
  const variants = new Set([
    raw,
    encodeURIComponent(raw),
    raw.replace(/'/g, '&#39;'),
    raw.replace(/"/g, '&#34;'),
  ]);
  for (const variant of variants) {
    if (variant.length < 2) continue;
    s = s.split(variant).join('');
  }
  return s;
}

/**
 * 预筛选相似判定：状态码一致 + 长度差在容差内 + 最长公共前缀 ≥ 85% → 视为"同构"。
 *
 * 与 Detector._boundarySimilar 同思路的轻量内联（避免跨模块耦合）。
 * @param {string} baseBody 基线正文
 * @param {number|null} baseStatus 基线状态码
 * @param {string} body 待比对正文
 * @param {number|null} status 待比对状态码
 * @returns {boolean} 是否同构
 */
export function prefilterSimilar(baseBody, baseStatus, body, status) {
  if (status != null && baseStatus != null && status !== baseStatus) return false;
  const la = baseBody.length;
  const lb = body.length;
  if (Math.abs(la - lb) > Math.max(24, Math.max(la, lb) * 0.12)) return false;
  const m = Math.min(la, lb);
  if (m === 0) return la === lb;
  let common = 0;
  while (common < m && baseBody[common] === body[common]) common++;
  return common >= m * 0.85;
}

/**
 * 时间探针按 dbms 选族。
 *
 *   MySQL 族 → AND SLEEP(s)；PostgreSQL → AND pg_sleep(s) IS NULL；
 *   SQL Server → '; WAITFOR DELAY（堆叠）；Oracle → DBMS_PIPE.RECEIVE_MESSAGE；
 *   SQLite（无服务器端 sleep）→ 空数组，仅靠单引号报错探针；
 *   未知库 → MySQL + PG 双族。
 *
 * [CTX-FIX 2026-09-18] 每个方言族补发**数值上下文**变体（不带前导单引号）：
 * 原实现每种方言只有带 `'` 的一条 → 数值型注入点上 `' AND SLEEP(2)` 是语法错误、
 * 秒回无延迟；而「恒 200 + 固定页」这类点又没有单引号内容差异信号可用 →
 * 预筛选判「无迹象」直接剪掉整点（实测 blackbox-lab C2-blindtime 整点漏检）。
 *
 * @param {string|null} dbms 数据库类型
 * @param {number} sleepSec 睡眠秒数
 * @returns {string[]} 探针后缀数组（拼在原始值之后）
 */
export function timeProbeValues(dbms, sleepSec) {
  const s = Number(sleepSec) || 2;
  /** 同一条件的两种闭合上下文：[字符串型, 数值型] */
  const both = (cond) => [`' ${cond}`, ` ${cond}`];
  switch (String(dbms || '').toLowerCase()) {
    case 'mysql': case 'mariadb': case 'tidb':
      return both(`AND SLEEP(${s})-- -`);
    case 'postgresql':
      return both(`AND pg_sleep(${s}) IS NULL-- -`);
    case 'sql server': case 'mssql':
      return [`'; WAITFOR DELAY '0:0:${s}'--`, `; WAITFOR DELAY '0:0:${s}'--`];
    case 'oracle': case 'dm8':
      return both(`AND DBMS_PIPE.RECEIVE_MESSAGE('pf', ${s}) = 'pf'-- -`);
    case 'sqlite':
      return [];
    default:
      // 未知库：MySQL 双上下文 + PG 字符串上下文。不给 PG 数值变体是**有意的**：
      // 预筛选的判定方向是「所有探针都无信号才剪」，每多一条探针就多一份
      // 「剪不断反而白花请求」，而 budget 不足时整个预筛选会自动放弃（保守全保留）
      // —— 多给 PG 数值变体会让多参数目标更容易撞上那条线，把 MySQL 目标本已
      // 到手的剪枝收益一起赔进去。
      return [`' AND SLEEP(${s})-- -`, ` AND SLEEP(${s})-- -`, `' AND pg_sleep(${s}) IS NULL-- -`];
  }
}

/**
 * 基线 RTT 实测（预筛选共享 1 次）：注入原值的单次请求耗时。
 *
 * 动态预算的依据：原固定 120ms 在公网（RTT>120ms）下探测必超时 → 全部保守
 * 保留 → 预筛选空转。改为实测 RTT 后按 clamp(3×RTT+150, 300, 2000) 定预算。
 * @param {object} httpClient HTTP 客户端
 * @param {object} prefilterCtx 预筛选上下文（含 target）
 * @param {object} target 扫描目标
 * @param {object} samplePoint 采样点
 * @returns {Promise<number|null>} 耗时 ms；失败/超时返回 null（调用方跳过预筛）
 */
export async function probeBaselineRttMs(httpClient, prefilterCtx, target, samplePoint) {
  const point = samplePoint || null;
  if (!point) return null;
  try {
    const t0 = Date.now();
    const req = buildInjectionRequest(target, point, point.originalValue || '1');
    const res = await sendInjection(httpClient, prefilterCtx, req, { timeoutMs: 2000, retry: 0 });
    if (res == null || isUnusableResponse(res)) return null;
    const elapsed = Date.now() - t0;
    return Number.isFinite(elapsed) && elapsed >= 0 ? elapsed : null;
  } catch {
    return null;
  }
}

/**
 * 静态参数跳过：同值去重（零请求）+ 哨兵探测（每点 1 请求，基线跨点共享）。
 *
 * 四项全过才判"静态参数（改值不影响响应）"→ 跳过完整检测：
 *   ① 状态码一致；② 正文长度一致（字节级，不做容差）；③ 规范化正文一致；
 *   ④ 哨兵值不得回显（回显 = 参数参与响应构造 → 动态参数）。
 * @param {object} deps 依赖：{ mapPool }
 * @param {object} ctxBase 扫描上下文
 * @param {object} target 扫描目标
 * @param {object[]} points 注入点
 * @returns {Promise<object[]>} 保留的点
 */
export async function skipStaticPoints(deps, ctxBase, target, points) {
  if (target.mode === 'direct' || !points || points.length === 0) return points || [];
  const httpClient = ctxBase.httpClient;
  const ctx = { ...ctxBase, target };
  const skip = [];
  // a) 同值去重（零请求）：原始值完全相同的参数只测第一个
  const seenValues = new Set();
  const toProbe = [];
  for (const p of points) {
    if (p && p.precisionMarked) {
      toProbe.push(p); // 用户显式指定的点：不做同值去重，也不做哨兵跳过
      continue;
    }
    const val = p.originalValue == null ? '' : String(p.originalValue);
    if (seenValues.has(val)) {
      skip.push(p);
      continue;
    }
    seenValues.add(val);
    toProbe.push(p);
  }
  if (toProbe.length <= 1) return points.filter((p) => !skip.includes(p));
  // b) 哨兵探测：每点 1 请求（基线跨点共享）；点级并发限 4，与预筛选对齐
  const baselineCache = new Map(); // `${method} ${url}` -> Promise<响应|null>
  const getBaseline = (point) => {
    const orig = point.originalValue == null ? '' : String(point.originalValue);
    const req = buildInjectionRequest(target, point, orig);
    const key = `${req.method || 'GET'} ${req.url}`;
    if (!baselineCache.has(key)) {
      baselineCache.set(key, sendInjection(httpClient, ctx, req, { retry: 0 }).catch(() => null));
    }
    return baselineCache.get(key);
  };
  await deps.mapPool(
    toProbe,
    async (point) => {
      try {
        if (point.precisionMarked) return; // 精确标记点永不跳过
        const orig = point.originalValue == null ? '' : String(point.originalValue);
        const sentinel = staticSentinel(orig);
        const sentReq = buildInjectionRequest(target, point, sentinel);
        // 哨兵探测用零重试（失败即保守保留，不放大探测成本）
        const [baseRes, sentRes] = await Promise.all([
          getBaseline(point),
          sendInjection(httpClient, ctx, sentReq, { retry: 0 }),
        ]);
        if (!baseRes || !sentRes || isUnusableResponse(baseRes) || isUnusableResponse(sentRes)) return; // 基线/哨兵任一失败 → 无法判定 → 保守保留
        // ① 状态码必须一致
        if ((baseRes.status ?? null) !== (sentRes.status ?? null)) return;
        const baseBody = String(baseRes.data ?? '');
        const sentBody = String(sentRes.data ?? '');
        // ② 正文长度必须一致（字节级，不做容差——判定要保守）
        if (baseBody.length !== sentBody.length) return;
        // ③ 规范化正文必须完全一致（仅折叠空白，动态内容敏感）
        if (normalizeForStatic(baseBody) !== normalizeForStatic(sentBody)) return;
        // ④ 哨兵值不得回显在响应中（回显 = 参数参与响应构造 → 动态参数）
        const injectedSentinel = applyPrefixSuffix(target, point, sentinel);
        if (sentBody.includes(injectedSentinel)) return;
        // 四项全过 → 静态参数（改值不影响响应），跳过完整检测
        skip.push(point);
      } catch {
        /* 构造/发送异常 → 保守保留 */
      }
    },
    4
  );
  return points.filter((p) => !skip.includes(p));
}

/**
 * 参数预筛选：对每个注入点发 3 个廉价探测（基线 + 单引号报错 + 时间向量，点内并行），
 * 返回"需完整检测"的点；明显无注入迹象的点被过滤。
 *
 * 保守策略（宁可多测不漏检）：
 *   · 任一探测请求失败 / 在预算时间内未返回（网络/超时/慢目标）→ 无法判定 → 保守保留；
 *   · 单引号探测响应明显偏离基线（状态码/长度/前缀变化）→ 可疑 → 保留；
 *   · 时间向量探测耗时明显高于绝对下限 → 触发延迟 → 保留；
 *   · 仅当两探皆无信号才判「无注入迹象」→ 跳过完整检测。
 *
 * 预筛选不修改注入点对象、不改变报告 point 列表，仅影响「哪些点进入完整检测循环」。
 * @param {object} deps 依赖：{ mapPool }
 * @param {object} ctxBase 扫描上下文
 * @param {object} target 扫描目标
 * @param {object[]} points 注入点
 * @returns {Promise<object[]>} 保留的点
 */
export async function prefilterPoints(deps, ctxBase, target, points) {
  const cfg = ctxBase.config || {};
  if (target.mode === 'direct' || !points || points.length === 0) return points || [];
  const httpClient = ctxBase.httpClient;
  // [P0 2026-09-09] knownPoint 直通点不参与预筛选（手工确认的可注入点不需要
  // 「有没有迹象」判定；探针反而可能因闭合形态未给全而误判无信号），
  // 但必须原样并入返回集（调用方以返回集作为「进入完整检测」的点集合）
  const knownPoints = points.filter((p) => p.knownPoint);
  points = points.filter((p) => !p.knownPoint);
  if (points.length === 0) return knownPoints;
  const skipIds = new Set();
  const prefilterCtx = { ...ctxBase, target };
  const sleepSec = cfg.timeBlindSleepSec ?? defaults.timeBlindSleepSec ?? 2;
  // [P1-FIX 2026-09-05] 动态预算：原固定 120ms 在公网（RTT>120ms）下探测必超时 →
  // 全部保守保留 → 预筛选空转。改为：目标基线 RTT 实测（共享 1 次）→
  // 预算 = clamp(3×RTT+150, 300, 2000)。基线测不通（不可达）→ 直接跳过预筛
  // （保守保留全部，与旧超时行为一致但零白费请求）。手动 cfg.prefilterBudgetMs
  // 仍最高优先（不测基线，保持确定性）。
  let budgetMs = Number.isFinite(cfg.prefilterBudgetMs) && cfg.prefilterBudgetMs > 0
    ? cfg.prefilterBudgetMs
    : null;
  if (budgetMs == null) {
    const rtt = await probeBaselineRttMs(httpClient, prefilterCtx, target, points[0]);
    if (rtt == null) {
      logger.info('预筛选基线测量失败（目标不可达/超时），跳过预筛选，保守保留全部注入点');
      return [...knownPoints, ...points];
    }
    budgetMs = Math.min(2000, Math.max(300, Math.round(rtt * 3 + 150)));
  }
  // 时间向量信号下限：绝对秒级延迟余量（≈0.5-0.9s），宽于检测阈值，保守兜住真实 sleep
  const timeFloorMs = Math.max(800, (cfg.timeThresholdMs ?? defaults.timeThresholdMs) * 0.6);
  // [P1-FIX 2026-09-05] 时间探针按 dbms 选族（原硬编码 MySQL SLEEP：非 MySQL 目标
  // 必然语法错误无延时信号 → 预筛漏剪时间型注入点）。未知库发 MySQL+PG 双族覆盖最常见两系。
  const dbms = cfg.dbms || target?.config?.dbms || target.dbms || ctxBase.dbms || null;
  const probes = timeProbeValues(dbms, sleepSec);
  // [MERGED: perf] 请求治理：旧实现 Promise.all(points.map(...)) 对全部点 × 3 探测并发（无上限）；
  // 且探测经令牌桶排队，预算内放不完时 Promise.race 返回 null → 保守全保留，
  // 但已排队的探测请求仍会发出（结果被丢弃）→ 白费 3×N 请求。本版：
  //   1) 仅当全部探测（N×(2+时间探针数)）可在「初始满桶突发 + 预算窗口」内放行时才预筛
  //      （限速过低直接跳过，零白费请求）；
  //   2) 点级并发经 mapPool 限到 4，避免无上限并发放大突发。
  const ratePerSec = Number.isFinite(cfg.ratePerSec) && cfg.ratePerSec > 0 ? cfg.ratePerSec : defaults.ratePerSec;
  const totalProbes = points.length * (2 + probes.length);
  const servableInBudget = ratePerSec + (budgetMs / 1000) * ratePerSec;
  if (totalProbes > servableInBudget) {
    logger.info(
      `预筛选预算不足（${points.length} 点 × 3 探测 = ${totalProbes} 请求 > 限速 ${ratePerSec}/s × ~${(budgetMs / 1000).toFixed(2)}s 可放行 ${Math.floor(servableInBudget)}），跳过预筛选避免白费请求`
    );
    return [...knownPoints, ...points];
  }
  // 点级并发限 4（12 个并发探测）：与调度并发对齐，避免 points×3 无上限并发
  await deps.mapPool(
    points,
    async (point) => {
      const orig = point.originalValue || '1';
      const probe = (value) => {
        const req = buildInjectionRequest(target, point, value);
        const t0 = Date.now();
        // 预筛选探测用短超时 + 零重试：慢/不可达目标（DNS 慢、页面慢）快速放弃并保守保留。
        // 短超时会取消底层请求（含 DNS 解析），不残留后台请求占住事件循环（测试/慢目标友好）。
        return sendInjection(httpClient, prefilterCtx, req, { timeoutMs: budgetMs, retry: 0 }).then(
          (res) => ({ res, elapsed: Date.now() - t0 })
        );
      };
      try {
        // 基线 + 单引号报错 + 时间向量（按 dbms 选族）并行，整体受预算竞速约束：墙钟≈单次 RTT
        const trio = await Promise.race([
          Promise.all([probe(orig), probe(`${orig}'`), ...probes.map((v) => probe(`${orig}${v}`))]),
          new Promise((resolve) => setTimeout(() => resolve(null), budgetMs)),
        ]);
        if (!trio) return; // 预算超时：无法判定 → 保守保留
        const [base, quote, ...timed] = trio;
        // 保守：任一探测失败（网络错误/超时）→ 保留做完整检测，绝不因探测失败漏检
        if (!base || base.res == null || isUnusableResponse(base.res) || !quote || quote.res == null || isUnusableResponse(quote.res)) return;
        if (timed.some((t) => !t || t.res == null || isUnusableResponse(t.res))) return;
        // 探测① 单引号报错：闭合破坏 → 报错/空页/500 → 响应明显偏离基线 → 可疑保留
        const baseBody = String(base.res?.data ?? '');
        const baseStatus = base.res?.status ?? null;
        const quoteBody = String(quote.res?.data ?? '');
        const quoteStatus = quote.res?.status ?? null;
        if (!prefilterSimilar(baseBody, baseStatus, quoteBody, quoteStatus)) {
          // [OPT-FIX 2026-09-08] 输入校验甄别（fp_strict 类 205 请求削减）：单引号探针报错后，
          // 追加 1 个「良性非法值」探针（zz9qx0，无任何 SQL 特征）：
          //   · 良性探针响应与单引号探针同构（状态码+正文指纹一致）→ 是输入白名单/校验报错
          //     而非 SQL 报错 → 该点注入面无效 → 安全跳过（实测 205 请求 → ~7 请求）；
          //   · 任一差异 → 真实 SQL 报错信号 → 保守保留完整检测（不漏检）；
          //   · 良性探针失败/超时 → 保守保留。
          // [OPT-FIX 2026-09-08#2] 甄别仅适用于「报错状态码」响应（status>=400）：无报错状态
          // 的空结果页（200 "No results found"）在真注入点（布尔差异型，如 sqli-labs L04）上
          // 与良性非法值天然同构——若不限定状态码会把布尔差异型注入点误跳过（实测漏检）。
          // 200 空结果页不受影响（走正常信号判定保留完整检测），仅牺牲 200 自定义错误页
          // 目标的削减收益（保守换取零漏检）。
          if (quoteStatus != null && quoteStatus >= 400) {
            try {
              const benign = await probe(`${orig}zz9qx0`);
              if (benign && benign.res != null) {
                const bBody = String(benign.res?.data ?? '');
                const bStatus = benign.res?.status ?? null;
                if (prefilterSimilar(quoteBody, quoteStatus, bBody, bStatus)) {
                  skipIds.add(point.id);
                  return;
                }
              }
            } catch { /* 甄别失败 → 保守保留 */ }
          }
          return;
        }
        // 探测② 时间向量：任一族探针耗时明显高于绝对下限 → 触发延迟 → 保留
        if (timed.some((t) => t.elapsed >= timeFloorMs)) return;
        // 两探皆无信号 → 判为无注入迹象，跳过完整检测
        skipIds.add(point.id);
      } catch {
        // 探测异常（如 URL 构造失败）→ 保守保留
      }
    },
    4 // [MERGED: perf] 点级并发上限
  );
  return [...knownPoints, ...points.filter((p) => !skipIds.has(p.id))];
}

/**
 * 输入校验型目标的「可证安全跳过」判定（单参数目标专用）。
 *
 * 背景（实测）：作战中最费时间的往往不是「有注入」，而是「参数在进 SQL 之前就被
 * 白名单拦死」—— ?id=1' 与 ?id=1zz9qx0 返回同一张 400 页。多参数目标有
 * prefilterPoints 兜住，但单参数目标被刻意排除在预筛之外（怕在唯一的点上误剪导致
 * 漏检），于是这类目标仍要打满 200+ 请求（e2e fp_strict 实测 211）：既慢，又在
 * WAF/风控上刷出一堆无效攻击特征——真实项目里这就足够让出口 IP 被临时封禁。
 *
 * 判定比「报错页相同」强一档，能排除最危险的反例「目标真有洞但异常被统一吞掉」：
 *   ① 基线为正常页（<400），单引号探针偏离基线且为 >=400；
 *   ② 良性非法值（zz9qx0，无任何 SQL 特征）与单引号响应同构 → 疑似输入校验而非 SQL 报错；
 *   ③ 恒真串探针必须同样被拒（字符串上下文 `' OR '1'='1` 与数字上下文 ` OR 1=1`）：
 *      SQL 若真被执行，恒真条件会返回正常页（差异即信号）→ 说明「同构」只是异常被吞 → 保留；
 *   ④ 四路响应体任一含 SQL 报错签名（ERROR_SIG）→ 保留。
 *
 * 请求成本：每点 5 个（基线 → 单引号 → 剩下三路并行，墙钟≈2-3 RTT；串行前两步是为了
 * 在基线/单引号不满足形状时立即放弃，不多花那 3 个），换掉 200+ 请求的完整检测预算。
 * 保守红线：任一探测失败/超时/判定不成立 → 保留完整检测，本函数绝不「判不出就跳过」。
 *
 * @param {object} deps 依赖：{ mapPool }
 * @param {object} ctxBase 扫描上下文
 * @param {object} target 扫描目标
 * @param {object[]} points 注入点
 * @returns {Promise<{ candidate: object[], skipped: object[] }>} 保留点与跳过原因
 */
export async function validationGuardedSkipPoints(deps, ctxBase, target, points) {
  const cfg = ctxBase.config || {};
  if (target.mode === 'direct' || !Array.isArray(points) || points.length === 0) {
    return { candidate: points || [], skipped: [] };
  }
  const httpClient = ctxBase.httpClient;
  const prefilterCtx = { ...ctxBase, target };
  // 单探针超时：与预筛选同量级（不可达目标快速放弃 → 保守保留），可被 prefilterBudgetMs 覆盖
  const budgetMs =
    Number.isFinite(cfg.prefilterBudgetMs) && cfg.prefilterBudgetMs > 0 ? cfg.prefilterBudgetMs : 1500;
  const skip = new Map();

  await deps.mapPool(points, async (point) => {
    const orig = point.originalValue || '1';
    // 每路响应只剔「自己那次注入的值」（部分目标错误页会原样回显非法输入，不剔则永远不同构）。
    // 不剔 orig 本身：短数字（如 '1'）在正文里无处不在，剔了会把一切变得相同（假跳过 → 漏检）。
    const st = (r) => r?.res?.status ?? null;
    const rawBody = (r) => String(r?.res?.data ?? '');
    const norm = (r, value) => normEcho(rawBody(r), value);
    const probe = (value) => {
      const req = buildInjectionRequest(target, point, value);
      return sendInjection(httpClient, prefilterCtx, req, { timeoutMs: budgetMs, retry: 0 })
        .then((res) => ({ res, value }))
        .catch(() => null);
    };
    try {
      const base = await probe(orig);
      if (!base || base.res == null || isUnusableResponse(base.res)) return;
      const baseStatus = st(base);
      // ① 基线必须是正常页（基线本身就 4xx/5xx 的目标形态不明，不判）
      if (baseStatus == null || baseStatus >= 400) return;
      const quote = await probe(`${orig}'`);
      if (!quote || quote.res == null || isUnusableResponse(quote.res)) return;
      const quoteStatus = st(quote);
      // 单引号探针必须是报错状态码（200 自定义错误页与真注入天然同构，不可判）
      if (quoteStatus == null || quoteStatus < 400) return;
      const quoteBody = norm(quote, `${orig}'`);
      // ② 单引号必须偏离基线（与基线同构说明连报错都没有，交给常规流程）
      if (prefilterSimilar(rawBody(base), baseStatus, quoteBody, quoteStatus)) return;
      const rest = await Promise.all([
        probe(`${orig}zz9qx0`),
        probe(`${orig}' OR '1'='1`),
        probe(`${orig} OR 1=1`),
      ]);
      // 任一探测失败（网络错误/超时/返回空）→ 无法判定 → 保守保留
      if (rest.some((r) => !r || r.res == null || isUnusableResponse(r.res))) return;
      // ④ 任一回包含 SQL 报错签名 → 明确保留（error 技术有活可干）
      if (ERROR_SIG.test(rawBody(quote))) return;
      for (const r of rest) if (ERROR_SIG.test(rawBody(r))) return;
      // ②+③ 良性非法值与两个恒真串探针必须与单引号响应同构且均为 >=400：
      // SQL 真被执行时恒真条件会返回正常页，任一路差异 → 不跳过（防「异常被吞」型漏检）。
      for (const r of rest) {
        const rs = st(r);
        if (rs == null || rs < 400) return;
        if (!r) continue;
        if (!prefilterSimilar(quoteBody, quoteStatus, norm(r, r.value), rs)) return;
      }
      skip.set(point.id, {
        pointId: point.id,
        reason: 'input_validation',
        note: `基线 ${baseStatus}，单引号/良性非法值/恒真串四路探针均同构于 ${quoteStatus} 且无 SQL 报错签名 → 判定为输入校验拦截而非 SQL 报错`,
      });
    } catch {
      // 探测异常 → 保守保留
    }
  }, 4);

  if (skip.size === 0) return { candidate: points, skipped: [] };
  return { candidate: points.filter((p) => !skip.has(p.id)), skipped: [...skip.values()] };
}
