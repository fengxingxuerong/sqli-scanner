import { nanoid } from 'nanoid';
import { TargetParser } from './TargetParser.js';
import { UnionDetector } from './detectors/UnionDetector.js';
import { ErrorDetector } from './detectors/ErrorDetector.js';
import { BooleanBlindDetector } from './detectors/BooleanBlindDetector.js';
import { TimeBlindDetector } from './detectors/TimeBlindDetector.js';
import { StackedDetector } from './detectors/StackedDetector.js';
import { OobDetector } from './detectors/OobDetector.js';
import { SecondOrderDetector } from './detectors/SecondOrderDetector.js';
import { NoSqlInjectionDetector } from './detectors/NoSqlInjectionDetector.js';
import { InlineQueryDetector } from './detectors/InlineQueryDetector.js';
import { DBFingerprinter } from './DBFingerprinter.js';
import { Extractor } from './Extractor.js';
import { Exploiter } from './Exploiter.js';
import { ColumnTypeEnumerator } from './ColumnTypeEnumerator.js';
import { WafIdentifier } from '../core/waf/WafIdentifier.js';
import { recommend } from '../core/waf/wafRecommend.js';
import { ReportGenerator } from '../services/ReportGenerator.js';
import { createTarget, createReport } from './models.js';
// [P0-FIX 2026-09-09] 生产护栏：扫描级高危池策略通过 AsyncLocalStorage 下发给 selectPayloads
import { runWithDestructivePolicy } from './payloadRegistry.js';
import * as eventBus from '../core/eventBus.js';
import { httpClient } from '../core/httpClient.js';
import { logger } from '../core/logger.js';
// [P0-SEC 2026-09-08] 扫描级 scope 登记：放在 ScanManager 而不是只放在 REST 路由里——
// CLI（server/bin/cli.js）与测试/复用型调用不进路由，只放路由会造成「Web 有范围约束、
// CLI 没有」的双标（而 CLI 才是渗透现场的主入口）。
import { parseScope, registerScanScope } from '../core/scopeGuard.js';
// [D32 实战 P0-1] 自定义请求变换（签名/加密参数）扩展点；回收挂在 lifecycle._disposeScan
import { ensureScanTransform } from '../core/requestTransform.js';
// [D36 实战 P0-2] Bearer/Token 自动续期（回收同样挂在 lifecycle._disposeScan）
import { normalizeRefreshConfig, registerScanRefresh } from '../core/bearerKeeper.js';
import { runScanLoop } from './scanRunner.js';
import { extractAll, extractByScope } from './extractScope.js';
// [大文件拆分 2026-09-20] 注入点预过滤家族（~390 行、9 个方法）外移至 scan/prefilter.js。
// 该簇内部耦合极低（6 个方法完全不引用 this），唯一的实例依赖 _mapPool 改为
// **依赖注入**（下方 this._prefilterDeps），不外传 this。类内保留同名薄委托，
// 故 discover.js 与既有测试的调用点零影响。
import {
  staticSentinel,
  normalizeForStatic,
  normEcho,
  prefilterSimilar,
  timeProbeValues,
  probeBaselineRttMs,
  skipStaticPoints,
  prefilterPoints,
  validationGuardedSkipPoints,
} from './scan/prefilter.js';

// [P2] 纯函数工具集已拆分到 scanHelpers.js，此处 re-export 保持向后兼容
export { urlHash, SYS_DBS, publicTarget, publicReport } from './scanHelpers.js';
import { mapPool, mergeExtracted, mergeExtractedForResume, hasData, publicTarget } from './scanHelpers.js';

// 扫描状态机的终态集合（stop/pause 与路由层共用一份，不要在两处各列一遍数组）
export const TERMINAL_STATUSES = ['completed', 'stopped', 'error'];

// [五期拆分 2026-10-01] 类体只剩构造器、start/stop/pause/resume、报告面（status/getReport/
// exportReport）、_run 与预过滤/提取薄委托；客户端工厂（scanClient）、指纹缓存（fingerprint）、
// 暂停与回收（lifecycle）、技术位选择（techniqueSelect）、补充趟（supplemental）、能力抑制
// 汇总（capabilityConstraints）物理搬移到 ./scan/*（函数体逐行原样，由 ScanManager.prototype
// 挂载，this 语义不变）—— scanRunner/extractScope/discover 经实例成员的调用面与 30 个测试
// 文件的导入面完全不变。
import {
  _wrapWithSignal, _waitWhilePaused, _retire, _disposeScan, _evictIfOverLimit,
} from './scan/lifecycle.js';
import { getConnector, _maybeClose, getScanClient } from './scan/scanClient.js';
import { _fingerprintCached } from './scan/fingerprint.js';
import { _selectedTechs, activeDetectors } from './scan/techniqueSelect.js';
import { _runSecondOrder, _runNoSql } from './scan/supplementalRuns.js';
import { collectCapabilityConstraints } from './scan/capabilityConstraints.js';
export { collectCapabilityConstraints };

/** 上下文回收窗口（毫秒）：非法值/未设置一律回落 30s，不设 0（0=立即回收会让报告永远读不到） */
function _envRetireTtl() {
  const n = Number(process.env.SCAN_RETIRE_TTL_MS);
  return Number.isFinite(n) && n >= 1000 ? Math.round(n) : 30000;
}

// 扫描管理器（门面模式）：对外暴露 start/stop/getReport/exportReport，
// 内部串起「发现→指纹→四检测器→提取→构造报告」，全程经 EventBus 推送进度。
export class ScanManager {
  /**
   * @param {object} [opts]
   * @param {any} [opts.wafIdentifier] 测试注入：WAF 指纹识别器
   * @param {any} [opts.wafRecommend] 测试注入：tamper 推荐器
   * @param {number} [opts.retireTtlMs] 扫描上下文回收 TTL（默认 30s）
   * @param {number} [opts.maxScans] scans Map 上限（默认 100）
   */
  constructor({ wafIdentifier, wafRecommend, retireTtlMs, maxScans } = {}) {
    this.httpClient = httpClient; // 统一 HttpClient（便于测试时注入 mock）
    this.parser = new TargetParser(this.httpClient);
    // 扫描上下文回收（P0-R1）：completed/stopped/error 后置 retiredAt，TTL 到期清 scans 条目
    // [2026-09-28 接口靶场] 可经 SCAN_RETIRE_TTL_MS 配置：此前写死 30s，
    //   意味着"扫完半小时再回来取报告"在接口层必然失败（台账回补上之后至少还能读，
    //   但内存里那份的可见窗口完全不能调，长会议/夜班场景没法按现场节奏放宽）。
    this.retireTtlMs = retireTtlMs ?? _envRetireTtl();
    this.maxScans = maxScans ?? 100; // scans Map 上限，超限淘汰最旧扫描
    this._scanClients = new Map(); // scanId -> 扫描作用域 HttpClient 视图（按 scanId 独立限速桶）
    // 检测器注册表：新增技术只加一个类并在此处登记（OobDetector 末位，作为盲注/无回显兜底）
    this.detectors = [
      new UnionDetector(),
      new ErrorDetector(),
      new BooleanBlindDetector(),
      new TimeBlindDetector(),
      new StackedDetector(),
      new OobDetector(),
    ];
    // 二阶注入检测器：独立实例，不进 this.detectors 数组（不参与一阶 per-point 循环，
    // 由 _runSecondOrder 在聚合之后作为补充趟调用，与一阶流水线正交）。
    this.secondOrderDetector = new SecondOrderDetector();
    // 非 SQL 注入检测器（NoSQL/GraphQL/SSTI）：同样独立实例，不进一阶循环，由 _runNoSql 补充趟调用（opt-in）。
    this.noSqlDetector = new NoSqlInjectionDetector();
    // 内联查询检测器（对标 sqlmap Q）：作为经典 SQLi 技术注册进一阶主调度（technique='inline'），
    // 仅当用户显式勾选 'inline' 时运行（opt-in），默认 techniques 不含它，避免对无回显点目标产生噪音。
    this.inlineDetector = new InlineQueryDetector();
    this.detectors.push(this.inlineDetector);
    this.fp = new DBFingerprinter();
    // WAF 指纹识别 + 推荐（可注入桩，默认使用真实实现；识别复用指纹基线，零额外发包）
    this.wafIdentifier = wafIdentifier || new WafIdentifier();
    this.wafRecommend = wafRecommend || recommend;
    this.extractor = new Extractor();
    this.exploiter = new Exploiter(this.extractor); // 利用能力（含堆叠深度提取 fallback）
    this.colTypeEnum = new ColumnTypeEnumerator();
    this.extractor.setColumnTypeEnumerator(this.colTypeEnum);
    this._colTypeCache = new Map(); // db.table -> 列类型数组，避免重复枚举相同表
    this.reportGen = new ReportGenerator();
    // scanId -> { target, report, status, cancelled }
    this.scans = new Map();
  }

  /**
   * 启动扫描（异步执行，立即返回 scanId）
   * @param {object} input 目标输入
   * @returns {Promise<string>} scanId
   */
  async start(input) {
    const target = createTarget(input);
    const scanId = nanoid(12);
    const report = createReport(scanId, target);
    // [P0-FIX 2026-09-09] 把「本次被抑制的能力」写进报告：抑制本身是对的，**不可见才是问题**。
    // 否则使用者只能靠猜「risk=3 到底投了没有」，而交付文档里一句「已按最高风险等级测试」
    // 就是错的——这类不实陈述在复盘里是要命的。
    try {
      report.summary = report.summary || {};
      report.summary.constraints = collectCapabilityConstraints(target.config, target);
    } catch { /* 约束标注失败不影响扫描 */ }
    // 授权范围登记（未配置 scope 时为 no-op，零行为变化）：HttpClient 在每一跳重定向前取用。
    try {
      registerScanScope(scanId, parseScope(target.config && target.config.scope));
    } catch { /* 登记失败不阻断扫描（入口侧已校过一次） */ }
    // [D32 实战 P0-1] 自定义请求变换（签名/加密参数）。**失败即不启动扫描**（await 抛出）：
    // 与 customPayloads 同口径 —— 静默忽略脚本会让使用者以为自定义签名生效了，
    // 然后在目标上跑一整轮全被拒的请求，最后产出一份「未检出」。
    // 登记成功后必须把「用了脚本」写进 summary.constraints：报告里的 PoC curl
    // **没有**重算签名，直接复制必然失败，这句不写就是不实交付。
    const xform = await ensureScanTransform(scanId, target.config);
    if (xform) {
      report.summary = report.summary || {};
      const list = Array.isArray(report.summary.constraints) ? report.summary.constraints : [];
      list.push(
        `本次扫描/检测阶段的每条出站请求都经过自定义变换脚本 ${xform.file}` +
        `（sha256=${xform.sha256.slice(0, 16)}…，含保活/CSRF 取页/登录这些非注入请求；` +
        '注入点发现阶段的爬虫请求不经此层）：报告中的 PoC curl 未重算签名，' +
        '直接复制会因签名/加密不匹配而失败，复现必须带同一脚本重放',
      );
      report.summary.constraints = list;
    }
    // [D36 实战 P0-2] Bearer/Token 自动续期登记（形状非法 ⇒ 扫描不启动）。
    // 注册必须在这里而不是 getScanClient：视图按 scanId 缓存，等到建视图时才校验就晚了 ——
    // 而"配了续期端点却配错"若降级继续，症状与前半程正常、后半程全 401 的静默假阴性一模一样。
    {
      const br = target.config && target.config.bearerRefresh;
      if (br) {
        const norm = normalizeRefreshConfig(br);
        registerScanRefresh(scanId, norm);
        report.summary = report.summary || {};
        const list2 = Array.isArray(report.summary.constraints) ? report.summary.constraints : [];
        list2.push(
          `本次启用 Bearer 自动续期：${norm.url}` +
          `（tokenField=${norm.tokenField || '自动探测'}${norm.refreshToken ? '' : '，刷新凭据取自会话 Cookie'}）` +
          '；续期失败时报告会把「未检出」降级为不可信，不会把 401 半程写成无漏洞',
        );
        report.summary.constraints = list2;
      }
    }
    this.scans.set(scanId, { target, report, status: 'running', cancelled: false, createdAt: Date.now(), abortController: new AbortController() });
    eventBus.create(scanId);
    // [MERGED: security] 事件脱敏：SSE 不再携带 target 凭据（auth/cookie/header）
    eventBus.emit(scanId, 'scan_started', { scanId, target: publicTarget(target) });
    // scans Map 容量上限：超限淘汰最旧扫描（防本地 DoS 长跑内存膨胀）
    this._evictIfOverLimit();

    // 异步执行扫描流水线，避免阻塞 HTTP 响应
    this._run(scanId).catch((err) => {
      logger.error(`扫描 ${scanId} 异常：${err.message}`);
      eventBus.emit(scanId, 'scan_error', { code: err.code, message: err.message });
      const s = this.scans.get(scanId);
      if (s) {
        s.status = 'error';
        s.report.finishedAt = new Date().toISOString();
      }
      // 错误路径同样回收扫描上下文（30s TTL）
      this._retire(scanId);
    });

    return scanId;
  }

  // 停止扫描（返回布尔；"为什么停不了"由 status() 给出，路由层据此区分三种情形）
  // [P0-FIX 2026-09-28 接口靶场] 终态扫描不再被改写成 'stopped'：
  //   旧实现对**已完成**的扫描也返回 true 并把 status 覆盖成 'stopped' —— 一次正常跑完的
  //   扫描在报告里变成"被人停了"，交付时这句假陈述会误导复盘（"是谁中断的？"）。
  stop(scanId) {
    const s = this.scans.get(scanId);
    if (!s) return false;
    if (TERMINAL_STATUSES.includes(s.status)) return false; // 已结束：不改状态、不重复回收
    s.cancelled = true;
    s.paused = false; // 清除暂停态
    s.status = 'stopped';
    // [⑮] 中断在途 HTTP 请求：abort() 触发所有传入 signal 的 axios/undici 请求
    // 抛出 AbortError，不再等待超时或响应返回。与 s.cancelled 协作：
    //   abort → 中断当前在途请求（立即生效）
    //   cancelled → 阻止新请求发出（点边界轮询检查）
    try { s.abortController?.abort(); } catch { /* 已 abort 或不存在 */ }
    eventBus.emit(scanId, 'scan_stopped', { scanId });
    // stopped 路径回收扫描上下文
    this._retire(scanId);
    return true;
  }

  // [⑮] 获取扫描级 AbortSignal，供 httpClient wrapper 注入到每个请求
  getSignal(scanId) {
    return this.scans.get(scanId)?.abortController?.signal || null;
  }

  // [P0-FIX] 暂停扫描：设置 paused 标志（扫描循环在点边界检查并等待），
  // 不回收上下文、不终止请求。仅 running 状态可暂停。
  pause(scanId) {
    const s = this.scans.get(scanId);
    if (!s || s.status !== 'running') return false;
    if (s.paused) return true; // 已暂停则幂等
    s.paused = true;
    s.status = 'paused';
    eventBus.emit(scanId, 'scan_paused', { scanId });
    return true;
  }

  // 恢复暂停的扫描：清除 paused 标志，回到 running。
  resume(scanId) {
    const s = this.scans.get(scanId);
    if (!s || s.status !== 'paused') return false;
    s.paused = false;
    s.status = 'running';
    eventBus.emit(scanId, 'scan_resumed', { scanId });
    return true;
  }

  // 获取实时报告（返回深拷贝，防 running 时序列化撕裂）
  /**
   * 扫描运行态（HTTP 层的可观测面）。
   *
   * 为什么必须有这个方法：`getReport()` 返回的是**报告快照**，而"扫描在不在跑、
   * 有没有暂停"记在 scans 条目上、不在报告里 —— 于是 REST 客户端只能靠一条 SSE
   * 长连接推断状态（断了就完全看不到）。pause/resume 的接口返回 `paused:true`
   * 也只证明路由收到了，不证明状态机真的动了。sqlmap 那侧的 /report 早就带
   * `status`，内置引擎对齐这个契约。
   * @param {string} scanId
   * @returns {{scanId:string,status:string,paused:boolean,retired:boolean,startedAt:?string,finishedAt:?string,points:number,vulns:number,dbms:?string,elapsedMs:number}|null}
   */
  status(scanId) {
    const s = this.scans.get(scanId);
    if (!s) return null;
    const rep = s.report || {};
    const startedAtMs = rep.startedAt ? Date.parse(String(rep.startedAt)) : NaN;
    const finishedAtMs = rep.finishedAt ? Date.parse(String(rep.finishedAt)) : NaN;
    return {
      scanId,
      status: s.status,
      paused: Boolean(s.paused),
      retired: Boolean(s._retired),
      startedAt: rep.startedAt || null,
      finishedAt: rep.finishedAt || null,
      points: (rep.points || []).length,
      vulns: (rep.vulns || []).length,
      dbms: rep.dbms || null,
      elapsedMs: Number.isFinite(startedAtMs) ? Math.max(0, (Number.isFinite(finishedAtMs) ? finishedAtMs : Date.now()) - startedAtMs) : 0,
    };
  }

  getReport(scanId) {
    const s = this.scans.get(scanId);
    if (!s || !s.report) return null;
    try {
      return structuredClone(s.report);
    } catch {
      // structuredClone 不可用时回退 JSON 序列化
      return JSON.parse(JSON.stringify(s.report));
    }
  }

  // 导出报告（json / html / csv / markdown / db-json / sarif）
  // reportArg：允许把"台账里读回来的报告"喂进同一条渲染路径。
  //   为什么需要参数而不是在路由里再写一个 switch：两种来源各自渲染一次，
  //   就会出现"内存里的报告能导出、台账里那份少一个格式"的漂移（本仓反复出现的那族）。
  exportReport(scanId, format = 'json', reportArg = undefined) {
    const s = this.scans.get(scanId);
    const report = reportArg !== undefined ? reportArg : s && s.report;
    if (!report) return null;
    if (format === 'html') return this.reportGen.toHTML(report);
    if (format === 'csv') return this.reportGen.toCSV(report);
    if (format === 'markdown' || format === 'md') return this.reportGen.toMarkdown(report);
    if (format === 'sarif') return this.reportGen.toSARIF(report); // [批次 9 2026-09-15] SARIF 2.1.0
    if (format === 'db-json') return JSON.stringify(report.data); // 仅拖库数据（库/表/列/行）
    return this.reportGen.toJSON(report);
  }

  // 扫描流水线
  async _run(scanId) {
    // [P0-FIX 2026-09-09] 把生产护栏策略放进本次扫描的异步上下文：所有经 selectPayloads 的筛选
    // 自动读到，不需要每个检测器手工透传（又一个「某个阶段漏一个键」的坑位就此消失）。
    const s = this.scans.get(scanId);
    const cfg = (s && s.target && s.target.config) || {};
    return runWithDestructivePolicy(
      {
        productionMode: cfg.productionMode !== false,
        confirmDestructive: cfg.confirmDestructive === true,
      },
      () => runScanLoop(this, scanId)
    );
  }

  // [B-perf] skip-static 参数预筛选（对标 sqlmap --skip-static，opt-in）：
  // 返回「需完整检测」的点集合；被判静态（同值重复 / 哨兵探测无差异）的点被过滤。
  // 两层判定（均保守，宁可多测不漏检）：
  //   a) 同值去重：原始值完全相同的参数只测第一个（零请求成本；检测结论对同值参数等价）。
  //   b) 哨兵探测：仅剩单点时跳过（无跨点预算可省）；多点时对每点发 1 次哨兵请求
  //      （值改为明显不同的哨兵值），与「原始值基线」比对——状态码、正文长度、规范化正文
  //      全部一致且哨兵值未回显在响应中 → 判定静态参数；任一维度有差异 / 任一请求失败
  //      → 保守保留做完整检测。
  // 基线按「请求方法 + URL」缓存共享：同页面的多参数目标只发 1 次基线（form 点不同 action
  // 各自基线），总成本 ≈ 去重后点数 + 1 请求。不修改注入点对象、不改变报告 point 列表。
  // 精确标记点（precisionMarked，用户显式 * 指定）不参与任何跳过。
  // ===== [大文件拆分 2026-09-20] 注入点预过滤家族：实现已外移至 scan/prefilter.js =====
  // 下方 9 个方法保留**同名薄委托**：discover.js 与既有测试的调用点零影响。
  // 唯一的实例依赖 _mapPool 经 _prefilterDeps 注入，模块侧不接触 this。
  //
  // 为什么这一簇能安全外移（对比 scan/detect.js 那次评估）：6 个方法完全不引用 this，
  // 其余只簇内互调 —— 不是那种「靠 37 个散变量跨阶段通信」的高耦合段。
  // 保守红线（外移后逐字保留）：任一探测失败/超时/不可判定 → 保留该点做完整检测。

  /** 预过滤模块的依赖注入点（getter 使 _mapPool 被替换时仍取最新实现） */
  get _prefilterDeps() {
    return { mapPool: this._mapPool.bind(this) };
  }

  // [B-perf] skip-static 参数预筛选（对标 sqlmap --skip-static，opt-in）：
  // 返回「需完整检测」的点集合；被判静态（同值重复 / 哨兵探测无差异）的点被过滤。
  // 两层判定（均保守，宁可多测不漏检）：
  //   a) 同值去重：原始值完全相同的参数只测第一个（零请求成本；检测结论对同值参数等价）。
  //   b) 哨兵探测：仅剩单点时跳过（无跨点预算可省）；多点时对每点发 1 次哨兵请求
  //      （值改为明显不同的哨兵值），与「原始值基线」比对——状态码、正文长度、规范化正文
  //      全部一致且哨兵值未回显在响应中 → 判定静态参数；任一维度有差异 / 任一请求失败
  //      → 保守保留做完整检测。
  // 基线按「请求方法 + URL」缓存共享：同页面的多参数目标只发 1 次基线（form 点不同 action
  // 各自基线），总成本 ≈ 去重后点数 + 1 请求。不修改注入点对象、不改变报告 point 列表。
  // 精确标记点（precisionMarked，用户显式 * 指定）不参与任何跳过。
  async _skipStaticPoints(ctxBase, target, points) {
    return skipStaticPoints(this._prefilterDeps, ctxBase, target, points);
  }

  // 哨兵值构造：数字 +1001（1→1002）、非数字字符串加 _sst 后缀（abc→abc_sst）
  _staticSentinel(orig) {
    return staticSentinel(orig);
  }

  // 静态判定用正文规范化：仅折叠连续空白并去首尾（时间戳/CSRF 等任何其它差异都视为动态）
  _normalizeForStatic(body) {
    return normalizeForStatic(body);
  }

  // P2-P1 参数预筛选：对每个注入点发 3 个廉价探测（基线 + 单引号报错 + 时间向量，点内并行），
  // 返回「需完整检测」的点；明显无注入迹象的点被过滤（省完整检测的指纹/检测器请求，约 50-75%）。
  // 完整保守策略与预算推导见 scan/prefilter.js 的 prefilterPoints。
  async _prefilterPoints(ctxBase, target, points) {
    return prefilterPoints(this._prefilterDeps, ctxBase, target, points);
  }

  // [P1-FIX 2026-09-05] 基线 RTT 实测（预筛选共享 1 次）：注入原值的单次请求耗时。
  // 失败/超时返回 null（调用方跳过预筛）。2s 上限防不可达目标拖慢流水线。
  async _probeBaselineRttMs(httpClient, prefilterCtx, target, samplePoint) {
    return probeBaselineRttMs(httpClient, prefilterCtx, target, samplePoint);
  }

  // [P1-FIX 2026-09-05] 时间探针按 dbms 选族（含 [CTX-FIX 2026-09-18] 数值上下文变体）
  _timeProbeValues(dbms, sleepSec) {
    return timeProbeValues(dbms, sleepSec);
  }

  // [P1-PERF 2026-09-08 实战批次] 输入校验型目标的「可证安全跳过」判定（单参数目标专用）
  async _validationGuardedSkipPoints(ctxBase, target, points) {
    return validationGuardedSkipPoints(this._prefilterDeps, ctxBase, target, points);
  }

  // [P1-PERF 2026-09-08] 回显剥离：把本次注入值（原样 / URL 编码 / HTML 实体）从正文剔掉后再比对
  _normEcho(body, value) {
    return normEcho(body, value);
  }

  // 预筛选相似判定（状态码一致 + 长度差在容差内 + 最长公共前缀 ≥ 85%）
  _prefilterSimilar(baseBody, baseStatus, body, status) {
    return prefilterSimilar(baseBody, baseStatus, body, status);
  }

  // 完整拖库（库→表→列→数据）
  // extractScope 存在时（CLI --dbs/--tables/--columns/--dump/--current-db/--current-user/--count）
  // 走 _extractByScope 定向枚举；否则保留既有全量拖库逻辑（零回归）。
  async _extract(scanId, ctx) {
    return extractAll(this, scanId, ctx);
  }

  // [P2] 委托 scanHelpers.mapPool
  async _mapPool(items, fn, concurrency) {
    return mapPool(items, fn, concurrency);
  }

  // [P2] 委托 scanHelpers.mergeExtracted
  _mergeExtracted(target, src) {
    return mergeExtracted(target, src);
  }

  // [P2] 委托 scanHelpers.mergeExtractedForResume
  _mergeExtractedForResume(current, restored) {
    return mergeExtractedForResume(current, restored);
  }

  // [P2] 委托 scanHelpers.hasData
  _hasData(data) {
    return hasData(data);
  }

  // 枚举模式提取（对标 sqlmap --dbs/--tables/--columns/--dump/--current-db/--current-user/--count）。
  // extractScope = { mode, dbs?, tables?, cols?, excludeSysdbs? }
  //   dbs/tables 为数组；cols 为逗号串或数组；excludeSysdbs 默认 true。
  // 返回与 emptyExtractedData 同结构的对象（含 mode 专用字段 currentDb/currentUser/counts）。
  async _extractByScope(scanId, ctx, scope) {
    return extractByScope(this, scanId, ctx, scope);
  }
}

// —— 五期拆分（2026-10-01）：搬移的方法在原型上按原名挂载（与原类方法同调用风格，this 语义不变）——
ScanManager.prototype._wrapWithSignal = _wrapWithSignal;
ScanManager.prototype._waitWhilePaused = _waitWhilePaused;
ScanManager.prototype._retire = _retire;
ScanManager.prototype._disposeScan = _disposeScan;
ScanManager.prototype._evictIfOverLimit = _evictIfOverLimit;
ScanManager.prototype.getConnector = getConnector;
ScanManager.prototype._maybeClose = _maybeClose;
ScanManager.prototype.getScanClient = getScanClient;
ScanManager.prototype._fingerprintCached = _fingerprintCached;
ScanManager.prototype._selectedTechs = _selectedTechs;
ScanManager.prototype.activeDetectors = activeDetectors;
ScanManager.prototype._runSecondOrder = _runSecondOrder;
ScanManager.prototype._runNoSql = _runNoSql;

export default ScanManager;
