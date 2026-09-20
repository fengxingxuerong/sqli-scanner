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
import { createTarget, createReport, createVulnerability } from './models.js';
// [P0-FIX 2026-09-09] 生产护栏：扫描级高危池策略通过 AsyncLocalStorage 下发给 selectPayloads
import { runWithDestructivePolicy, countDestructiveCandidates } from './payloadRegistry.js';
import { TECHNIQUE_TYPES } from './payloads.js';
import { defaults } from '../config/defaults.js';
import * as eventBus from '../core/eventBus.js';
import { withSafeUrl } from '../core/safeUrlKeeper.js';
import { withCsrf } from '../core/csrfKeeper.js';
import { httpClient } from '../core/httpClient.js';
import { DirectConnector } from '../core/directConnector.js';
import { oobReceiver } from '../core/oobReceiver.js';
import { logger } from '../core/logger.js';
// [大文件拆分 2026-09-20] `buildInjectionRequest` / `sendInjection` / `applyPrefixSuffix`
// 与 `isUnusableResponse` 的 import 已随预过滤家族一起移入 scan/prefilter.js。
// 其中那条 P0-FIX 说明（sendInjection 把失败降级为带 __netErr 的对象而非 null，
// 预过滤若继续用 `res == null` 判断会把两次失败看成「同构」→ 新增假阴性）也一并搬到
// prefilter.js 顶部，避免这条关键约束随搬移丢失。
// [P0-SEC 2026-09-08] 扫描级 scope 登记：放在 ScanManager 而不是只放在 REST 路由里——
// CLI（server/bin/cli.js）与测试/复用型调用不进路由，只放路由会造成「Web 有范围约束、
// CLI 没有」的双标（而 CLI 才是渗透现场的主入口）。
import { parseScope, registerScanScope, releaseScanScope } from '../core/scopeGuard.js';
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
    this.retireTtlMs = retireTtlMs ?? 30000; // 可测参数：测试可传短 TTL 验证回收
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
      report.summary.constraints = collectCapabilityConstraints(target.config);
    } catch { /* 约束标注失败不影响扫描 */ }
    // 授权范围登记（未配置 scope 时为 no-op，零行为变化）：HttpClient 在每一跳重定向前取用。
    try {
      registerScanScope(scanId, parseScope(target.config && target.config.scope));
    } catch { /* 登记失败不阻断扫描（入口侧已校过一次） */ }
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

  // 停止扫描
  stop(scanId) {
    const s = this.scans.get(scanId);
    if (!s) return false;
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

  // [⑮] 包装 httpClient：自动将扫描级 signal 注入到每次 request 调用
  _wrapWithSignal(scanId, client) {
    const signal = this.getSignal(scanId);
    if (!signal || !client || typeof client.request !== 'function') return client;
    return { ...client, request: (opts) => client.request({ ...opts, signal }) };
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

  // 导出报告（json / html / csv / markdown / db-json）
  exportReport(scanId, format = 'json') {
    const s = this.scans.get(scanId);
    if (!s) return null;
    if (format === 'html') return this.reportGen.toHTML(s.report);
    if (format === 'csv') return this.reportGen.toCSV(s.report);
    if (format === 'markdown' || format === 'md') return this.reportGen.toMarkdown(s.report);
    if (format === 'sarif') return this.reportGen.toSARIF(s.report); // [批次 9 2026-09-15] SARIF 2.1.0
    if (format === 'db-json') return JSON.stringify(s.report.data); // 仅拖库数据（库/表/列/行）
    return this.reportGen.toJSON(s.report);
  }

  // 选中技术集合：空/未定义 → 全部（含 stacked）；否则按所选
  // 若配置了 risk 级别，缩减高风险技术：
  //   risk 1：仅 union/error/boolean（安全，无写请求/无长时间等待）
  //   risk 2：全部（含 time/stacked/oob，默认）
  //   risk 3：全部 + 额外 OR 变体（由 Detector 层消费 risk 字段）
  _selectedTechs(config) {
    const sel = config && config.techniques;
    let techs = sel && sel.length ? sel : TECHNIQUE_TYPES;
    // [P0 2026-09-09] knownPoint.techniques：已知注入点的技术位白名单（扫描级过滤，
    // 与 config.techniques 取交集）——手工确认 union 注入后不再全技术位扫
    const kpTechs = config && config.knownPoint && Array.isArray(config.knownPoint.techniques)
      ? config.knownPoint.techniques
      : null;
    if (kpTechs && kpTechs.length) techs = techs.filter((t) => kpTechs.includes(t));
    // risk 门控
    const risk = (config && config.risk) != null ? config.risk : 2;
    if (risk < 2) {
      // risk 1：排除 time（慢速等待）、stacked（写操作风险）、oob（出站请求）
      techs = techs.filter((t) => !['time', 'stacked', 'oob'].includes(t));
    }
    // risk 3 不需要额外过滤，因为 risk 3 的 OR 变体由 Detector 独立消费 risk 字段
    return techs;
  }

  // 按技术选择过滤检测器（唯一过滤入口）
  activeDetectors(config) {
    const sel = this._selectedTechs(config);
    return this.detectors.filter((d) => sel.includes(d.technique));
  }

  // 连接器选择：direct 目标用 DirectConnector 直连数据库，其余用统一 HttpClient 单例。
  getConnector(target) {
    return target && target.mode === 'direct' ? new DirectConnector(target) : this.httpClient;
  }

  // 关闭非单例的连接器（如直连 DirectConnector），避免连接泄漏；HttpClient 单例不关。
  async _maybeClose(connector) {
    if (connector && connector !== this.httpClient && connector.close) {
      try {
        await connector.close();
      } catch {
        /* ignore */
      }
    }
  }

  // 获取扫描作用域的 HttpClient 视图：http 目标包装为按 scanId 独立限速桶的客户端
  // （前端 ratePerSec 设置由此生效，Detector/Extractor 无需改动），direct 目标原样返回。
  getScanClient(scanId, target) {
    const connector = this.getConnector(target);
    if (connector !== this.httpClient || typeof connector.forScan !== 'function') return connector;
    if (!this._scanClients.has(scanId)) {
      // [sqlmap 对标] --reqrate：reqRate > 0 时覆盖 ratePerSec 作为 TokenBucket 速率
      const reqRate = target.config && target.config.reqRate;
      const ratePerSec = (reqRate && reqRate > 0 ? reqRate : (target.config && target.config.ratePerSec)) || undefined;
      const sc = connector.forScan(scanId, ratePerSec);
      // [sqlmap 对标] --safe-url/--safe-freq：配置了保活 URL 时包装客户端
      // （SSRF 校验在 client.request 内逐请求执行；失败静默不影响扫描）
      const cfg = (target && target.config) || {};
      let view = sc;
      if (typeof cfg.safeUrl === 'string' && /^https?:\/\//i.test(cfg.safeUrl)) {
        view = /** @type {any} */ (withSafeUrl(sc, { safeUrl: cfg.safeUrl, safeFreq: cfg.safeFreq }));
      }
      // [sqlmap 对标 2026-09-14] --csrf-url/--csrf-token：CSRF 会话层（取页提取 token，
      // 每请求自动携带 + 定期刷新）。挂在 safeUrl 之后：token 取页吃到保活/协议策略。
      if (typeof cfg.csrfUrl === 'string' && /^https?:\/\//i.test(cfg.csrfUrl)) {
        view = /** @type {any} */ (withCsrf(view, {
          csrfUrl: cfg.csrfUrl,
          csrfTokenName: cfg.csrfTokenName,
          csrfMethod: cfg.csrfMethod,
          refreshFreq: cfg.csrfRefreshFreq,
        }));
      }
      // [P2-5] --force-ssl / --ignore-redirects：协议层策略注入每个请求（对标 sqlmap）。
      // forceSsl：目标 http:// 强制升级 https（httpClient.request 消费改写）；
      // ignoreRedirects：不跟随 3xx（httpClient.request 消费跳转上限 0）。
      // 在 forScan 视图之上再包一层，Detector/Extractor/二阶/NoSQL/WAF 全路径统一生效，
      // 且不影响未配协议策略的存量扫描（无配置时 view 原样返回零开销）。
      // [P1-FIX 2026-09-08 接线补齐] 出口层三键走同一个注入点：
      //   insecureTls / trustProxyEnv / ssrfViaProxy 此前只能靠 defaults 或环境变量——
      //   Detector.send 等 7 个调用点只透传 `proxy/auth`，per-scan config 到不了 HttpClient，
      //   于是「UI 勾了忽略自签证书」对实际发包无效（引擎已实现能力在 API 层不可达）。
      //   在扫描级视图统一注入后，新增出口类配置只需改 defaults + 白名单 + 这一处，不再漏接线。
      const egressPatch = {};
      if (cfg.insecureTls === true) egressPatch.insecureTls = true;
      if (cfg.trustProxyEnv !== undefined) egressPatch.trustProxyEnv = cfg.trustProxyEnv !== false;
      if (cfg.ssrfViaProxy !== undefined) egressPatch.ssrfViaProxy = cfg.ssrfViaProxy;
      const proto =
        cfg.forceSsl === true || cfg.ignoreRedirects === true || Object.keys(egressPatch).length > 0
          ? egressPatch
          : null;
      const baseHead = typeof view.headRequest === 'function' ? view.headRequest.bind(view) : null;
      if (proto) {
        const baseRequest = view.request.bind(view);
        view = {
          ...view,
          request: (opts) => baseRequest({
            ...opts,
            ...(cfg.forceSsl === true ? { forceSsl: true } : {}),
            ...(cfg.ignoreRedirects === true ? { ignoreRedirects: true } : {}),
            ...egressPatch,
          }),
          // [P0-FIX 2026-09-09] headRequest（--null-connection）必须走同一层包装：
          // 它不经过 view.request，以前只包 request 等于「HEAD 一路看不到 insecureTls/代理/scope 以外的出口语义」。
          // 实战表现：自签目标上 GET 能扫、开了 --null-connection 就全量失败，现场极难归因。
          ...(baseHead
            ? {
                headRequest: (url, opts = {}) =>
                  baseHead(url, {
                    ...opts,
                    ...(cfg.forceSsl === true ? { forceSsl: true } : {}),
                    ...(cfg.ignoreRedirects === true ? { ignoreRedirects: true } : {}),
                    ...egressPatch,
                  }),
              }
            : {}),
        };
      }
      this._scanClients.set(scanId, view);
    }
    return this._scanClients.get(scanId);
  }

  // 指纹结果按目标缓存（同目标多注入点不重复跑 8-9 请求指纹）。
  // fpCache 存 Promise：并发 worker 同时命中 miss 时共享同一 in-flight 指纹，杜绝重复请求。
  // [CTX-FIX 2026-09-18] **判不出的结果不共享**：整轮指纹是用「触发它的那一个注入点」的上下文跑的
  //   （闭合前缀与点位置直接决定探针能否执行）。开 --test-headers/--test-path 后排在最前的常常是
  //   path/header 点，其上下文会把整轮指纹跑废，而 null 一旦被缓存就被后面每个点继承：
  //   实测 blackbox-lab C2-blindtime（真 MySQL 时间盲注点）r2 档因此 dbms=null → time 通道按
  //   未知方言投放 → 漏检；同一目标关掉 header/path 点单跑则 dbms=MySQL 正常命中。
  //   现给「重跑」留预算：最多 FP_RETRY_MAX+1 次尝试，成功定库的目标零额外请求（行为与原来一致）。
  async _fingerprintCached(fpCache, ctxBase, target, point) {
    // [CTX-FIX 2026-09-18] 缓存键按「点类别」分桶，不再整台目标共享一份：
    // path / header 点的探针上下文与 query/body 点往往完全不同（实测 /api/sleep 的 path 点
    // 探针全部 404 → 整轮指纹 null），而检测是多点**并发**跑的（detect.js 里 Promise.all），
    // 谁先跑谁定调 → 真能出结果的 query 点只能继承那份 null。
    // 分桶后最多每类各跑一次指纹（query/body/cookie 仍共用 'main'，与原行为等价）。
    const cls = point?.location === 'path' || point?.location === 'header' ? point.location : 'main';
    const key = `${target.baseUrl || target.url || (target.mode === 'direct' ? 'direct' : 'target')}|${cls}`;
    const FP_RETRY_MAX = 2;
    let slot = fpCache.get(key);
    if (!slot) {
      slot = { promise: null, attempts: 0 };
      fpCache.set(key, slot);
    }
    if (!slot.promise) {
      slot.attempts++;
      const allowRetry = slot.attempts <= FP_RETRY_MAX;
      slot.promise = this.fp
        .fingerprint({ ...ctxBase, target, point })
        .catch((e) => {
          logger.warn(`指纹识别失败：${e.message}`);
          return null;
        })
        .then((res) => {
          // 未定出库 → 撤下这条 in-flight 记录，让下一个注入点用自己的上下文再试
          if (allowRetry && (!res || !res.dbms)) slot.promise = null;
          return res;
        });
    }
    return await slot.promise;
  }

  // 扫描上下文回收：completed/stopped/error 后置 retiredAt，TTL 到期清 scans 条目 + eventBus + 限速桶
  _retire(scanId) {
    const s = this.scans.get(scanId);
    if (!s || s._retired) return;
    s._retired = true;
    s.retiredAt = new Date().toISOString();
    const timer = setTimeout(() => {
      this._disposeScan(scanId);
    }, this.retireTtlMs);
    if (typeof timer.unref === 'function') timer.unref(); // 不阻塞进程退出
    s._retireTimer = timer;
  }

  // 立即清理某次扫描的全部上下文（TTL 到期 / 超限淘汰）
  _disposeScan(scanId) {
    // [P0-SEC] 同步回收 scope 登记（防同 id 复用旧范围，也防 Map 无界增长）
    releaseScanScope(scanId);
    const rec = this.scans.get(scanId);
    this.scans.delete(scanId);
    eventBus.dispose(scanId);
    if (this._scanClients.has(scanId)) {
      if (typeof this.httpClient.removeBucket === 'function') this.httpClient.removeBucket(scanId);
      // [sqlmap 对标] --max-requests：清理请求计数（防 Map 无界增长）
      if (typeof this.httpClient.removeRequestCount === 'function') this.httpClient.removeRequestCount(scanId);
      // [P1-FIX 2026-09-05] Cookie Jar 随扫描退役清理（防跨扫描会话泄漏 + Map 无界增长）
      if (typeof this.httpClient.clearJar === 'function') this.httpClient.clearJar(scanId);
      this._scanClients.delete(scanId);
    }
    if (rec && rec._retireTimer) clearTimeout(rec._retireTimer);
  }

  // scans Map 容量上限：超限淘汰最旧扫描
  // [MERGED: engine ★FIX-2] 只淘汰「非 running」的扫描：运行中的扫描若被淘汰，报告会立即
  // 从 getReport 中消失（用户拿不到结果），而 _run 的请求仍在继续（脱离治理）。
  // 全部 running 时宁可暂时超限也不淘汰在途扫描。
  _evictIfOverLimit() {
    if (this.scans.size <= this.maxScans) return;
    let victim = null;
    let oldestTs = Infinity;
    for (const [id, rec] of this.scans) {
      if (rec.status === 'running') continue; // 不淘汰运行中的扫描
      const ts = rec.createdAt || 0;
      if (ts < oldestTs) {
        oldestTs = ts;
        victim = id;
      }
    }
    if (victim) this._disposeScan(victim);
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

  // 二阶注入补充趟：在既有一阶聚合之后运行，对"每个存储点 × 每个触发页"调用独立 SecondOrderDetector。
  // 门控（唯一硬门）：secondOrder.enabled && triggerUrls 非空 && 存在 isStorePoint 点；
  // 否则直接 return []（零写、对一阶零侵入）。命中结果复用既有 foundByPoint → 聚合去重 → riskOf 通道。
  async _runSecondOrder(scanId, target, points, dbms) {
    const so = (target.config && target.config.secondOrder) || {};
    if (!so.enabled) return []; // 未启用：直接跳过，对目标零写
    const triggerUrls = Array.isArray(so.triggerUrls) ? so.triggerUrls : [];
    if (triggerUrls.length === 0) return []; // 无候选触发页：跳过
    const storePoints = points.filter((p) => p && p.isStorePoint);
    if (storePoints.length === 0) return []; // 无存储点：跳过

    // 告警：开启二阶检测即代表将对目标发起真实写请求（POST 注册/评论/资料）
    logger.warn(
      '二阶检测已开启：将对目标发起真实写请求（POST 注册/评论/资料），仅在你确认已授权目标时执行'
    );

    // 二阶 OOB 触发：oobTrigger 开启且 oob 启用时，确保带外接收端就绪（幂等；失败仅告警不阻断，
    // 检测器侧会再以 OOB_DISABLED 拒绝未就绪分支，由下方 try/catch 捕获记录）
    const oobCfg = (target.config && target.config.oob) || {};
    if (so.oobTrigger === true && oobCfg.enabled) {
      try {
        await oobReceiver.start(oobCfg);
      } catch (e) {
        logger.warn(`二阶 OOB 接收端启动失败，OOB 触发判定将不可用：${e.message}`);
      }
    }

    const collected = [];
    // [P0-FIX 2026-09-06] ctxBase 补 dbms：缺失时 SecondOrderDetector._buildProbe 走
    // SECOND_ORDER_PROBES[0]（单引号裸探针）而非该库报错模板 → 探针退化必漏（real-world-lab 实测）
    const ctxBase = { httpClient: this._wrapWithSignal(scanId, this.getScanClient(scanId, target)), config: target.config, dbms };
    // [P1-FIX 2026-09-07] 按「存储目标」分组调度：同一 actionUrl（同一张表单）的字段共享
    // 同一份存储——并发检测时 A 点刚写入的探针会被 B 点的写入覆盖（实测 body 点探针被
    // item_id 点阴性对照覆盖 → 触发页读到良性值 → 恒漏检）。故同组内严格串行，
    // 不同 actionUrl（不同表单/不同存储）之间仍可并行。
    const storeGroups = new Map();
    for (const p of storePoints) {
      const key = String(p.actionUrl || p.id);
      if (!storeGroups.has(key)) storeGroups.set(key, []);
      storeGroups.get(key).push(p);
    }
    const groups = [...storeGroups.values()];
    // [MERGED: perf] 并发治理：旧实现双层 for 全串行（storePoints × triggerUrls 逐对 await），
    // 10 存储点 × 3 触发页 = 30 次检测墙钟线性累加。现按「存储组」并行（_mapPool 限并发，
    // 默认 2；组内存储点与触发页均串行——同一存储内并发写会相互污染读回判定）。
    const concurrency = Math.max(1, Math.min(Number(so.concurrency) || 2, groups.length));
    await this._mapPool(
      groups,
      async (group) => {
        for (const point of group) {
          const pointDbms = dbms || point.dbms; // 复用一阶已识别的 dbms（若有时）
          for (const triggerUrl of triggerUrls) {
            const ctx = { ...ctxBase, target, point, dbms: pointDbms, triggerUrl, scanId };
            try {
              const result = await this.secondOrderDetector.detect(ctx);
              if (result.vulnerable) {
                // 复用既有聚合/风险纳管通道：先经 ReportGenerator.riskOf 定级（second_order → High）
                const risk = this.reportGen.riskOf([
                  createVulnerability(point.id, 'second_order', 'Medium', result.payloads, result.evidence),
                ]);
                const vuln = createVulnerability(
                  point.id,
                  'second_order',
                  risk,
                  result.payloads,
                  result.evidence
                );
                vuln.dbms = result.dbms;
                collected.push(vuln);
                eventBus.emit(scanId, 'detection_found', { ...result, riskLevel: risk });
              }
            } catch (e) {
              logger.warn(`二阶检测失败（点 ${point.id} / 触发页 ${triggerUrl}）：${e.message}`);
            }
          }
        }
      },
      concurrency
    );
    await this._maybeClose(ctxBase.httpClient);
    return collected;
  }

  // 非 SQL 注入补充趟（NoSQL/GraphQL/SSTI）：门控 noSql.enabled 才运行，默认关闭（opt-in）。
  // 对一阶流水线零侵入：仅在启用时对每个注入点 × 每个类别（nosql/graphql/ssti）调用独立 NoSqlInjectionDetector。
  // 命中复用既有聚合/风险纳管通道（technique 统一记为 'nosql'，报告层按 noSqlKind 细分展示）。
  async _runNoSql(scanId, target, points, dbms) {
    const noSql = (target.config && target.config.noSql) || {};
    if (!noSql.enabled) return []; // 未启用：直接跳过，对目标零额外请求
    const kinds = Array.isArray(noSql.kinds) && noSql.kinds.length ? noSql.kinds : ['nosql', 'graphql', 'ssti'];
    const collected = [];
    const ctxBase = { httpClient: this._wrapWithSignal(scanId, this.getScanClient(scanId, target)), config: target.config };
    logger.info(`非SQL注入检测已开启（类别：${kinds.join('/')}），将对 ${points.length} 个注入点逐一探测`);
    // [MERGED: perf] 并发治理：旧实现点 × 类别双层串行；现按「注入点」并行（_mapPool 限并发 2），
    // 同一注入点内类别仍串行（探测表按成本升序命中即停的短路语义不变）。
    const concurrency = Math.max(1, Math.min(Number(noSql.concurrency) || 2, points.length));
    await this._mapPool(
      points,
      async (point) => {
        for (const kind of kinds) {
          const ctx = { ...ctxBase, target, point, dbms: dbms || point.dbms, noSqlKind: kind };
          try {
            const result = await this.noSqlDetector.detect(ctx);
            if (result.vulnerable) {
              const risk = this.reportGen.riskOf([
                createVulnerability(point.id, 'nosql', 'Medium', result.payloads, result.evidence),
              ]);
              const vuln = createVulnerability(point.id, 'nosql', risk, result.payloads, result.evidence);
              vuln.dbms = null;
              vuln.noSqlKind = kind; // 透传细分类别（NoSQL/GraphQL/SSTI）
              collected.push(vuln);
              eventBus.emit(scanId, 'detection_found', { ...result, riskLevel: risk });
            }
          } catch (e) {
            logger.warn(`非SQL注入检测失败（点 ${point.id} / 类别 ${kind}）：${e.message}`);
          }
        }
      },
      concurrency
    );
    await this._maybeClose(ctxBase.httpClient);
    return collected;
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


/**
 * [P0-FIX 2026-09-09] 汇总「本次扫描被抑住了什么能力」，写进 report.summary.constraints。
 *
 * 为什么需要：本项目反复出现同一类缺陷——开关存在、引擎支持、中间断链，而用户以为生效了。
 * 把「没做」显式写出来，质控与交付时才能回答「你到底测了什么」；一句「已按最高风险等级测试」
 * 在没投放高危池时就是不实陈述。仅记真实可抑制项：当前 level/risk 本来就投不到高危模板时不记，
 * 免得给人一条假线索去改无关开关。
 *
 * @param {object} config 扫描配置（target.config）
 * @returns {string[]} 可读说明（空数组 = 本次无任何能力被抑制）
 */
export function collectCapabilityConstraints(config = {}) {
  const out = [];
  const productionMode = config.productionMode !== false;
  const confirmDestructive = config.confirmDestructive === true;
  const risk = Number(config.risk) || Number(defaults.risk) || 2;
  const level = Number(config.level) || Number(defaults.level) || 1;
  const useRegistry = config.useRegistry === true;

  if (productionMode && !confirmDestructive) {
    let n = 0;
    try {
      n = countDestructiveCandidates({ level, risk, testFilter: config.testFilter, testSkip: config.testSkip });
    } catch {
      n = 0;
    }
    if (n > 0) {
      out.push(
        `高危 payload 池（写文件/RCE/重运算类，本配置下候选 ${n} 条）已抑制：` +
          'productionMode=true 且未 confirmDestructive=true。确需在已授权目标上投放时显式设 confirmDestructive=true；' +
          '靶场/演练环境可整体关护栏（productionMode=false）'
      );
    }
  }
  if (!useRegistry && risk >= 3) {
    out.push(
      '扁平 payload 路径（useRegistry=false）不经过注册表高危池门控：REST/UI 下高危向量根本不会投放'
        + '（只允许 CLI 的 --risk 3 + --confirm-destructive 显式合并到进程级 payload 池）。' +
        '要真正拿到 risk=3 语义请用 useRegistry=true（受本护栏约束）或走 CLI 双开关'
    );
  }
  const so = config.secondOrder && typeof config.secondOrder === 'object' ? config.secondOrder : {};
  if (so.enabled === true && productionMode && so.allowWrites !== true) {
    out.push(
      '二阶非幂等写请求（POST/PUT/PATCH/DELETE）已抑制：productionMode=true 时需 secondOrder.allowWrites=true。' +
        '未放行时只跑幂等方法（GET/HEAD/OPTIONS），存储型写路径可能测不到'
    );
  }
  if (config.enableExtract === true) {
    out.push(
      '本次开启拖库（enableExtract）：提取阶段会向目标发出大量读请求（受限速与行数上限约束）。' +
        '生产环境建议控制行数并避开业务高峰'
    );
  }
  return out;
}

export default ScanManager;
