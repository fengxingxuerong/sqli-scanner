import { nanoid } from 'nanoid';
import { TargetParser } from './TargetParser.js';
import { UnionDetector } from './detectors/UnionDetector.js';
import { ErrorDetector } from './detectors/ErrorDetector.js';
import { BooleanBlindDetector } from './detectors/BooleanBlindDetector.js';
import { TimeBlindDetector } from './detectors/TimeBlindDetector.js';
import { StackedDetector } from './detectors/StackedDetector.js';
import { OobDetector } from './detectors/OobDetector.js';
import { SecondOrderDetector } from './detectors/SecondOrderDetector.js';
import { SecondOrderDiscovery } from './SecondOrderDiscovery.js';
import { DBFingerprinter } from './DBFingerprinter.js';
import { Extractor } from './Extractor.js';
import { Exploiter } from './Exploiter.js';
import { ColumnTypeEnumerator } from './ColumnTypeEnumerator.js';
import { WafIdentifier } from '../core/waf/WafIdentifier.js';
import { recommend } from '../core/waf/wafRecommend.js';
import { Scheduler } from '../services/Scheduler.js';
import { ReportGenerator } from '../services/ReportGenerator.js';
import { createTarget, createReport, emptyExtractedData, createVulnerability } from './models.js';
import { TECHNIQUE_TYPES } from './payloads.js';
import { buildInjectionRequest, sendInjection, obfuscateIfNeeded } from './injection.js';
import * as eventBus from '../core/eventBus.js';
import { httpClient } from '../core/httpClient.js';
import { SafeProbeClient } from '../core/SafeProbeClient.js';
import { oobReceiver } from '../core/oobReceiver.js';
import { logger } from '../core/logger.js';

// 扫描管理器（门面模式）：对外暴露 start/stop/getReport/exportReport，
// 内部串起「发现→指纹→四检测器→提取→构造报告」，全程经 EventBus 推送进度。
// 生命周期：扫描结束（completed/error/stopped）后经 _finalizeScan 释放 OOB 引用、
// 并按 scanRetentionMs 定时淘汰扫描快照（防止 scans Map 无限增长导致内存泄漏）。
export class ScanManager {
  constructor({ wafIdentifier, wafRecommend, scanRetentionMs, maxScans } = {}) {
    this.httpClient = httpClient; // 统一 HttpClient（便于测试时注入 mock）
    // 扫描快照保留期（ms）：结束后多久自动从内存清除；0 = 不自动清理（谨慎，会泄漏）。
    this.scanRetentionMs = scanRetentionMs ?? 30 * 60 * 1000;
    // 内存中最多保留的扫描快照数（超出后按完成时间淘汰最旧的已完成/错误/停止扫描）。
    this.maxScans = maxScans ?? 20;
    // scanId -> 淘汰定时器句柄（stop/清理时取消，避免残留定时器）
    this._evictTimers = new Map();
    this.parser = new TargetParser(this.httpClient);
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
    // 二阶触发页自动发现器（方向 1）：从目标页链接发现候选触发页并经哨兵回显确认；
    // 仅当 secondOrder.enabled && autoDiscover && 未手填 triggerUrls 时由 _runSecondOrder 调用。
    this.secondOrderDiscovery = new SecondOrderDiscovery(this.httpClient);
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
    this.scans.set(scanId, { target, report, status: 'running', cancelled: false });
    eventBus.create(scanId);
    eventBus.emit(scanId, 'scan_started', { scanId, target });

    // 异步执行扫描流水线，避免阻塞 HTTP 响应
    this._run(scanId).catch((err) => {
      logger.error(`扫描 ${scanId} 异常：${err.message}`);
      eventBus.emit(scanId, 'scan_error', { message: err.message });
      const s = this.scans.get(scanId);
      if (s) {
        s.status = 'error';
        s.report.finishedAt = new Date().toISOString();
      }
      this._finalizeScan(scanId); // 错误路径同样释放 OOB 引用 + 排定淘汰
    });

    return scanId;
  }

  // 停止扫描
  stop(scanId) {
    const s = this.scans.get(scanId);
    if (!s) return false;
    s.cancelled = true;
    eventBus.emit(scanId, 'scan_stopped', { scanId });
    return true;
  }

  // 获取实时报告
  getReport(scanId) {
    const s = this.scans.get(scanId);
    return s ? s.report : null;
  }

  // 导出报告（json / html）
  exportReport(scanId, format = 'json') {
    const s = this.scans.get(scanId);
    if (!s) return null;
    return format === 'html'
      ? this.reportGen.toHTML(s.report)
      : this.reportGen.toJSON(s.report);
  }

  // 选中技术集合：空/未定义 → 全部（含 stacked）；否则按所选
  _selectedTechs(config) {
    const sel = config && config.techniques;
    return sel && sel.length ? sel : TECHNIQUE_TYPES;
  }

  // 按技术选择过滤检测器（唯一过滤入口）
  activeDetectors(config) {
    const sel = this._selectedTechs(config);
    return this.detectors.filter((d) => sel.includes(d.technique));
  }

  // 扫描流水线
  async _run(scanId) {
    const s = this.scans.get(scanId);
    if (!s) return;
    const { target, report } = s;

    // 安全间隔探测（对标 sqlmap --safe-url / --safe-freq）：
    // 配置了安全 URL 时，用 SafeProbeClient 包裹真实 httpClient，周期性穿插安全探测，
    // 偏离基线即告警。未配置则直接用真实 httpClient（零侵入）。
    const spCfg = target.config && target.config.safeProbe;
    const safeAlerts = [];
    // 扫描级客户端（fork）：共享全局 httpClient 的连接池，但令牌桶/requestDelayMs/keepAlive
    // 均为本扫描独立实例——并发扫描各自限速、互不拖慢、互不覆盖配置。
    // 固定请求间延时（对标 sqlmap --delay）与连接复用（对标 --keep-alive / --no-keep-alive）
    // 在 fork 内按 config 覆盖，对所有发包入口（sendInjection / Detector.send / Extractor / 指纹等）自动生效。
    let scanHttpClient = this.httpClient.fork(target.config);
    if (spCfg && (spCfg.url || (Array.isArray(spCfg.urls) && spCfg.urls.length))) {
      scanHttpClient = new SafeProbeClient(scanHttpClient, {
        safeUrl: spCfg.url,
        safeUrls: Array.isArray(spCfg.urls) ? spCfg.urls : undefined,
        safeFreq: Number(spCfg.freq) > 0 ? Number(spCfg.freq) : 0,
        randomize: spCfg.randomize !== false, // 默认随机选 URL；false=顺序轮询
        onAnomaly: (info) => {
          safeAlerts.push({
            url: info.url,
            reason: info.reason,
            baselineStatus: info.baseline?.status ?? null,
            baselineLen: info.baseline?.body?.length ?? null,
            actualStatus: info.actual?.status ?? null,
            actualLen: info.actual?.body?.length ?? null,
            ts: new Date().toISOString(),
          });
          eventBus.emit(scanId, 'safe_probe_alert', {
            url: info.url,
            reason: info.reason,
            baselineStatus: info.baseline?.status ?? null,
            actualStatus: info.actual?.status ?? null,
          });
          logger.warn(`安全探测告警（${info.url}）：${info.reason}`);
        },
      });
    }
    const ctxBase = { httpClient: scanHttpClient, config: target.config };

    // 1) 发现注入点（表单爬取为 async，需 await）
    const points = await this.parser.discover(target);
    report.points = points;
    eventBus.emit(scanId, 'point_discovered', { points });

    // 2) 调度每个注入点（并发池 + 令牌桶限速 + 重试）
    const scheduler = new Scheduler(target.config.concurrency, target.config.ratePerSec);
    // pointId -> { point, ctx, found:[{technique, result}] }
    const foundByPoint = new Map();
    const extracted = emptyExtractedData();
    // WAF 指纹聚合（跨注入点去重，按 vendor 保留最高置信度）；识别数据来自指纹基线，零额外发包
    const wafAgg = new Map();
    let dbms = null;
    const selectedTechs = this._selectedTechs(target.config);
    const stackedSelected = selectedTechs.includes('stacked');

    // OOB 带外接收端：仅当 oob 被选中且显式 enabled 时启动（默认关闭，避免意外出站带外）。
    // 记录本扫描是否持有 OOB 引用，结束时配对 stop（引用计数归零才真正关闭，不误杀并发扫描）。
    const oobCfg = target.config.oob;
    if (selectedTechs.includes('oob') && oobCfg && oobCfg.enabled) {
      try {
        await oobReceiver.start(oobCfg);
        s.oobStarted = true;
      } catch (e) {
        logger.warn(`OOB 接收端启动失败，oob 检测将不可用：${e.message}`);
      }
    }

    await scheduler.run(points, async (point) => {
      if (s.cancelled) return;

      // 指纹识别（返回 { dbms, baseline }，baseline 供 WAF 识别复用）
      // 强制 DBMS（--dbms）：跳过自动指纹判定，仅取基线响应供 WAF 识别与盲注比对，直接采用强制值。
      const forcedDbms = target.config && target.config.dbms;
      let fpResult;
      if (forcedDbms) {
        const baseReq = buildInjectionRequest(
          target,
          point,
          obfuscateIfNeeded(ctxBase, point.originalValue || '1'),
          ctxBase
        );
        const baselineResp = await sendInjection(this.httpClient, ctxBase, baseReq);
        fpResult = {
          dbms: forcedDbms,
          baseline: {
            status: baselineResp?.status ?? 0,
            headers: baselineResp?.headers ?? {},
            body: String(baselineResp?.data ?? ''),
          },
        };
      } else {
        fpResult = await this.fp.fingerprint({ ...ctxBase, target, point });
      }
      const detectedDbms = fpResult && fpResult.dbms;
      if (detectedDbms) {
        point.dbms = detectedDbms;
        dbms = detectedDbms;
      }
      // WAF 指纹识别：复用指纹阶段已抓取的基线响应（status/headers/body），零额外发包
      const wafCands = this.wafIdentifier.identify((fpResult && fpResult.baseline) || {});
      for (const c of wafCands) {
        const prev = wafAgg.get(c.vendor);
        if (!prev || c.confidence > prev.confidence) wafAgg.set(c.vendor, c);
      }
      const ctx = {
        ...ctxBase,
        target,
        point,
        dbms: detectedDbms || point.dbms,
        extractor: this.extractor,
      };

      // 逐个检测器尝试（按技术选择过滤）；经典技术命中维持 break-on-first-hit，
      // 仅当 stacked 也被选中时才不抢断，确保末位 stacked 能独立确认
      const found = [];
      for (const detector of this.activeDetectors(target.config)) {
        if (s.cancelled) break;
        eventBus.emit(scanId, 'point_testing', {
          pointId: point.id,
          technique: detector.technique,
        });
        try {
          const result = await detector.detect(ctx);
          if (result.vulnerable) {
            found.push({ technique: detector.technique, result });
            // 经典技术维持 break；stacked 本身在末位，不抢断
            if (detector.technique !== 'stacked' && !stackedSelected) break;
          }
        } catch (e) {
          logger.warn(`检测器 ${detector.technique} 失败：${e.message}`);
        }
      }
      if (found.length) foundByPoint.set(point.id, { point, ctx, found });
    });

    // 3) 聚合 + 去重（同点 stacked 命中 → 仅留 1 条 stacked(Critical)，其余移入印证）
    const finalVulns = [];
    const corroborations = [];
    for (const { point, ctx, found } of foundByPoint.values()) {
      const stackedItem = found.find((f) => f.technique === 'stacked');
      const items = stackedItem ? [stackedItem] : found;
      if (stackedItem) {
        for (const f of found) {
          if (f !== stackedItem) {
            corroborations.push({ pointId: point.id, technique: f.technique, dbms: f.result.dbms });
          }
        }
      }
      for (const f of items) {
        const risk =
          f.technique === 'stacked'
            ? 'Critical'
            : this.reportGen.riskOf([
                createVulnerability(point.id, f.technique, 'Medium', f.result.payloads, f.result.evidence, f.result.trace),
              ]);
        const vuln = createVulnerability(point.id, f.technique, risk, f.result.payloads, f.result.evidence, f.result.trace);
        vuln.dbms = f.result.dbms;
        // OOB 带外命中：透传结构化 token/callback 供前端专门展示（vuln 为普通对象，直接附加）
        if (f.technique === 'oob' && f.result.token) {
          vuln.oob = { token: f.result.token, callback: f.result.callback };
        }
        finalVulns.push(vuln);
        eventBus.emit(scanId, 'detection_found', { ...f.result, riskLevel: risk });
      }
    }

    // 3.5) 二阶补充趟：在一阶聚合之后运行，并入同一 finalVulns（门控 + 独立实例，对一阶零侵入）
    const soVulns = await this._runSecondOrder(scanId, target, points, dbms);
    for (const v of soVulns) finalVulns.push(v);

    // 4) 提取：仅对最终保留的漏洞做（union/error 拖库；boolean/time 版本证明）
    for (const { point, ctx } of foundByPoint.values()) {
      const vuln = finalVulns.find((v) => v.pointId === point.id);
      if (!vuln) continue;
      if (target.config.enableExtract) {
        if (vuln.technique === 'union' || vuln.technique === 'error') {
          const exData = await this._extract(scanId, ctx);
          this._mergeExtracted(extracted, exData);
        } else if (vuln.technique === 'boolean' || vuln.technique === 'time') {
          const proof = await this.extractor.extractProof(ctx);
          if (proof) {
            eventBus.emit(scanId, 'extraction_progress', {
              db: point.dbms,
              table: null,
              count: 1,
              note: `盲注二分提取版本：${proof}`,
            });
          }
        }
      }
    }

    // 5) 汇总报告并定级
    report.vulns = finalVulns;
    report.data = target.config.enableExtract ? extracted : null;
    report.summary.stackedEnabled = stackedSelected;
    report.summary.stackedCorroborations = corroborations;
    const hasData = this._hasData(extracted);
    report.riskLevel = hasData ? 'Critical' : this.reportGen.riskOf(finalVulns);
    report.dbms = dbms;
    report.finishedAt = new Date().toISOString();
    // WAF 规避标注：任一规避开关开启时，在报告摘要中记录（便于结果复现）
    const we = target.config && target.config.wafEvasion;
    if (we && (we.randomUA || we.jitterMs > 0 || we.obfuscate || (we.tamper && we.tamper.enabled))) {
      report.summary = report.summary || {};
      report.summary.wafEvasion = {
        randomUA: !!we.randomUA,
        jitterMs: Number(we.jitterMs) || 0,
        obfuscate: !!we.obfuscate,
        // tamper 链式组合标注（enabled/plugins 有序/intensity 仅审计）
        tamper: {
          enabled: !!(we.tamper && we.tamper.enabled),
          plugins: Array.isArray(we.tamper && we.tamper.plugins) ? [...we.tamper.plugins] : [],
          intensity: (we.tamper && we.tamper.intensity) || 'medium',
        },
      };
    }
    // WAF 指纹识别汇总：识别到 WAF 时发射 waf_detected 事件并在报告中记录（零额外发包）
    const wafVendors = [...wafAgg.values()].sort((a, b) => b.confidence - a.confidence);
    if (wafVendors.length > 0) {
      const suggestions = this.wafRecommend(wafVendors);
      eventBus.emit(scanId, 'waf_detected', { vendors: wafVendors, suggestions });
      report.summary = report.summary || {};
      report.summary.wafDetected = wafVendors;
    }
    // 安全间隔探测告警汇总（对标 sqlmap --safe-url 偏离告警；仅记录不阻断）
    if (safeAlerts.length > 0) {
      report.summary = report.summary || {};
      report.summary.safeProbeAlerts = safeAlerts;
    }
    s.status = 'completed';
    eventBus.emit(scanId, 'scan_completed', report);
    this._finalizeScan(scanId); // 释放 OOB 引用 + 排定淘汰定时器（防 scans Map 内存泄漏）
  }

  /**
   * 扫描收尾（completed / error 路径共用）：
   * 1) 释放本扫描持有的 OOB 接收端引用（引用计数归零才真正关闭，并发扫描互不误杀）；
   * 2) 按 scanRetentionMs 排定淘汰定时器（unref，不阻塞进程退出），到点从 scans Map 删除并清理 EventBus；
   * 3) 超过 maxScans 时按完成时间淘汰最旧快照（防无限增长）。
   */
  _finalizeScan(scanId) {
    const s = this.scans.get(scanId);
    if (!s) return;
    if (s.oobStarted) {
      try {
        oobReceiver.stop();
      } catch (e) {
        logger.warn(`OOB 接收端停止失败：${e.message}`);
      }
      s.oobStarted = false;
    }
    // 取消已存在的淘汰定时器（防止重复排定）
    const prev = this._evictTimers.get(scanId);
    if (prev) clearTimeout(prev);
    const timer = setTimeout(() => this._evictScan(scanId), this.scanRetentionMs);
    if (typeof timer.unref === 'function') timer.unref(); // 不阻塞 Node 进程退出
    this._evictTimers.set(scanId, timer);
    this._enforceScanLimit();
  }

  // 从内存淘汰某次扫描快照（completed/error/stopped 才可删除；running 保留）
  _evictScan(scanId) {
    this._evictTimers.delete(scanId);
    const s = this.scans.get(scanId);
    if (!s || s.status === 'running') return;
    this.scans.delete(scanId);
    eventBus.dispose(scanId); // 清理事件命名空间，避免 EventEmitter 泄漏
  }

  // 上限控制：超过 maxScans 时，按完成时间淘汰最旧的已完成/错误/停止扫描
  _enforceScanLimit() {
    const max = this.maxScans;
    if (!(max > 0) || this.scans.size <= max) return;
    const finished = [...this.scans.entries()]
      .filter(([, v]) => v.status !== 'running' && v.report && v.report.finishedAt)
      .sort((a, b) => new Date(a[1].report.finishedAt) - new Date(b[1].report.finishedAt));
    while (this.scans.size > max && finished.length > 0) {
      const [oldestId] = finished.shift();
      this._evictScan(oldestId);
    }
  }

  // 二阶注入补充趟：在既有一阶聚合之后运行，对"每个存储点 × 每个触发页"调用独立 SecondOrderDetector。
  // 门控（唯一硬门）：secondOrder.enabled && triggerUrls 非空 && 存在 isStorePoint 点；
  // 否则直接 return []（零写、对一阶零侵入）。命中结果复用既有 foundByPoint → 聚合去重 → riskOf 通道。
  async _runSecondOrder(scanId, target, points, dbms) {
    const so = (target.config && target.config.secondOrder) || {};
    if (!so.enabled) return []; // 未启用：直接跳过，对目标零写
    // 存储点来源：启发式 isStorePoint ∪ 手动指定（manualStorePoints 参数名列表）。
    // 手动指定的点运行时把 isStorePoint 置真，使报告/拓扑的存储点高亮与一阶识别点一致。
    const manualSet = new Set(Array.isArray(so.manualStorePoints) ? so.manualStorePoints : []);
    if (manualSet.size > 0) {
      for (const p of points) {
        if (p && manualSet.has(p.param)) p.isStorePoint = true;
      }
    }
    const storePoints = points.filter((p) => p && p.isStorePoint);
    if (storePoints.length === 0) return []; // 无存储点（含手动指定未命中任一参数）：跳过（发现器也需存储点才能确认触发页）

    // 触发页来源：手动 triggerUrls 优先；autoDiscover 在 enabled 且未手填时自动发现并经哨兵确认。
    // 注意：即便开启自动发现，也仅在"手填为空"时接管，避免覆盖用户显式指定的触发页。
    let triggerUrls = Array.isArray(so.triggerUrls)
      ? so.triggerUrls.filter((x) => typeof x === 'string' && /^https?:\/\//i.test(x))
      : [];
    if (so.autoDiscover && triggerUrls.length === 0) {
      const disc = await this.secondOrderDiscovery.run({ target, config: target.config, storePoints });
      triggerUrls = disc.confirmed;
      // 落报告 + 推送事件（供前端展示"自动发现结果"）；scan 不存在时静默跳过
      const storePointsLite = storePoints.map((p) => ({ param: p.param, storeKind: p.storeKind }));
      const sc = this.scans.get(scanId);
      if (sc) {
        sc.report.summary = sc.report.summary || {};
        sc.report.summary.secondOrderDiscovery = {
          candidates: disc.candidates,
          confirmed: disc.confirmed,
          storePoints: storePointsLite,
        };
      }
      eventBus.emit(scanId, 'second_order_discovery', {
        candidates: disc.candidates,
        confirmed: disc.confirmed,
        storePoints: storePointsLite,
      });
    }
    if (triggerUrls.length === 0) return []; // 无候选触发页（含自动发现无确认）：跳过

    // 告警：开启二阶检测即代表将对目标发起真实写请求（POST 注册/评论/资料）
    logger.warn(
      '二阶检测已开启：将对目标发起真实写请求（POST 注册/评论/资料），仅在你确认已授权目标时执行'
    );

    const collected = [];
    // 与一阶流水线一致：二阶趟也走扫描级 fork（独立限速/连接策略），避免污染全局单例
    const ctxBase = { httpClient: this.httpClient.fork(target.config), config: target.config };
    for (const point of storePoints) {
      const pointDbms = dbms || point.dbms; // 复用一阶已识别的 dbms（若有时）
      for (const triggerUrl of triggerUrls) {
        const ctx = { ...ctxBase, target, point, dbms: pointDbms, triggerUrl };
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
    return collected;
  }

  // 完整拖库（库→表→列→数据）
  async _extract(scanId, ctx) {
    const data = emptyExtractedData();
    try {
      const dbs = await this.extractor.enumerateDatabases(ctx);
      data.databases = dbs;
      // 库级并发拖库（受 dumpDatabaseConcurrency 约束），单库失败不影响整体
      // UNION 提取失败时自动 fallback 到堆叠深度提取（deepDump），并统计走了 fallback 的表
      const aggregated = await this.extractor.dumpAllDatabases(ctx, dbs, {
        fallback: (c, db, table, cols) => this.exploiter.deepDump(c, db, table, cols),
        onFallback: (t) => {
          data.meta = data.meta || {};
          (data.meta.deepDumpTables ||= []).push(t);
        },
      });
      data.tables = aggregated.tables;
      data.columns = aggregated.columns;
      data.rows = aggregated.rows;
      // 列类型枚举 + 进度推送（库数通常不多，保持串行遍历；类型枚举失败被吞）
      for (const db of dbs) {
        const tbls = aggregated.tables[db] || [];
        eventBus.emit(scanId, 'extraction_progress', { db, table: null, count: tbls.length });
        for (const table of tbls) {
          const cols = aggregated.columns[`${db}.${table}`] || [];
          data.columns[`${db}.${table}`] = cols;
          if (this.colTypeEnum) {
            const cacheKey = `${db}.${table}`;
            try {
              let typed = this._colTypeCache.get(cacheKey);
              if (!typed) {
                typed = await this.colTypeEnum.enumerate(ctx, db, table, cols);
                this._colTypeCache.set(cacheKey, typed);
              }
              data.columns[cacheKey] = typed.map((c) => `${c.name}:${c.type}`);
            } catch {
              /* 类型枚举失败不影响主流程 */
            }
          }
          const rowsArr = aggregated.rows[`${db}.${table}`] || [];
          data.rows[`${db}.${table}`] = rowsArr;
          eventBus.emit(scanId, 'extraction_progress', {
            db,
            table,
            count: rowsArr.length,
          });
        }
      }
    } catch (e) {
      logger.warn(`提取失败：${e.message}`);
    }
    return data;
  }

  _mergeExtracted(target, src) {
    if (!src) return;
    for (const db of src.databases) {
      if (!target.databases.includes(db)) target.databases.push(db);
    }
    for (const [k, v] of Object.entries(src.tables)) target.tables[k] = v;
    for (const [k, v] of Object.entries(src.columns)) target.columns[k] = v;
    for (const [k, v] of Object.entries(src.rows)) target.rows[k] = v;
  }

  _hasData(data) {
    return !!(
      (data.databases && data.databases.length) ||
      (data.tables && Object.keys(data.tables).length) ||
      (data.rows && Object.keys(data.rows).length)
    );
  }
}

export default ScanManager;
