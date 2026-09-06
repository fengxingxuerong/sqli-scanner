import { Scheduler } from '../services/Scheduler.js';
import { emptyExtractedData, createVulnerability } from './models.js';
import { defaults } from '../config/defaults.js';
import * as eventBus from '../core/eventBus.js';
import { ScanSession } from '../core/sessionStore.js';
import { oobReceiver } from '../core/oobReceiver.js';
import { logger } from '../core/logger.js';
import { urlHash, publicReport } from './ScanManager.js';
import { _colGuessCache } from './Extractor.js';
import { dialectToDbms } from './DialectSqlBuilder.js';
import { dnsCache } from '../core/httpClient.js';
import { verifyTamperChains } from '../core/waf/chainVerify.js';

// 暂停轮询间隔（ms）：扫描暂停时在点边界阻塞等待，避免忙等
const PAUSE_POLL_MS = 300;
// HTTP 请求日志节流间隔（ms）：同一扫描内 http_request 事件最少间隔，防 SSE 高峰期刷屏
const HTTP_LOG_THROTTLE_MS = 250;

/**
 * 扫描流水线主循环：发现注入点 → 预筛选 → 调度检测器 → 聚合漏洞 → 提取数据 → 生成报告。
 * 由 ScanManager._run 委托调用；全程经 EventBus 推送进度事件。
 * @param {import('./ScanManager.js').ScanManager} sm ScanManager 实例
 * @param {string} scanId 扫描 ID
 * @returns {Promise<void>}
 */
export async function runScanLoop(sm, scanId) {
    const s = sm.scans.get(scanId);
    if (!s) return;
    const { target, report } = s;
    // 按 scanId 注入扫描作用域 HttpClient（独立限速桶，前端 ratePerSec 生效）
    const rawClient = sm.getScanClient(scanId, target);
    // [请求日志] 包一层：请求完成后发 http_request 事件（节流 250ms，URL 脱敏）
    // 直连模式（DirectConnector 无 url 语义）跳过；前端 ProgressView 时间线展示
    const client = rawClient && typeof rawClient.request === 'function' ? rawClient : null;
    // [⑮] 扫描级 AbortSignal：stop() 时 abort，中断所有在途 HTTP 请求
    const scanSignal = sm.getSignal ? sm.getSignal(scanId) : null;
    const ctxBase = {
      httpClient: client && target.mode !== 'direct'
        ? {
            ...client,
            request: async (opts) => {
              // [⑮] 自动注入扫描级 signal，stop() 时中断在途请求
              const res = await client.request(scanSignal ? { ...opts, signal: scanSignal } : opts);
              const now = Date.now();
              if (now - (ctxBase._lastHttpLogTs || 0) >= HTTP_LOG_THROTTLE_MS) {
                ctxBase._lastHttpLogTs = now;
                try {
                  const u = new URL(opts.url || '');
                  u.search = '';
                  eventBus.emit(scanId, 'http_request', {
                    method: String(opts.method || 'GET').toUpperCase(),
                    url: `${u.protocol}//${u.host}${u.pathname}`,
                    status: res?.status ?? 0,
                    ms: typeof res?.__networkMs === 'number' ? Math.round(res.__networkMs) : undefined,
                  });
                } catch { /* URL 非法不发日志 */ }
              }
              return res;
            },
            // [sqlmap 对标] --null-connection：HEAD 请求也经扫描级 signal 注入 + 日志节流
            ...(typeof client.headRequest === 'function' ? {
              headRequest: async (url, opts) => {
                const res = await client.headRequest(url, scanSignal ? { ...opts, signal: scanSignal } : opts);
                const now = Date.now();
                if (now - (ctxBase._lastHttpLogTs || 0) >= HTTP_LOG_THROTTLE_MS) {
                  ctxBase._lastHttpLogTs = now;
                  try {
                    const u = new URL(url || '');
                    u.search = '';
                    eventBus.emit(scanId, 'http_request', {
                      method: 'HEAD',
                      url: `${u.protocol}//${u.host}${u.pathname}`,
                      status: res?.status ?? 0,
                      ms: typeof res?.__networkMs === 'number' ? Math.round(res.__networkMs) : undefined,
                    });
                  } catch { /* URL 非法不发日志 */ }
                }
                return res;
              },
            } : {}),
          }
        : rawClient,
      config: target.config,
      ...(scanSignal ? { signal: scanSignal } : {}),
    };

    // 1) 发现注入点（表单爬取为 async，需 await）
    // [P0-FIX] 传入 per-scan httpClient（rawClient），使爬取/表单探测也走 per-scan 限速桶
    eventBus.emit(scanId, 'scan_phase', { phase: 'discovering', message: '正在发现注入点…' });
    const points = await sm.parser.discover(target, rawClient);
    report.points = points;
    eventBus.emit(scanId, 'point_discovered', { points });

    // 会话持久化（对标 sqlmap --session/--resume）：
    // 若配置给出 sessionFile 且文件存在 → 恢复历史（resume 模式，跳过已完成点）；否则新建会话。
    // P2-P4：config.sessionDefault=true 时无显式 sessionFile 也自动落盘到按目标 URL 哈希
    // 派生的文件名（sqli-session-<urlHash8>.json），避免不同目标并发扫描互踩同一固定文件；
    // 同一目标复扫仍可命中相同文件名实现 resume（复扫近 0 请求）。
    const cfg = target.config || {};
    // --fresh-queries：清空所有查询缓存（列数猜解缓存、DNS 缓存）
    // 确保每次扫描都从零开始，不依赖历史缓存结果
    if (cfg.freshQueries) {
      _colGuessCache.clear();
      if (dnsCache && typeof dnsCache.clear === 'function') dnsCache.clear();
      // [P0-FIX] freshQueries 也需跳过会话恢复：用户期望全新扫描而非 resume 跳过已完成点。
      // 故下方 sessionFile 即使存在也不加载，改为新建会话（与 sqlmap --flush-session 语义对齐）。
      // 由于 sessionFile 继续保留，后续扫描可 resume，但本次扫描强制从零开始。
    }
    // … 会话持久化（对标 sqlmap --session/--resume）
    // 需注意在 freshQueries 模式下跳过 session restore（上面已标记），但 sessionFile 仍可
    // 用于落盘（即本次扫描结果仍落盘，但不会从历史恢复）。
    const sessionDefault = cfg.sessionDefault === true && target.mode !== 'direct';
    const sessionFile = cfg.sessionFile || (sessionDefault ? `sqli-session-${urlHash(target.baseUrl || target.url)}.json` : null);
    const sessionUrl = target.baseUrl || target.url || null;
    let session = null;
    let restored = null;
    // 如果 freshQueries 启用，跳过会话文件加载（强制全新扫描）：
    // 不恢复历史，但保留 sessionFile 供本次结果落盘（后续扫描可 resume 本次进度）。
    if (cfg.freshQueries) {
      if (sessionFile) {
        session = new ScanSession(scanId, { url: sessionUrl, config: target.config }, sessionFile);
        await session.setPoints(points).catch(() => null);
      }
    } else if (sessionFile) {
      const loaded = await ScanSession.load(sessionFile).catch(() => null);
      // sessionDefault 模式：仅当历史会话 URL 与当前目标一致才 resume（避免跨目标误续跑旧点）
      if (loaded && (!sessionDefault || (sessionUrl && loaded.url === sessionUrl))) {
        restored = loaded;
        session = restored;
        logger.info(`会话恢复：${restored.pendingPointIds().length} 个未完成点待续跑，已合并 ${restored.vulns.length} 条历史命中`);
      } else {
        session = new ScanSession(scanId, { url: sessionUrl, config: target.config }, sessionFile);
      }
      // await 落盘：setPoints 内部是异步 _flush，若 fire-and-forget，扫描/测试结束后
      // 迟到的写盘会重建会话文件（曾导致 phase3.sessionDefault 测试偶发竞态失败）。
      await session.setPoints(points).catch(() => null);
    }

    // P2-P1 参数预筛选（性能）：完整检测前对每个注入点发 1-2 个廉价探测（单引号报错 + 时间向量），
    // 明显无注入迹象的参数点直接跳过完整检测（省 50-75% 请求）。默认开启（config.prefilter !== false）。
    // 保守策略：任一探测出现信号（响应明显偏离基线 / 触发延迟）即保留做完整检测；探测失败（网络/超时）
    // 一律保守保留，绝不因探测失败漏检。预筛选不改变报告 point 列表（report.points 仍是全部点），
    // 仅决定哪些点进入完整检测循环。resume 模式：已完成点不参与本轮（避免重复请求）。
    // 仅对多参数目标生效：单参数点直接完整检测（探测相对收益低，且避免单点上多余 RTT/请求开销）。
    let pointsToScan = session
      ? points.filter((p) => !(session.perPoint[p.id] && session.perPoint[p.id].status === 'done'))
      : points;
    // [B-perf] skip-static 参数预筛选（对标 sqlmap --skip-static，opt-in config.skipStatic === true）：
    // a) 同值去重——原始值完全相同的参数只测第一个（零请求成本）；
    // b) 哨兵探测——每参数发 1 次明显不同的哨兵值请求，与基线响应比对（状态码 + 长度 +
    //    规范化正文全部一致且哨兵值未回显）→ 判定静态参数，跳过该点完整检测。
    // 每点 1 请求换 46+ 请求/点的完整检测预算；判定保守（任一维度有差异/探测失败 → 照常检测），
    // 精确标记点（* 指定）不参与跳过。先于 prefilter 跑（更廉价：1 req/点 vs 3 req/点），
    // 静态点连预筛选探测也省掉。默认关闭（skipStatic !== true 时零行为变化）。
    if (cfg.skipStatic === true && pointsToScan.length > 1) {
      const candidate = await sm._skipStaticPoints(ctxBase, target, pointsToScan);
      const skipped = pointsToScan.filter((p) => !candidate.includes(p));
      for (const p of skipped) {
        eventBus.emit(scanId, 'point_skipped', { pointId: p.id, reason: 'static' });
      }
      if (skipped.length) {
        logger.info(
          `skip-static 跳过 ${skipped.length}/${pointsToScan.length} 个静态参数点（同值去重 + 哨兵探测）`
        );
        // 跳过点记入会话（resume 不再重测；不产生漏洞），落盘失败不阻断主流程
        if (session) {
          await Promise.all(skipped.map((p) => session.savePointResult(p.id, { found: [] }).catch(() => null)));
        }
      }
      pointsToScan = candidate;
    }
    if (cfg.prefilter !== false && pointsToScan.length > 1) {
      const candidate = await sm._prefilterPoints(ctxBase, target, pointsToScan);
      const skipped = pointsToScan.filter((p) => !candidate.includes(p));
      if (skipped.length) {
        logger.info(
          `预筛选跳过 ${skipped.length}/${pointsToScan.length} 个无注入迹象参数点（省完整检测请求）`
        );
        // 跳过点记入会话（resume 不再重测；不产生漏洞），落盘失败不阻断主流程
        if (session) {
          await Promise.all(skipped.map((p) => session.savePointResult(p.id, { found: [] }).catch(() => null)));
        }
      }
      pointsToScan = candidate;
    }

    // 2) 调度每个注入点（并发池 + 令牌桶限速 + 重试）
    eventBus.emit(scanId, 'scan_phase', { phase: 'detecting', message: `正在检测 ${pointsToScan.length} 个注入点…` });
    const scheduler = new Scheduler(target.config.concurrency, target.config.ratePerSec);
    // pointId -> { point, ctx, found:[{technique, result}] }
    const foundByPoint = new Map();
    const extracted = emptyExtractedData();
    // WAF 指纹聚合（跨注入点去重，按 vendor 保留最高置信度）；识别数据来自指纹基线，零额外发包
    const wafAgg = new Map();
    // 指纹共享缓存（按目标 key，存 Promise）：同目标多注入点只跑一次指纹，省 8-9 请求/点
    const fpCache = new Map();
    let dbms = null;
    // [P1-FIX 2026-09-05] 解析出的 DBMS 版本（{major,minor,raw} | null），供 ctx/payload 过滤消费
    let dbmsVersion = null;
    // WAF 重跑共享基线：指纹阶段抓取的 baseline 响应（status/headers/body）供 retry 复用
    let sharedBaseline = null;
    const selectedTechs = sm._selectedTechs(target.config);
    const stackedSelected = selectedTechs.includes('stacked');

    // OOB 带外接收端：仅当 oob 被选中且显式 enabled 时启动（默认关闭，避免意外出站带外）
    const oobCfg = target.config.oob;
    if (selectedTechs.includes('oob') && oobCfg && oobCfg.enabled) {
      try {
        await oobReceiver.start(oobCfg);
      } catch (e) {
        logger.warn(`OOB 接收端启动失败，oob 检测将不可用：${e.message}`);
      }
    }

    await scheduler.run(pointsToScan, async (point) => {
      if (s.cancelled) return;
      // [P0-FIX] 暂停等待：扫描暂停时在点边界阻塞（不终止请求、不回收上下文），
      // 等待 resume 或 stop。轮询间隔 PAUSE_POLL_MS，避免忙等。
      while (s.paused && !s.cancelled) {
        await new Promise((resolve) => setTimeout(resolve, PAUSE_POLL_MS));
      }
      if (s.cancelled) return;
      // resume 模式：已完成点跳过（节省请求，恢复历史扫描进度）
      if (session && session.perPoint[point.id] && session.perPoint[point.id].status === 'done') {
        eventBus.emit(scanId, 'point_skipped', { pointId: point.id, reason: 'resume-done' });
        return;
      }

      // [⑳] direct 模式：从驱动 dialect 直接映射 DBMS，作为指纹识别 fallback。
      // DirectConnector 不走 HTTP，响应头识别必然失败 → 原先死回退 MySQL。
      // 现在优先从 driver.dialect 映射正确 DBMS，指纹识别仍跑（猜列数/baseline），但 dbms=null 时回落到 dialect。
      let dialectDbms = null;
      if (target.mode === 'direct' && rawClient && typeof rawClient.getDialect === 'function') {
        try {
          const dialect = await rawClient.getDialect();
          if (dialect) {
            dialectDbms = dialectToDbms(dialect);
            if (dialectDbms) {
              point.dbms = dialectDbms;
              dbms = dialectDbms;
            }
          }
        } catch { /* dialect 获取失败，留给指纹识别处理 */ }
      }
      // [Phase6-FIX] 仅当一阶技术被选中时才执行指纹识别/boundary 探测——
      // 二阶-only 扫描无需指纹/boundary，且这些步骤会向存储点发 ORDER BY payload，
      // 污染二阶靶场的 stored value，导致二阶检测器 baseline 已含报错而判定失败。
      const _hasFirstOrder = selectedTechs.some(t => ['union', 'error', 'boolean', 'time', 'stacked', 'inline'].includes(t));
      // [sqlmap 对标] --dbms：用户显式指定 DBMS 时跳过指纹识别（省 8-9 请求/点 + 语义确定），
      // 直接按指定库构造 payload/提取语句。指纹阶段仅在不指定时运行。
      const forcedDbms = (cfg.dbms && String(cfg.dbms).trim()) || null;
      // 指纹识别（返回 { dbms, baseline }，baseline 供 WAF 识别复用）。
      // 同目标多注入点共享：首点跑完整指纹（8-9 请求），后续点命中缓存零额外指纹请求。
      let fpResult = null;
      if (_hasFirstOrder && !forcedDbms) {
        fpResult = await sm._fingerprintCached(fpCache, ctxBase, target, point);
      }
      let detectedDbms = forcedDbms || (fpResult && fpResult.dbms);
      // [⑳] 指纹识别未命中时，回落到 direct 模式 dialect 映射的 DBMS（避免死回退 MySQL）
      if (!detectedDbms) detectedDbms = dialectDbms;
      // [P1-1] 保存 baseline 供 WAF 重跑复用（fpResult.baseline 零额外发包抓取的基线响应）
      if (fpResult && fpResult.baseline) sharedBaseline = fpResult.baseline;
      if (detectedDbms) {
        point.dbms = detectedDbms;
        dbms = detectedDbms;
      }
      // [P1-FIX 2026-09-05] 版本流转：指纹解析出的版本挂到 ctx（点级共享），供
      // payloadRegistry 版本过滤与 extractionMaps 版本分支消费（未知版本为 null）
      if (fpResult && fpResult.version) {
        point.dbmsVersion = fpResult.version;
        dbmsVersion = fpResult.version;
      }
      // WAF 指纹识别：复用指纹阶段已抓取的基线响应（status/headers/body），零额外发包
      const wafCands = sm.wafIdentifier.identify((fpResult && fpResult.baseline) || {});
      for (const c of wafCands) {
        const prev = wafAgg.get(c.vendor);
        if (!prev || c.confidence > prev.confidence) wafAgg.set(c.vendor, c);
      }
      // [sqlmap 对标] 主动 WAF 探测：被动识别无果且 config.activeWafProbe 开启时，
      // 主动发送 WAF 触发 payload 观察拦截响应以识别厂商。仅 direct 模式外触发。
      if (wafCands.length === 0 && cfg.activeWafProbe === true && target.mode !== 'direct') {
        try {
          const probeResult = await sm.wafIdentifier.activeProbe(target, ctxBase.httpClient);
          if (probeResult.detected) {
            const vendor = probeResult.vendor || 'unknown';
            wafAgg.set(vendor, { vendor, confidence: probeResult.confidence, evidence: 'active probe' });
            logger.info(`主动 WAF 探测命中：${vendor}（confidence=${probeResult.confidence}）`);
          }
        } catch (e) {
          logger.warn(`主动 WAF 探测失败：${e.message}`);
        }
      }
      // 闭合上下文探测（对标 sqlmap boundary）：识别引号/括号闭合前缀，写入 point.boundary。
      // 仅对经典 SQLi 技术启用（union/error/boolean/time/stacked/inline），二阶/NoSQL 补充趟不消费。
      // 探测结果复用于后续提取阶段（Extractor 也按 boundary 拼闭合前缀）。
      if (_hasFirstOrder && point.boundary == null && !point.boundaryProbed) {
        point.boundaryProbed = true;
        try {
          // 用构造函数名查找 UnionDetector（避免依赖 detectors[0] 构造顺序）
          const unionDetector = sm.detectors.find(d => d.constructor.name === 'UnionDetector' || d.constructor.name === 'Detector');
          if (!unionDetector) throw new Error('未找到 UnionDetector');
          point.boundary = await unionDetector.probeBoundary({
            ...ctxBase,
            target,
            point,
            dbms: detectedDbms || point.dbms,
          });
        } catch {
          point.boundary = '';
        }
      }

      const ctx = {
        ...ctxBase,
        target,
        point,
        dbms: detectedDbms || point.dbms,
        // [P1-FIX 2026-09-05] 版本随 ctx 下发（点级，跨检测器/提取器共享）
        dbmsVersion: point.dbmsVersion || dbmsVersion || null,
        // 同点共享基线：后续检测器/提取器可消费此字段复用，避免各自重测 baseline
        baseline: (fpResult && fpResult.baseline) || null,
        extractor: sm.extractor,
        // scanId 透传给 Extractor：盲注常见值缓存（predictOutput）按 scanId+target 维度隔离
        scanId,
        // [Feature 4] session 透传给 Extractor：dumpData 行级断点续传
        session: session || null,
      };

      // 检测器调度：分两层并行，兼顾「经典技术快速抢断省请求」与「慢速采样(time/stacked/oob)并行提速」。
      // 层1 快速回显/布尔层：union / error / boolean / inline —— 这些命中即典型注入，命中后（stacked 未选时）无需再跑慢速层，省请求。
      // 层2 慢速采样层：time / stacked / oob —— 各自需多次采样或独立确认，彼此无依赖，层内并行（墙钟≈单检测器耗时而非累加）。
      // 仅当 stacked 也被选中时，即使层1命中仍跑层2（确保末位 stacked 能独立确认）。
      // 注意：runLayer 仅执行 FAST/SLOW 数组内的技术；任何新加的 SQLi 技术必须加入二者之一，否则不会被调度（inline 即如此接入）。
      const FAST = ['union', 'error', 'boolean', 'inline'];
      const SLOW = ['time', 'stacked', 'oob'];
      const active = sm.activeDetectors(target.config);
      const runLayer = async (techniques) => {
        const inLayer = active.filter((d) => techniques.includes(d.technique));
        const results = await Promise.all(
          inLayer.map(async (detector) => {
            eventBus.emit(scanId, 'point_testing', { pointId: point.id, technique: detector.technique });
            try {
              const result = await detector.detect(ctx);
              return { technique: detector.technique, result, vulnerable: !!result?.vulnerable };
            } catch (e) {
              logger.warn(`检测器 ${detector.technique} 失败：${e.message}`);
              return { technique: detector.technique, result: null, vulnerable: false };
            }
          })
        );
        return results.filter((r) => r.vulnerable);
      };

      const found = [];
      // 层1：快速层并行
      const fastHits = await runLayer(FAST);
      found.push(...fastHits);
      const fastConfirmed = fastHits.length > 0;
      // 是否还需跑慢速层：未命中、或 stacked 被选中（需独立确认）→ 跑层2；否则省去慢速层请求
      const needSlow = !fastConfirmed || stackedSelected;
      if (needSlow && !s.cancelled) {
        const slowHits = await runLayer(SLOW);
        found.push(...slowHits);
      }
      if (found.length) foundByPoint.set(point.id, { point, ctx, found });
      // 单点检测+提取完成后落盘（增量持久化，支持断点续拉）。
      // 必须 await：savePointResult 内部是异步写盘，若 fire-and-forget，扫描完成后
      // 写盘可能仍在进行——测试/调用方在扫描结束后清理会话文件会被迟到的写盘重新创建
      // （曾导致 phase3.sessionDefault 测试偶发竞态失败）。
      if (session) await session.savePointResult(point.id, { found: found.map((f) => ({ technique: f.technique, result: f.result })) }).catch(() => null);
    }, 0); // [MERGED: perf] retry=0：单请求重试归 HttpClient 统一负责，避免双重放大为 (retry+1)² 次物理请求

    // 3.4) WAF 自动 tamper 重跑（P1-D5）：识别到高置信 WAF 且用户未显式配置 tamper 时，
    // 对「未命中点」套用 wafRecommend 推荐链重跑快速层（union/error/boolean），受节流控制。
    // 不覆盖用户显式选择；仅在默认配置下自动兜底，提升 WAF 目标召回。
    // [MERGED: engine ★FIX-3] 统一经 shouldAutoRetry 门控（原实现忽略了
    // defaults.wafEvasion.autoRetry=false 的默认开关，WafIdentifier.shouldAutoRetry 成死代码）。
    const wafVendorsPre = [...wafAgg.values()].sort((a, b) => b.confidence - a.confidence);
    const autoRetryEnabled = sm.wafIdentifier.shouldAutoRetry
      ? sm.wafIdentifier.shouldAutoRetry(wafVendorsPre, target.config)
      : wafVendorsPre.some((v) => v.confidence >= 0.8); // 兼容未注入桩的构造
    const highConfWaf = autoRetryEnabled ? wafVendorsPre.find((v) => v.confidence >= 0.8) : null;
    if (highConfWaf && !s.cancelled) {
      const suggestions = sm.wafRecommend(wafVendorsPre);
      // [P1-FIX 2026-09-05] 链动态验证（从"猜链"到"验链"）：候选链逐条发轻量探针实测是否被拦截，
      // 取首条放行的链；全部被拦则跳过重跑（省掉注定失败的整轮检测请求）。
      // 验证异常 → 保守回退 suggestions[0]（对齐旧行为，验证器故障不削弱重跑）。
      let plugins = null;
      const verifyPoint = pointsToScan.find((p) => !foundByPoint.has(p.id)) || pointsToScan[0];
      if (verifyPoint && suggestions.length) {
        plugins = (await verifyTamperChains({
          httpClient: sm.getScanClient(scanId, target),
          target,
          point: verifyPoint,
          chains: suggestions,
          config: target.config || {},
        }))?.plugins ?? null;
      } else {
        plugins = suggestions[0] && suggestions[0].plugins;
      }
      if (plugins && plugins.length) {
        const retryConfig = {
          ...target.config,
          wafEvasion: {
            ...(target.config.wafEvasion || {}),
            tamper: { enabled: true, plugins: [...plugins], intensity: 'medium' },
          },
        };
        const retryCtxBase = { httpClient: sm.getScanClient(scanId, target), config: retryConfig };
        const retryPoints = pointsToScan.filter((p) => !foundByPoint.has(p.id));
        if (retryPoints.length) {
          logger.info(
            `WAF 识别（${highConfWaf.vendor}），自动套 tamper [${plugins.join(',')}] 重跑 ${retryPoints.length} 个未命中点（快速层）`
          );
          await scheduler.run(retryPoints, async (point) => {
            if (s.cancelled) return;
            const rctx = {
              ...retryCtxBase,
              target,
              point,
              dbms: point.dbms || dbms,
              extractor: sm.extractor,
              baseline: sharedBaseline, // [P1-1] WAF 重跑携带 baseline，防检测器重复基线请求
            };
            const fast = sm.activeDetectors(retryConfig).filter((d) =>
              ['union', 'error', 'boolean'].includes(d.technique)
            );
            const results = await Promise.all(
              fast.map(async (detector) => {
                eventBus.emit(scanId, 'point_testing', { pointId: point.id, technique: detector.technique, tamperRetry: true });
                try {
                  const result = await detector.detect(rctx);
                  return { technique: detector.technique, result, vulnerable: !!result?.vulnerable };
                } catch (e) {
                  logger.warn(`WAF 重跑检测器 ${detector.technique} 失败：${e.message}`);
                  return { technique: detector.technique, result: null, vulnerable: false };
                }
              })
            );
            const hits = results.filter((r) => r.vulnerable);
            if (hits.length) foundByPoint.set(point.id, { point, ctx: rctx, found: hits });
          }, 0); // [MERGED: perf] retry=0：同主循环，单请求重试归 HttpClient
        }
      }
    }

    // 3) 聚合 + 去重（同点 stacked 命中 → 仅留 1 条 stacked(Critical)，其余移入印证）
    const finalVulns = [];
    const corroborations = [];
    for (const { point, found } of foundByPoint.values()) {
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
            : sm.reportGen.riskOf([
                createVulnerability(point.id, f.technique, 'Medium', f.result.payloads, f.result.evidence, f.result.trace),
              ]);
        const vuln = createVulnerability(point.id, f.technique, risk, f.result.payloads, f.result.evidence, f.result.trace);
        vuln.dbms = f.result.dbms;
        // [G4 对标 sqlmap --parse-errors] 透传错误详情（opt-in）：错误原文/上下文/SQL 片段
        if (f.result.errorDetail) vuln.errorDetail = f.result.errorDetail;
        finalVulns.push(vuln);
        eventBus.emit(scanId, 'detection_found', { ...f.result, riskLevel: risk });
      }
    }

    // [MERGED: engine ★FIX-1] 用户已 stop()：不再发起任何新的检测/写请求。聚合（纯内存）已完成，
    // 此处直接收尾，保持 status='stopped'。原实现会继续跑二阶段/NoSQL/提取，且最终把 status
    // 覆盖为 'completed'——二阶检测在用户中止后仍会对目标发起真实写请求（POST 注册/评论），
    // 这是安全与一致性的双重问题。
    if (s.cancelled) {
      report.vulns = finalVulns;
      report.summary.stackedEnabled = stackedSelected;
      report.summary.stackedCorroborations = corroborations;
      report.riskLevel = sm.reportGen.riskOf(finalVulns);
      report.dbms = dbms;
      report.finishedAt = new Date().toISOString();
      if (session) await session.finalize(report).catch(() => {});
      eventBus.emit(scanId, 'scan_stopped_finalized', { scanId, vulns: finalVulns });
      await sm._maybeClose(ctxBase.httpClient);
      sm._retire(scanId);
      return;
    }

    // 3.5) 二阶补充趟：在一阶聚合之后运行，并入同一 finalVulns（门控 + 独立实例，对一阶零侵入）
    const soVulns = await sm._runSecondOrder(scanId, target, points, dbms);
    for (const v of soVulns) finalVulns.push(v);

    // 3.6) 非 SQL 注入补充趟（NoSQL/GraphQL/SSTI）：门控 noSql.enabled 才跑，对无此类后端的
    // 目标默认关闭以避免噪音；命中并入同一 finalVulns（与二阶同通道，opt-in 独立趟）。
    const noSqlVulns = await sm._runNoSql(scanId, target, points, dbms);
    for (const v of noSqlVulns) finalVulns.push(v);

    // 4) 提取：仅对最终保留的漏洞做（union/error 拖库；boolean/time 版本证明）。
    // 点间并行（T3）：不同注入点的提取任务并发执行，并行度受 extractConcurrency 约束；
    // 实际发包速率仍被 HttpClient 令牌桶 + Scheduler 统一限速，不放大对目标压力到危险程度。
    const extractTasks = [];
    for (const { point, ctx } of foundByPoint.values()) {
      const vuln = finalVulns.find((v) => v.pointId === point.id);
      if (!vuln) continue;
      extractTasks.push({ point, ctx, vuln });
    }
    if (target.config.enableExtract) {
      const extractConcurrency = Math.max(1, target.config.extractConcurrency || defaults.extractConcurrency);
      await sm._mapPool(extractTasks, async ({ point, ctx, vuln }) => {
        // [MERGED: engine ★FIX-1] 兜底：提取期间用户 stop()，立即停止剩余提取请求
        if (s.cancelled) return;
        if (vuln.technique === 'union' || vuln.technique === 'error') {
          eventBus.emit(scanId, 'scan_phase', { phase: 'extracting', message: `正在从 ${point.dbms || '数据库'} 提取数据…` });
          const exData = await sm._extract(scanId, ctx);
          sm._mergeExtracted(extracted, exData);
        } else if (vuln.technique === 'boolean') {
          const proof = await sm.extractor.extractProof(ctx);
          if (proof) {
            eventBus.emit(scanId, 'extraction_progress', {
              db: point.dbms,
              table: null,
              count: 1,
              // P2-P7：完整值投票复验未通过时注明低置信（提取值仍可用，需人工复核）
              confidence: ctx.extractConfidence === 'low' ? 'low' : 'high',
              note: `盲注二分提取版本：${proof}${ctx.extractConfidence === 'low' ? '（低置信：完整值复验未通过）' : ''}`,
            });
          }
        } else if (vuln.technique === 'time') {
          // 时间盲注独立提取通道：优先走时间判定，无标量延迟原语的库降级布尔通道。
          // 可选链调用保证老 extractor 桩（仅实现 extractProof）零回归。
          const proof =
            (typeof sm.extractor.extractTimeProof === 'function'
              ? await sm.extractor.extractTimeProof(ctx)
              : null) || (await sm.extractor.extractProof(ctx));
          if (proof) {
            eventBus.emit(scanId, 'extraction_progress', {
              db: point.dbms,
              table: null,
              count: 1,
              confidence: ctx.extractConfidence === 'low' ? 'low' : 'high',
              note: `时间盲注提取版本：${proof}${ctx.extractConfidence === 'low' ? '（低置信：完整值复验未通过）' : ''}`,
            });
          }
        } else if (vuln.technique === 'inline') {
          // 内联提取（对标 sqlmap Q）：把标量子查询注入值位置，期待回显点把结果带出。
          // 无回显点时 extractInlineProof 返回 null（本工具不重建查询模板，故回退到盲注通道由其它技术覆盖）。
          const proof = await sm.extractor.extractInlineProof(ctx);
          if (proof) {
            eventBus.emit(scanId, 'extraction_progress', {
              db: point.dbms,
              table: null,
              count: 1,
              note: `内联查询提取版本：${proof}`,
            });
          }
        }
      }, extractConcurrency);
    }

    // 5) 汇总报告并定级
    report.vulns = finalVulns;
    // resume 模式：合并历史会话已落盘的命中（已完成点本次被跳过不重测，但结论须保留在报告中）
    if (restored) {
      for (const v of restored.vulns) {
        if (!report.vulns.some((x) => x.pointId === v.pointId && x.technique === v.technique)) {
          report.vulns.push(createVulnerability(v.pointId, v.technique, 'Medium', [], `[resume] 历史会话命中`, null));
        }
      }
    }
    report.data = target.config.enableExtract ? extracted : null;
    // [P0-FIX] resume 模式：合并历史会话已落盘的提取数据（拖库断点续跑不丢已拉数据）。
    // 已完成点本次跳过不重提取，但历史库/表/列/行结论须合并回报告，保证数据证据链完整。
    if (restored && restored.extracted) {
      report.data = sm._mergeExtractedForResume(report.data, restored.extracted);
    }
    // [P0-FIX] 增量落盘：提取数据写入会话（供下次 resume 合并），落盘失败不阻断主流程
    if (session) {
      try { session.extracted = report.data; await session.setExtracted(report.data); } catch { /* 落盘失败不阻断 */ }
    }
    report.summary.stackedEnabled = stackedSelected;
    report.summary.stackedCorroborations = corroborations;
    const hasData = sm._hasData(extracted);
    report.riskLevel = hasData ? 'Critical' : sm.reportGen.riskOf(finalVulns);
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
      const suggestions = sm.wafRecommend(wafVendors);
      eventBus.emit(scanId, 'waf_detected', { vendors: wafVendors, suggestions });
      report.summary = report.summary || {};
      report.summary.wafDetected = wafVendors;
    }
    // 会话落盘收尾（resume 模式可用同一 sessionFile 续跑/复核）：必须先 finalize 落盘完成，再置 completed，
    // 避免 resume 端在 status=completed 后、落盘前抢读到一个 vulns 为空的半成品会话。
    if (session) await session.finalize(report).catch(() => {});
    s.status = 'completed';
    // [MERGED: security] scan_completed 事件脱敏：SSE 不再携带 target 凭据
    eventBus.emit(scanId, 'scan_completed', publicReport(report));
    await sm._maybeClose(ctxBase.httpClient);
    // completed 路径回收扫描上下文（TTL 到期清 scans + eventBus + 限速桶）
    sm._retire(scanId);
}
