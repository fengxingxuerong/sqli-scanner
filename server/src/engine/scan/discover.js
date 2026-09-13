// ============================================================================
// scan/discover.js —— 发现注入点 + 点位准备（原 scanRunner.runScanLoop 阶段 1）
//
// 从 runScanLoop 中搬出（2026-09-12 拆分第三批 3a）。**纯搬移，行为不变**。
//
// 职责：
//   ① parser.discover 发现注入点（表单爬取为 async）+ 空点位显式告警（防静默假阴性）
//   ② 会话持久化（--session/--resume）：freshQueries 跳过恢复但仍落盘
//   ③ 点位准备（先于 skip-static/prefilter）：knownPoint 直通 + invalidValue 失效值替换
//   ④ 三层廉价跳过（各自 opt-in，保守语义一致：探针失败一律保留完整检测）：
//      skip-static 哨兵探测 → prefilter 参数预筛选 → validationSkip 输入校验型可证安全
//
// ⚠️ cfg 改由主函数上移传入（本模块内不再自建）：它在阶段 2/3.4 也被使用，
//    留在本模块会导致下游拿不到。原 cfg 定义行已从搬移体移除。
// ============================================================================
import * as eventBus from '../../core/eventBus.js';
import { logger } from '../../core/logger.js';
import { ScanSession } from '../../core/sessionStore.js';
import { urlHash } from '../scanHelpers.js';
import { _colGuessCache } from '../Extractor.js';
import { dnsCache } from '../../core/httpClient.js';
import { applyInvalidValues } from '../invalidValue.js';
import { applyKnownPoints } from '../knownPoint.js';

/**
 * @param {object} run 扫描运行期上下文（需含 sm/scanId/target/cfg/ctxBase/rawClient/report）
 * @returns {Promise<{points: Array, pointsToScan: Array, session: object|null, restored: object|null}>}
 */
export async function discoverPoints(run) {
  const { sm, scanId, target, cfg, ctxBase, rawClient, report } = run;


    // 1) 发现注入点（表单爬取为 async，需 await）
    // [P0-FIX] 传入 per-scan httpClient（rawClient），使爬取/表单探测也走 per-scan 限速桶
    eventBus.emit(scanId, 'scan_phase', { phase: 'discovering', message: '正在发现注入点…' });
    const points = await sm.parser.discover(target, rawClient);
    report.points = points;
    eventBus.emit(scanId, 'point_discovered', { points });

    // [本期新增] 空注入点显式告警（防静默假阴性）：解析出 0 个注入点时不再静默输出 Low 风险，
    // 而是在 summary 明确告知用户如何开启更多注入面。此前 0 注入点会直接走到「无漏洞」结论，
    // 把「根本没测」（不带 query 参数、未测请求头/ path 段）误读成「测了且安全」。
    if (!points.length) {
      report.summary = report.summary || {};
      report.summary.noInjectionPoints = true;
      report.summary.noInjectionPointsHint =
        '未发现任何可测参数：目标 URL 无 query 参数，且未启用请求头/ path 段注入点。' +
        '如需测试请求头注入请加 --test-headers，测试 URL path 末段注入请加 --test-path。';
    }

    // 会话持久化（对标 sqlmap --session/--resume）：
    // 若配置给出 sessionFile 且文件存在 → 恢复历史（resume 模式，跳过已完成点）；否则新建会话。
    // P2-P4：config.sessionDefault=true 时无显式 sessionFile 也自动落盘到按目标 URL 哈希
    // 派生的文件名（sqli-session-<urlHash8>.json），避免不同目标并发扫描互踩同一固定文件；
    // 同一目标复扫仍可命中相同文件名实现 resume（复扫近 0 请求）。
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
    // [P0 2026-09-09 实战批次] 点位准备（先于 skip-static/prefilter）：
    // ① knownPoint 直通：手工确认的可注入参数跳过预筛选与闭合探测（闭合形态由使用者给定）；
    // ② invalidValue 失效值替换：有效值 → 随机大数/恒真逻辑式/随机串，规避缓存页/静态页噪声。
    // 两者都直接改写点对象 → 探测/检测/提取全链路统一生效。
    const knownHits = applyKnownPoints(pointsToScan, cfg);
    if (knownHits) {
      logger.info(`已知注入点直通：${knownHits}/${pointsToScan.length} 个点跳过预筛选与闭合探测（config.knownPoint）`);
    }
    const invalidCount = applyInvalidValues(pointsToScan, cfg);
    if (invalidCount) {
      logger.info(`失效值替换已应用（invalidValue=${cfg.invalidValue}）：${invalidCount} 个点的有效值已替换（缓存/静态页噪声规避）`);
    }
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
    // [perf-FIX 2026-09-07] 单点目标 opt-in 预筛选：原「仅多参数目标生效」使单参数无注入目标
    // （如 fp_strict/fp_noecho/fp_json e2e 场景）必须跑完 ~205 个完整检测请求。新增
    // config.prefilterSinglePoint=true（默认关闭，零回归）：单点也走廉价预筛选探测
    // （基线 RTT + 4 探针 ≈ 5 请求 vs 205 请求）。注意保守语义不变：任一探针有信号/
    // 失败/超时 → 保留完整检测。静默型技术（stacked-only / second-order-only 单技术
    // 扫描）不适用单点预筛选（探针无信号会误跳过），调用方自行权衡；多参数目标行为不变。
    if (cfg.prefilter !== false && (pointsToScan.length > 1 || cfg.prefilterSinglePoint === true)) {
      const candidate = await sm._prefilterPoints(ctxBase, target, pointsToScan);
      const skipped = pointsToScan.filter((p) => !candidate.includes(p));
      if (skipped.length) {
        // [P1-AUDIT 2026-09-08] 跳过必须在报告里留痕：报告只留 point 列表会让「没测」看起来像
        // 「测了且无漏洞」，无法审计也无法复现（给点打 skipReason，不改变 points 集合本身）。
        for (const p of skipped) p.skipReason = 'prefilter';
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

    // [P1-PERF 2026-09-08 实战批次] 单参数目标的「输入校验型可证安全跳过」。
    // 上面预筛选对单点目标是 opt-in（prefilterSinglePoint）——因为「探针无信号」不足以在唯一
    // 的点上做跳过决定。本块用更强的判据（良性非法值 + 两路恒真串必须同构被拒且无 SQL 报错签名）
    // 把「参数在进 SQL 前就被白名单拦死」这类目标从 200+ 请求压到 5 请求：
    // 实战意义不只是省时间——少打 200 个无效攻击特征就不会把出口 IP 送进 WAF 黑名单，
    // 也不会把客户生产应拖到慢。默认开启，config.validationSkip=false 可关。
    // 仅当：预筛选未接管本目标（单点且未开 prefilterSinglePoint）+ 技术集含可回显类技术时生效。
    const _hasEchoTech = (cfg.techniques || []).some((t) => ['union', 'error', 'boolean', 'time', 'inline'].includes(t));
    const prefilterTookOver =
      cfg.prefilter !== false && (points.length > 1 || cfg.prefilterSinglePoint === true);
    if (
      cfg.prefilter !== false &&
      cfg.validationSkip !== false &&
      !prefilterTookOver &&
      _hasEchoTech &&
      pointsToScan.length > 0 &&
      target.mode !== 'direct'
    ) {
      const { candidate, skipped } = await sm._validationGuardedSkipPoints(ctxBase, target, pointsToScan);
      if (skipped.length) {
        logger.info(
          `输入校验判定：跳过 ${skipped.length}/${pointsToScan.length} 个「参数被白名单拦死」的点（省 200+ 请求/点）`
        );
        for (const s of skipped) {
          // 跳过原因写回注入点（report.points 仍保留全量点）：使用者必须能看见「为什么没测」
          const p = points.find((x) => x.id === s.pointId);
          if (p) {
            p.skipReason = s.reason;
            p.skipNote = s.note;
          }
          eventBus.emit(scanId, 'point_skipped', { pointId: s.pointId, reason: s.reason, note: s.note });
        }
        if (session) {
          await Promise.all(
            skipped.map((s) => session.savePointResult(s.pointId, { found: [] }).catch(() => null))
          );
        }
        pointsToScan = candidate;
      }
    }

  return { points, pointsToScan, session, restored };
}
