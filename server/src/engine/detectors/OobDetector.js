import { nanoid } from 'nanoid';
import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { OOB_PAYLOADS, DNS_OOB_PAYLOADS, SUPPORTED, fillPayload, replaceAllLiteral } from '../payloads.js';
import { oobTunnel } from '../../core/oobTunnel.js';
import { ErrorCode, AppError } from '../../core/errors.js';
import { logger } from '../../core/logger.js';

/**
 * [实战分析 P1 2026-10-02] 从 callbackBase 派生 SMB/UNC 回调路径的 host\share 部分。
 * Windows UNC 主机位不含 :port——`\\127.0.0.1:8899\x` 在真实目标上永远解析不了，
 * 所以 UNC 类向量必须用裸主机：剥 scheme、剥路径、剥端口，token 挪进 share 名
 * （外部 SMB 监听如 Responder 可从 share 名读出 token 完成确认）。
 * [D87 2026-10-18] 实现迁至 core/oobTunnel.js（本地/外部两种拓扑共用同一派生逻辑），
 * 此处保留同名再导出，避免既有调用方与测试断链。
 * @param {string} callbackBase 形如 'http://h:8899' / 'h:8899' / 'h' / 'h/prefix'
 * @param {string} token nanoid token
 * @returns {string} `<host>\oob\<token>`（不含前导 \\\\，模板层按需自带）
 */
export { deriveUncPath } from '../../core/oobTunnel.js';

// OOB 带外检测器（无回显盲注兜底）
// 策略模式与现有 Detector 子类一致：detect(ctx) 返回 DetectionResult。
// 仅当 ScanManager 已按需启动 OOB 隧道（oob 被选中且 enabled）时才可能命中；
// 命中即确认注入存在，但"只确认、不进拖库/二分提取"（扫描聚合阶段 oob 落空属预期）。
export class OobDetector extends Detector {
  constructor() {
    super('oob');
  }

  /**
   * @param {object} ctx { httpClient, target, point, dbms, config }
   * @returns {Promise<import('../models.js').DetectionResult>}
   */
  async detect(ctx) {
    const { httpClient, target, point, dbms, config } = ctx;
    const result = createDetectionResult(point.id, 'oob');

    // 隧道未启动（oob 未正确启用）→ 抛 OOB_DISABLED，由调度层捕获并记录
    // [D87] 判据从 oobReceiver 改为 oobTunnel：两种回连拓扑（本地监听/外部协作端）都经
    // 同一抽象，检测器无需知道背后是哪条；语义不变（未启用仍然拒绝，不静默放过）。
    if (!oobTunnel.isStarted()) {
      throw new AppError(ErrorCode.OOB_DISABLED, 'oob 接收端未启动（需 oob 被选中且 enabled）');
    }
    const oobCfg = (config && config.oob) || {};
    const timeoutMs = Number.isFinite(oobCfg.timeoutMs) ? oobCfg.timeoutMs : 5000;

    // 生成带外 token，并由隧道解析出回连地址（本地模式: callbackBase 派生；
    // interactsh 模式: 协作端域名，token 编进子域标签）。
    const token = nanoid(16);
    const addr = oobTunnel.resolveAddresses(token, oobCfg);
    const callback = addr.http;
    // [实战分析 P1 2026-10-02] UNC/SMB 类向量（MySQL/MariaDB/TiDB LOAD_FILE、MSSQL
    // xp_dirtree）用裸主机 + share 名形态：Windows UNC 主机位不含 :port。
    const uncPath = addr.unc;

    // 候选 DBMS：已知 dbms 且支持 OOB → 仅打该库；否则遍历所有支持库逐一尝试
    const supportedDbs = Object.keys(SUPPORTED).filter(
      (k) => SUPPORTED[k] && SUPPORTED[k].oob && Array.isArray(OOB_PAYLOADS[k]) && OOB_PAYLOADS[k].length > 0
    );
    const candidates =
      dbms && OOB_PAYLOADS[dbms] && OOB_PAYLOADS[dbms].length ? [dbms] : supportedDbs;

    // 触发目标带外请求：将 {CALLBACK}/{UNC} 填入各库 OOB 触发语句。
    // 注意：OOB 注入【不做 tamper】，否则会破坏回调地址导致回连失败。
    // [实战分析 P1 2026-10-02 通道边界显式化] UNC/SMB 向量的回连走「目标 → 本机 445」，
    // 内置接收端只监听 HTTP+DNS 捕获不到 SMB 握手——投放 UNC 向量时打一次提示，
    // 告知三条可行路径（外部 SMB 监听 / oob.dnsOob DNS 通道 / callbackBase 配目标可解析
    // 的主机名）。只 log 不落 report：通道没配齐时 DNS/HTTP 轮仍可能命中，不算能力缺失。
    let uncHintLogged = false;
    const tried = [];
    for (const cdb of candidates) {
      for (const tpl of OOB_PAYLOADS[cdb] || []) {
        if (tpl.includes('{UNC}') && !uncHintLogged) {
          uncHintLogged = true;
          logger.info(
            '[oob] 投放 UNC/SMB 类向量：token 在 share 名（' + uncPath + '）。' +
            '内置接收端不监听 445——需外部 SMB 监听（Responder/Inveigh）读 share 名，' +
            '或配 oob.dnsOob 走 DNS 通道；callbackBase 需为目标可解析的主机名（IP 直连 445 只有本机自身可达）。'
          );
        }
        const payload = replaceAllLiteral(
          replaceAllLiteral(
            fillPayload(tpl, { orig: point.originalValue || '1' }),
            '{CALLBACK}',
            callback
          ),
          '{UNC}',
          uncPath
        );
        tried.push(payload);
        const req = this.buildRequest(target, point, payload);
        try {
          // 经统一 HttpClient 发送（与全引擎一致）；单请求失败不中断其余尝试
          await this.send(httpClient, ctx, req);
        } catch {
          /* 单个带外请求失败忽略，继续尝试其它库/模板 */
        }
      }
    }

    // 等待目标回连（本地监听命中 / interactsh 轮询取回；测试可直接调 oobTunnel.receive）
    const hit = await oobTunnel.waitForToken(token, timeoutMs);
    if (hit) {
      result.vulnerable = true;
      result.dbms = dbms || null; // 已知库则标注；未知时仅确认注入存在
      result.evidence = `OOB 带外确认：token=${token} 被目标 DBMS 回连至接收端 ${callback}（无回显注入成立）`;
      result.payloads = tried;
      // 与现有检测器一致：同步标记注入点
      point.confirmed = true;
      point.technique = 'oob';
      point.dbms = dbms || point.dbms;
      return result;
    }

    // —— DNS OOB 轮（对标 sqlmap --dns-domain）：oob.dnsOob 开启且配置了回调域名才追加 ——
    // token 作为子域名标签触发目标对 <token>.<dnsDomain> 的 DNS 查询，由接收端 UDP 监听捕获
    //（与 HTTP 轮共用 receive/waitForToken 统一 token 机制）。适用于无 HTTP 出站、仅 DNS 出站
    // 的目标。DNS 轮同样【不做 tamper】（会破坏域名）；域名缺失或 UDP 监听启动失败时自然落空。
    const dnsDomain = typeof oobCfg.dnsDomain === 'string' ? oobCfg.dnsDomain.trim() : '';
    if (oobCfg.dnsOob === true && dnsDomain) {
      const dnsToken = nanoid(16);
      const dnsName = `${dnsToken}.${dnsDomain}`;
      const dnsSupported = Object.keys(SUPPORTED).filter(
        (k) =>
          SUPPORTED[k] &&
          SUPPORTED[k].oob &&
          Array.isArray(DNS_OOB_PAYLOADS[k]) &&
          DNS_OOB_PAYLOADS[k].length > 0
      );
      const dnsCandidates =
        dbms && DNS_OOB_PAYLOADS[dbms] && DNS_OOB_PAYLOADS[dbms].length ? [dbms] : dnsSupported;
      for (const cdb of dnsCandidates) {
        for (const tpl of DNS_OOB_PAYLOADS[cdb] || []) {
          const payload = replaceAllLiteral(
            replaceAllLiteral(fillPayload(tpl, { orig: point.originalValue || '1' }), '{TOKEN}', dnsToken),
            '{DOMAIN}',
            dnsDomain
          );
          tried.push(payload);
          const req = this.buildRequest(target, point, payload);
          try {
            await this.send(httpClient, ctx, req);
          } catch {
            /* 单个带外请求失败忽略，继续尝试其它库/模板 */
          }
        }
      }
      const dnsHit = await oobTunnel.waitForToken(dnsToken, timeoutMs);
      if (dnsHit) {
        result.vulnerable = true;
        result.dbms = dbms || null;
        result.evidence = `OOB 带外确认（DNS 通道）：token=${dnsToken} 触发目标对 ${dnsName} 的 DNS 查询被接收端捕获（无回显注入成立）`;
        result.payloads = tried;
        point.confirmed = true;
        point.technique = 'oob';
        point.dbms = dbms || point.dbms;
      }
    }
    return result;
  }
}

export default OobDetector;
