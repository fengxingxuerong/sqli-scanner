import { nanoid } from 'nanoid';
import { Detector } from '../Detector.js';
import { createDetectionResult } from '../models.js';
import { OOB_PAYLOADS, DNS_OOB_PAYLOADS, SUPPORTED, fillPayload } from '../payloads.js';
import { oobReceiver } from '../../core/oobReceiver.js';
import { ErrorCode, AppError } from '../../core/errors.js';

// OOB 带外检测器（无回显盲注兜底）
// 策略模式与现有 Detector 子类一致：detect(ctx) 返回 DetectionResult。
// 仅当 ScanManager 已按需启动 oobReceiver（oob 被选中且 enabled）时才可能命中；
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

    // 接收端未启动（oob 未正确启用）→ 抛 OOB_DISABLED，由调度层捕获并记录
    if (!oobReceiver.isStarted()) {
      throw new AppError(ErrorCode.OOB_DISABLED, 'oob 接收端未启动（需 oob 被选中且 enabled）');
    }
    const oobCfg = (config && config.oob) || {};
    // P2-13: 未显式配置 callbackBase 时按接收端 httpPort 派生（127.0.0.1:<httpPort>），
    // 避免用户只改 httpPort 不改 callbackBase 导致回连打到旧端口、OOB 静默失效。
    const httpPort = Number(oobCfg.httpPort);
    const callbackBase =
      (typeof oobCfg.callbackBase === 'string' && oobCfg.callbackBase.trim() !== ''
        ? oobCfg.callbackBase
        : Number.isFinite(httpPort) && httpPort > 0
          ? `127.0.0.1:${httpPort}`
          : '127.0.0.1:8899');
    const timeoutMs = Number.isFinite(oobCfg.timeoutMs) ? oobCfg.timeoutMs : 5000;

    // 生成带外 token，并与接收端地址拼成回调 URL（目标 DBMS 被触发后回连此地址）
    const token = nanoid(16);
    const callback = `${callbackBase}/oob/${token}`;

    // 候选 DBMS：已知 dbms 且支持 OOB → 仅打该库；否则遍历所有支持库逐一尝试
    const supportedDbs = Object.keys(SUPPORTED).filter(
      (k) => SUPPORTED[k] && SUPPORTED[k].oob && Array.isArray(OOB_PAYLOADS[k]) && OOB_PAYLOADS[k].length > 0
    );
    const candidates =
      dbms && OOB_PAYLOADS[dbms] && OOB_PAYLOADS[dbms].length ? [dbms] : supportedDbs;

    // 触发目标带外请求：将 {CALLBACK} 填入各库 OOB 触发语句。
    // 注意：OOB 注入【不做 tamper】，否则会破坏回调地址导致回连失败。
    const tried = [];
    for (const cdb of candidates) {
      for (const tpl of OOB_PAYLOADS[cdb] || []) {
        const payload = fillPayload(tpl, { orig: point.originalValue || '1' }).replaceAll(
          '{CALLBACK}',
          callback
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

    // 轮询等待目标回连（真实 DNS/SMB/HTTP 或测试直接调 oobReceiver.receive）
    const hit = await oobReceiver.waitForToken(token, timeoutMs);
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
          const payload = fillPayload(tpl, { orig: point.originalValue || '1' })
            .replaceAll('{TOKEN}', dnsToken)
            .replaceAll('{DOMAIN}', dnsDomain);
          tried.push(payload);
          const req = this.buildRequest(target, point, payload);
          try {
            await this.send(httpClient, ctx, req);
          } catch {
            /* 单个带外请求失败忽略，继续尝试其它库/模板 */
          }
        }
      }
      const dnsHit = await oobReceiver.waitForToken(dnsToken, timeoutMs);
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
