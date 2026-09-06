// 直连模式连接器（对标 sqlmap -d）
//
// 复用 HttpClient 的 request(req) 契约：返回 { status, headers, data }。
// 但 direct 模式下的 req 由 buildInjectionRequest 在 target.mode==='direct' 时产出，
// 其 req.sql 字段是要直连执行的 SQL（注入 payload 已拼接进 SQL 模板的 {INJECT} 标记处）。
//
// 这样检测器/提取器/接管器（全部经 sendInjection(httpClient, ctx, req) → httpClient.request(req)）
// 无需任何改动即可在直连模式下复用整条 SQLi 检测链路——区别仅在于"通道"从 HTTP 变成了数据库直连。

import { getDriver } from './dbDrivers.js';

export class DirectConnector {
  constructor(target) {
    this.target = target || {};
    this.driver = null;
    this._connecting = null;
  }

  async _ensure() {
    if (this.driver) return;
    if (!this._connecting) this._connecting = getDriver(this.target);
    this.driver = await this._connecting;
  }

  // [审查修复] 原正则含裸 `closed|ended|terminated|disconnected` 子串，会误命中 DBMS 普通语法错误
  //（如 PostgreSQL "unterminated quoted string"，un+terminated 含 "terminated"）→ 报错注入被当作断连，
  // 反复关闭/重建真实驱动（PGLite 重建多次后同步协议挂死，recall-e2e PG 场景整轮卡死）。
  // 修复：词边界 + 精确断连短语，仅明确连接丢失语义才判定；另加重连预算见 request()。

  // P1-6: 判断是否为连接丢失类错误（需重连）
  _isConnLostError(e) {
    const msg = String(e && e.message || e || '').toLowerCase();
    return /econnreset|econnrefused|protocol_connection_lost|socket hang up|connection (lost|refused|reset|terminated|closed|ended|timed out)|server closed the connection|terminating connection|connection .*?(closed|ended|dropped|broken)|already closed/.test(msg);
  }

  // 连续断连预算（上限 3 次，成功请求后归零）：防止真实断连反复重建驱动实例时
  // 陷入「重建→再断→再重建」的循环（WASM 驱动的直连模式每次重建成本很高）。
  _bumpConnDrop() {
    this._connDrops = (this._connDrops || 0) + 1;
    return this._connDrops;
  }
  _resetConnDrop() {
    this._connDrops = 0;
  }

  // P1-6: 重置连接状态，使下次 _ensure() 重新建立连接
  _resetConn() {
    this.driver = null;
    this._connecting = null;
  }

  // [⑳] 暴露驱动已知的方言，供 scanRunner 在 direct 模式下直接设置 ctx.dbms，
  // 避免盲目跑 HTTP 风格指纹识别（响应头识别在 direct 模式下必然失败）。
  // 返回小写方言名（如 'mysql', 'postgres', 'sqlite'），由调用方 dialectToDbms 映射为标准 DBMS 名。
  async getDialect() {
    await this._ensure();
    return this.driver?.dialect || null;
  }

  // 契约同 HttpClient.request(req) -> { status, headers, data }
  async request(req) {
    await this._ensure();
    const sql = req && req.sql;
    if (sql == null) {
      return { status: 200, headers: {}, data: '' };
    }
    try {
      // P2-18: 加查询超时（默认 30s），防止 SLEEP 类 payload 无限阻塞 worker
      const timeoutMs = (this.target.config && this.target.config.queryTimeout) || 30000;
      let timer;
      const result = await Promise.race([
        this.driver.query(sql),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('直连查询超时')), timeoutMs);
        }),
      ]);
      clearTimeout(timer);
      return { status: 200, headers: {}, data: rowsToText(result) };
    } catch (e) {
      // P1-6: 连接丢失时重置驱动并重试一次（防数据库重启/网络闪断后永久不可用）
      if (this._isConnLostError(e) && this.driver) {
        // [审查修复] 重连预算：连续断连 >3 次不再重建，直接返回错误（防重建循环）
        if (this._bumpConnDrop() > 3) {
          this._resetConnDrop();
          const msg = String(e && e.message ? e.message : e);
          return { status: 500, headers: {}, data: msg };
        }
        try { await this.driver.close?.(); } catch { /* ignore */ }
        this._resetConn();
        try {
          await this._ensure();
          const result = await this.driver.query(sql);
          this._resetConnDrop();
          return { status: 200, headers: {}, data: rowsToText(result) };
        } catch (e2) {
          const msg2 = e2 && e2.message ? e2.message : String(e2);
          return { status: 500, headers: {}, data: msg2 };
        }
      }
      // 数据库执行错误（报错注入向量）：把错误信息作为 body 返回，供 ERROR_SIG 匹配。
      // 返回 status 500 而非 200 —— 对齐 HTTP 模式"数据库错误 → 5xx / 异常页"的语义，
      // 并让 binaryGuessColumns 的 status>=500 判据能正确收敛列数（否则长错误串长度 > baseLen*0.5 永不收窄）。
      const msg = e && e.message ? e.message : String(e);
      this._resetConnDrop();
      return { status: 500, headers: {}, data: msg };
    }
  }

  async close() {
    if (this.driver && this.driver.close) {
      try {
        await this.driver.close();
      } catch {
        /* ignore */
      }
    }
    this.driver = null;
  }
}

// 把 driver 的 { rows, columns } 结果集渲染成文本（类似 HTTP body），供差异检测（UNION 回显/报错/布尔）使用。
// 始终带一个尾部换行作为"页面终止符"：这样布尔假（无数据行）的响应为 '\n' 而非空串，
// 能与基线在位置 0 即分叉，被 _similar 正确判为"非相似"，否则空串会被误判为相似导致布尔漏报。
function rowsToText(result) {
  if (!result) return '\n';
  const lines = [];
  if (Array.isArray(result.columns) && result.columns.length) {
    lines.push(result.columns.join('\t'));
  }
  const rows = result.rows || [];
  for (const r of rows) lines.push(r);
  const body = lines.join('\n');
  return body.length ? body + '\n' : '\n';
}
