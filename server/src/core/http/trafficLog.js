// ============================================================================
// core/http/trafficLog.js —— 原始 HTTP 流量落盘（对标 sqlmap `-t/--traffic-file`）
//
// ── 为什么需要它 ─────────────────────────────────────────────────────────────
// 引擎已有结构化 ledger（每次请求一行摘要）与报告（命中项 + PoC），但**没有原始报文**：
//   · 复现：拿到一份 traffic 就能离线重放，不必依赖"当时的目标还在不在"；
//   · 审计：证明「我确实发了这个请求、目标确实回了这个响应」，而不是只凭引擎自报；
//   · 调试：判定差异时能直接看两边的真实报文，而不是靠日志里的摘要字段。
// sqlmap 的 `-t` 就是这件事，本仓此前是 28 个能力缺口里唯一的 P2。
//
// ── 口径边界（写在代码里，避免后来人误读）───────────────────────────────────
// · 只记 `HttpClient.request()` 的**最终一次**往返：重定向的中间跳、重试的失败轮不在内。
//   理由：命中通常由单请求决定，而把钩子下沉到 `_sendFollowRedirects` 的每次 dispatch
//   会动到传输核心（重定向/HTTP2/401 重放三条路径），风险与收益不匹配。
// · body 默认截断 8KB（`--traffic-max-body` 可调，0 = 不截断）——不截断时一个 10MB
//   页面 × 数千请求会把盘写满，这不是"能力"，是事故。
// · **文件含完整请求头（含 Cookie/Authorization）**：审计要的就是完整，但落盘即凭据外泄面，
//   文档里必须写明"按凭据文件保管"。
// ============================================================================
import fs from 'node:fs';
import path from 'node:path';

/** 单条 body 默认截断字节数（0 = 不截断） */
export const DEFAULT_MAX_BODY = 8192;

/**
 * @typedef {object} TrafficState
 * @property {string} file 落盘路径
 * @property {number} maxBody 单条 body 截断上限
 * @property {number} count 已写条数
 * @property {boolean} warned 写失败是否已告警（避免每请求刷屏）
 */

/** @type {TrafficState|null} 进程级单例：一次运行只开一个流量文件 */
let state = null;

/**
 * 开启流量记录。重复调用会先关闭旧的（换文件）。
 * @param {string} file 目标文件（追加写；父目录不存在则创建）
 * @param {{maxBody?: number}} [opts] maxBody=0 表示不截断
 * @returns {{file: string, maxBody: number}} 实际生效的配置
 */
export function enableTrafficLog(file, opts = {}) {
  const abs = path.resolve(file);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  const maxBody = Number.isFinite(opts.maxBody) ? Math.max(0, Number(opts.maxBody)) : DEFAULT_MAX_BODY;
  state = { file: abs, maxBody, count: 0, warned: false };
  // 首次写入加一行头部注释，便于人一眼认出文件来源与口径（JSON 行格式本身不支持注释，
  // 所以用一条 `_meta` 记录——解析方按 `_meta` 字段跳过即可）。
  const meta = {
    _meta: 'sqli-scanner traffic log',
    startedAt: new Date().toISOString(),
    note: 'NDJSON：每行一次最终往返；含完整请求头（凭据面），按敏感文件保管',
    maxBody,
  };
  fs.appendFileSync(abs, JSON.stringify(meta) + '\n', 'utf8');
  return { file: abs, maxBody };
}

/**
 * 关闭流量记录。
 * @returns {number} 本次共写条数（不含 _meta 行）
 */
export function disableTrafficLog() {
  const n = state ? state.count : 0;
  state = null;
  return n;
}

/**
 * 当前是否已开启（供测试与调用方判断）。
 * @returns {boolean}
 */
export function trafficLogActive() {
  return state !== null;
}

/**
 * 按上限截断文本。
 * @param {unknown} body 原始 body
 * @param {number} maxBody 上限（0 = 不截断）
 * @returns {{text: string|null, bytes: number, truncated: boolean}}
 */
function clipBody(body, maxBody) {
  if (body === null || body === undefined) return { text: null, bytes: 0, truncated: false };
  const text = typeof body === 'string' ? body : String(body);
  const bytes = Buffer.byteLength(text, 'utf8');
  if (maxBody > 0 && bytes > maxBody) {
    return { text: text.slice(0, maxBody), bytes, truncated: true };
  }
  return { text, bytes, truncated: false };
}

/**
 * 记录一次往返。**任何异常都吞掉**——流量记录是旁路，绝不能因为它让扫描失败。
 * @param {{scanId?: string, method?: string, url?: string, headers?: object, data?: unknown}} req 请求侧
 * @param {{status?: number, headers?: object, data?: unknown}} res 响应侧
 * @param {object} [headers] 实际发出的头（调用方已合并认证/Cookie；缺省回退 req.headers）
 * @returns {boolean} 是否写入成功
 */
export function recordTraffic(req, res, headers) {
  if (!state) return false;
  try {
    const hdrs = headers || req.headers || {};
    const reqBody = clipBody(req.data, state.maxBody);
    const resBody = clipBody(res.data, state.maxBody);
    const row = {
      ts: new Date().toISOString(),
      scanId: req.scanId || null,
      req: {
        method: req.method || 'GET',
        url: req.url || null,
        headers: hdrs,
        bodyBytes: reqBody.bytes,
        body: reqBody.text,
        bodyTruncated: reqBody.truncated,
      },
      res: {
        status: res.status ?? null,
        headers: res.headers || {},
        bodyBytes: resBody.bytes,
        body: resBody.text,
        bodyTruncated: resBody.truncated,
      },
    };
    fs.appendFileSync(state.file, JSON.stringify(row) + '\n', 'utf8');
    state.count += 1;
    return true;
  } catch {
    // 写失败（盘满/权限/怪对象序列化）只告警一次：审计丢失要在日志里可见，
    // 但不能每请求刷屏、更不能中断扫描 —— 这是旁路，不是主链路。
    if (state && !state.warned) {
      state.warned = true;
      console.warn(`[traffic] 流量落盘失败（后续不再提示）：${state.file}`);
    }
    return false;
  }
}

/**
 * 仅供测试：重置内部状态（不落盘）。
 * @returns {void}
 */
export function _resetTrafficLogForTest() {
  state = null;
}
