// ============================================================================
// paramMiner.js — 参数挖掘（opt-in，吸收 Arjun 的参数发现思想：分组探测 + 反射定位
// + 二分收敛）。2026-10-02 竞品吸收批次新增。
//
// 解决什么问题：TargetParser 只能发现「已出现在 URL/body/表单里的参数」；真实目标
// （尤其 API）常见「隐藏参数才触发 SQL 拼接」—— ?debug=1 才回显报错、?sort= 才进
// ORDER BY。没有主动挖掘这一步，这类注入面整体漏检（假阴性，扫描器最贵的一类错）。
//
// 算法（Arjun 式，请求预算内收敛）：
//   ① baseline：不带探针参数取基线响应（status + 长度 + 原文）。
//   ② canary：带 1 个哨兵参数发一次 —— 若哨兵也被回显，说明目标无条件回显输入，
//      反射信号失效，退化为纯「响应差异」信号（状态码变 / 长度差超阈值）。
//   ③ 分组：字典按 chunkSize 分组，每组一次请求（所有参数同值携带随机标记）。
//      命中信号（标记回显 或 响应差异）→ 该组含活参数。
//   ④ 二分：命中组对半拆分逐层探测，收敛到单参数。
//   ⑤ 单参复核：收敛出的参数单独再发一次确认（剔除组间串扰的假阳性）。
//   防噪声护栏：超过 60% 的组命中 → 目标响应过噪（动态内容/全局 500），放弃本次
//   挖掘而不是产出海量假候选；请求预算 maxRequests 到顶即停，宁可少挖。
//
// 边界：只支持 GET/HEAD（query 载体）与 POST/PUT/PATCH urlencoded（body 载体）。
// JSON/XML/multipart 目标由调用方（TargetParser 6.6 步）跳过——注入侧对这类载体的
// 「新增键合入」没有对应渲染路径（JSON 点位要求点路径含点号），贸然产出点位会
// 把原请求体整个替换成单参数（发出去就是畸形的）。
// 所有请求经调用方传入的 client（per-scan 视图）发送：限速桶 / SSRF 校验 / scope
// 逐请求校验全部照常生效。
// ============================================================================
import { URL } from 'url';
import { PARAM_WORDLIST, MINE_CANARY } from './paramWordlist.js';

export const MINE_DEFAULTS = Object.freeze({
  chunkSize: 30, // 每次请求携带的候选参数数（Arjun 用 ~500；本仓保守取 30，压低单请求体积与误报面）
  maxRequests: 150, // 请求预算硬顶（含 baseline/canary/分组/二分/复核全部请求）
  lenDiffThreshold: 24, // 无反射时判定「响应有行为变化」的最小长度差
  noisyHitRatio: 0.6, // 组命中数超过该比例 → 判定目标过噪，放弃挖掘
});

/** 生成随机标记值（字母数字，全载体安全；每次探测换新，防上一轮残留在页面缓存里串扰判定） */
function freshToken() {
  return `zx${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * 构造一次探测请求（在真实载体上追加探针参数，尽量贴近后续注入请求的形态）。
 * @returns {{ url?: string, data?: string }} url 用于 query 载体；data（urlencoded 串）用于 body 载体
 */
function buildProbe(carrier, probeParams, token) {
  if (carrier.kind === 'query') {
    const u = new URL(carrier.url);
    for (const name of probeParams) u.searchParams.set(name, token);
    return { url: u.toString() };
  }
  const sp = new URLSearchParams(carrier.bodyParams);
  for (const name of probeParams) sp.set(name, token);
  return { data: sp.toString() };
}

/**
 * 发一次探测：成功带 status+text，失败带 error+空 text。
 * text 在两条分支都必须是字符串 —— 消费点（isHit / baseline 长度差）无条件读它，
 * 少一个键就是 checkJs 下的 `| undefined`；失败分支先被 `resp.error` 拦掉，
 * 补空串不会改变任何判定。
 * @returns {Promise<{status?: number, text: string, error?: unknown}>}
 */
async function sendProbe(client, carrier, probeParams, token, method, headers) {
  const probe = buildProbe(carrier, probeParams, token);
  try {
    const res = await client.request(
      carrier.kind === 'query'
        ? { method, url: probe.url, headers }
        : {
            method,
            url: carrier.url,
            data: probe.data,
            headers: {
              ...headers,
              ...(Object.keys(headers).some((k) => /^content-type$/i.test(k))
                ? {}
                : { 'Content-Type': 'application/x-www-form-urlencoded' }),
            },
          }
    );
    return { status: res?.status, text: String(res?.data ?? '') };
  } catch (e) {
    return { error: e, text: '' };
  }
}

/** 命中判定：标记回显（目标非全回显时）或 响应差异（状态码/长度） */
function isHit(resp, token, baseline, reflectsAll, lenDiffThreshold) {
  if (resp.error) return false; // 网络错误不算信号：单请求失败交给重试语义，这里只少挖不误报
  if (!reflectsAll && resp.text.includes(token)) return true;
  if (resp.status !== baseline.status) return true;
  if (Math.abs(resp.text.length - baseline.len) >= lenDiffThreshold) return true;
  return false;
}

/**
 * 参数挖掘主入口。
 * @param {object} opts
 * @param {string} opts.baseUrl 目标 URL（挖掘只作用于这一个 URL，不随爬虫扩散——请求预算优先收敛）
 * @param {string} [opts.method] 目标方法（GET/HEAD → query 载体；POST/PUT/PATCH → body 载体）
 * @param {Record<string,string>} [opts.bodyParams] body 载体时的既有参数
 * @param {Record<string,string>} [opts.headers] 透传请求头（auth 头等会话上下文）
 * @param {object} opts.client 发包客户端（per-scan 视图；必须支持 request()）
 * @param {string[]} [opts.existingParams] 已发现的参数名（挖掘候选里排除，预算不花在已知参数上）
 * @param {Partial<typeof MINE_DEFAULTS>} [opts.options] 覆盖默认参数（测试用）
 * @param {(msg: string) => void} [opts.log] 进度日志
 * @returns {Promise<{ names: string[], requests: number, reflectsAll: boolean, aborted: string|null }>}
 */
export async function mineParams(opts) {
  const {
    baseUrl,
    method = 'GET',
    bodyParams = {},
    headers = {},
    client,
    existingParams = [],
    options = {},
    log = () => {},
  } = opts;
  const cfg = { ...MINE_DEFAULTS, ...options };
  const m = String(method || 'GET').toUpperCase();
  const kind = m === 'POST' || m === 'PUT' || m === 'PATCH' ? 'body' : 'query';
  const carrier = { kind, url: baseUrl, bodyParams };

  let requests = 0;
  const budgetLeft = () => cfg.maxRequests - requests;
  async function send(params, token) {
    requests += 1;
    return sendProbe(client, carrier, params, token, m, headers);
  }

  // ① baseline（不带探针）——失败即目标不可达，直接放弃（挖掘是锦上添花，不阻塞主扫描）
  const baselineResp = await send([], freshToken());
  if (baselineResp.error) return { names: [], requests, reflectsAll: false, aborted: 'unreachable' };
  const baseline = { status: baselineResp.status, len: baselineResp.text.length };

  // ② canary：目标是否无条件回显输入（是 → 反射信号失效，退化为纯响应差异）
  const canaryToken = freshToken();
  const canaryResp = await send([MINE_CANARY], canaryToken);
  const reflectsAll = !canaryResp.error && canaryResp.text.includes(canaryToken);

  // 候选 = 字典 - 已发现参数 - 哨兵
  const known = new Set(existingParams);
  const candidates = PARAM_WORDLIST.filter((n) => !known.has(n) && n !== MINE_CANARY);
  const chunks = [];
  for (let i = 0; i < candidates.length; i += cfg.chunkSize) {
    chunks.push(candidates.slice(i, i + cfg.chunkSize));
  }

  // ③ 分组探测
  const hitChunks = [];
  let aborted = null;
  for (const chunk of chunks) {
    if (budgetLeft() <= 0) { aborted = 'budget'; break; }
    const token = freshToken();
    const resp = await send(chunk, token);
    if (isHit(resp, token, baseline, reflectsAll, cfg.lenDiffThreshold)) hitChunks.push(chunk);
  }
  // 防噪声护栏：大面积命中 = 目标响应过噪（动态内容/对未知参数全局报错），产出只会是海量假候选
  if (!aborted && chunks.length > 0 && hitChunks.length > Math.ceil(chunks.length * cfg.noisyHitRatio) && hitChunks.length > 4) {
    return { names: [], requests, reflectsAll, aborted: 'noisy' };
  }

  // ④⑤ 二分收敛 + 单参复核
  const confirmed = new Set();
  let queue = hitChunks.slice();
  while (queue.length > 0) {
    if (budgetLeft() <= 0) { aborted = aborted || 'budget'; break; }
    // 队列非空由 while 条件保证；shift() 的 `| undefined` 只是 TS 看不到该不变式
    const group = /** @type {string[]} */ (queue.shift());
    if (group.length === 1) {
      // 单参复核：换新标记单独确认（分组阶段的命中可能来自组内其他参数的串扰）
      const token = freshToken();
      const resp = await send(group, token);
      if (isHit(resp, token, baseline, reflectsAll, cfg.lenDiffThreshold)) confirmed.add(group[0]);
      continue;
    }
    if (budgetLeft() <= 1) { aborted = aborted || 'budget'; break; } // 拆分前确保两个半组都还发得起
    const mid = Math.floor(group.length / 2);
    for (const half of [group.slice(0, mid), group.slice(mid)]) {
      const token = freshToken();
      const resp = await send(half, token);
      if (isHit(resp, token, baseline, reflectsAll, cfg.lenDiffThreshold)) queue.push(half);
    }
  }

  const names = [...confirmed].sort();
  if (names.length > 0) {
    log(`[paramMine] 发现 ${names.length} 个隐藏参数：${names.join('、')}（${requests} 个请求${reflectsAll ? '，目标全回显，反射信号未参与判定' : ''}）`);
  } else if (aborted) {
    log(`[paramMine] 未发现隐藏参数（${requests} 个请求，提前终止：${aborted}）`);
  }
  return { names, requests, reflectsAll, aborted };
}
