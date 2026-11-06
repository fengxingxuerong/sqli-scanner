#!/usr/bin/env node
// ============================================================================
// e2e/ai-gateway-lab/mock-hang-gateway.mjs —— [D258] 复现「长 prompt 挂起」的确定性网关
//
// 为什么需要它：D255/D258 的动机来自真网关实测 —— 长报告 prompt 100s 超时，短 prompt
// 4.1s 返回（docs/llm-gateway-capability-2026-11-05.txt）。但那个网关需要外部 key，
// CI / 本机不一定有；没有它，短重试路径就只能靠 fetch stub 证明「请求变短了」，
// 证明不了「真 HTTP + 真 abort + 真重试」这条链。
//
// 本网关用**行为模拟**替代真模型：
//   · 首轮完整 prompt（analyst / writer / reviewer 的原文）→ 延迟 HANG_MS 后返回；
//   · 压缩短 prompt（D255/D258 的三段短 prompt）→ 30ms 内返回非空内容。
// 客户端 per-step 超时小于 HANG_MS 时，首轮必然 AbortError，短重试必然成功 ——
// 这正是「长 prompt 挂起、短 prompt 可用」的最小可复现形态。
//
// 判据绑定：短 prompt 用**开头前缀**识别（见 SHORT_PREFIXES）。若短 prompt 文案被改，
// 本网关会把短重试也挂起（套件红），而不是静默放行 —— 失败方向是安全的。
//
// 用法（两个终端）：
//   node e2e/ai-gateway-lab/mock-hang-gateway.mjs            # 默认 :18326
//   AI_GATEWAY_URL=http://127.0.0.1:18326 \
//   AI_GATEWAY_MODEL=mock-hang AI_GATEWAY_TIMEOUT_MS=6000 \
//   node e2e/ai-gateway-lab/run.mjs
//
// env：MOCK_PORT（默认 18326）、MOCK_HANG_MS（默认 5000）
// ============================================================================
import http from 'node:http';

const PORT = Number(process.env.MOCK_PORT) || 18326;
const HANG_MS = Number(process.env.MOCK_HANG_MS) || 5000;
const MODEL = 'mock-hang';

/** 短 prompt 前缀（与 ReportAI.js 的 buildShort*Prompt 一一对应；改动即套件红） */
const SHORT_PREFIXES = [
  '分析下面的 SQL 注入扫描结果',
  '写一份简短的 SQL 注入漏洞报告',
  '审阅并修订下面这份漏洞报告',
  // [D259] 分步短 prompt 都是这个前缀；识别不到就把分步请求也挂起，套件红（失败方向安全）
  '【分步',
];

/** 需要返回 JSON 的短 prompt（analyst 的短重试 + [D259] 分步分析首轮） */
const JSON_PREFIXES = [
  '分析下面的 SQL 注入扫描结果',
  '【分步·分析】',
];

const ANALYSIS = JSON.stringify({
  vulns: [{ name: 'SQL 注入', type: '布尔盲注', risk: '高危', dbms: 'MySQL', poc_payload: "1' AND '1'='1" }],
  overall_risk: '高危',
  impact_summary: 'mock 短重试返回',
});

/**
 * 读请求体（OpenAI 兼容 chat/completions 是小 JSON，直接拼接即可）。
 * @param {import('node:http').IncomingMessage} req 请求
 * @returns {Promise<string>} 原始 body
 */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => resolve(raw));
    req.on('error', reject);
  });
}

/**
 * 按 prompt 形态决定「挂起」还是「秒回」。
 * @param {string} user 用户消息
 * @returns {{short: boolean, content: string}} 判定与响应内容
 */
function classify(user) {
  const short = SHORT_PREFIXES.some((p) => user.startsWith(p));
  // [D259] 按前缀判 JSON，不能用 `includes('"vulns")`：分步 writer 的事实包里也含该字段，
  // 会把章节请求误判成 analyst 并回一段 JSON，掩盖「分步请求是否真的短」。
  const wantJson = JSON_PREFIXES.some((p) => user.startsWith(p));
  const titleMatch = user.match(/「([^」]+)」/);
  const title = titleMatch ? titleMatch[1] : 'Mock 报告';
  const content = wantJson
    ? ANALYSIS
    : `# ${title}\n\n本报告由短 prompt 生成（mock-hang-gateway）。\n`;
  return { short, content };
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && String(req.url || '').endsWith('/v1/models')) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ data: [{ id: MODEL }] }));
    return;
  }
  if (req.method !== 'POST' || !String(req.url || '').endsWith('/v1/chat/completions')) {
    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: { message: 'not found' } }));
    return;
  }
  const raw = await readBody(req);
  let user = '';
  try {
    const body = JSON.parse(raw);
    user = String(body?.messages?.[1]?.content || '');
  } catch {
    /* 非法 JSON 按长 prompt 处理（挂起 → 客户端超时） */
  }
  const { short, content } = classify(user);
  const delay = short ? 30 : HANG_MS;
  setTimeout(() => {
    if (res.writableEnded || res.destroyed) return;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ choices: [{ message: { content }, finish_reason: 'stop' }] }));
  }, delay);
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[mock-hang-gateway] listening on http://127.0.0.1:${PORT}（模型 ${MODEL}，长 prompt 挂起 ${HANG_MS}ms）`);
});
