#!/usr/bin/env node
// ============================================================================
// e2e/ai-gateway-lab/mock-gateway.mjs —— [D276] 确定性 AI 报告网关
//
// 为什么需要它：D228 的 ai-gateway 套件要真网关 + 真模型（opt-in，CI 里长期 SKIP）；
// D258 的 mock-hang 只模拟「长 prompt 挂起 / 短 prompt 秒回」一种形态。AI 报告链路
// 的其余事实（三角色流水线、分步 5 章撰写/审阅、D275 脱敏与确定性边界章节、
// usage/trace 累加）在无真网关环境下没有可执行判据。本网关用**行为模拟**替代模型，
// 让 `run-mock.mjs` 在 CI 里跑真实 HTTP + 真实 ReportAI 代码。
//
// 诚实边界（与 mock-hang 同一口径）：
//   · 它证明的是**链路事实**（请求分类、脱敏、章节数、边界章节、usage），
//     不证明模型输出质量或报告文风；
//   · prompt 分类按**开头前缀**识别。文案改了 ⇒ 返回 HTTP 500（未知 prompt），
//     套件红 —— 失败方向安全，不会把分类漂移静默放行；
//   · 不校验 key/model 名（客户端传什么就回什么 model），只校验请求形态。
//
// 用法（手工）：
//   node e2e/ai-gateway-lab/mock-gateway.mjs        # 默认 :18327
//   AI_GATEWAY_URL=http://127.0.0.1:18327 AI_GATEWAY_MODEL=mock-ai-report \
//     node e2e/ai-gateway-lab/run.mjs
//
// 程序化：
//   import { startMockGateway } from './mock-gateway.mjs';
//   const gw = await startMockGateway();   // 临时端口
//   ... gw.url / gw.state.requests ...
//   await gw.close();
//
// env（仅 CLI）：MOCK_PORT（默认 18327）
// ============================================================================
import http from 'node:http';
import { pathToFileURL } from 'node:url';

/** 模型名：/v1/models 与响应里的 model 字段都用它。 */
const MOCK_MODEL = 'mock-ai-report';

/** 分析角色的确定性 JSON（字段与 validateAnalysisJson 的消费面一致）。 */
const ANALYSIS_JSON = JSON.stringify({
  vulns: [{
    name: 'SQL 注入（布尔盲注）',
    type: '布尔盲注',
    risk: '高危',
    cvss: '引擎未评分',
    principle: '用户输入拼接进 SQL 语句，真假条件响应长度存在稳定差异。',
    location: 'id（url）GET',
    dbms: 'MySQL',
    exploitability: '中',
    poc_payload: "1' AND '1'='1",
    poc_verify: '真样本 1617B / 假样本 30B，首个差异偏移 214',
  }],
  overall_risk: '高危',
  impact_summary: '可读取数据库数据。',
});

/** writer 的确定性 Markdown（legacy 整篇 / 短重试共用）。 */
const WRITER_MD = [
  '## 一、漏洞概述',
  '',
  'Mock 网关生成的确定性报告：目标存在布尔盲注。',
  '',
  '## 二、漏洞描述',
  '',
  '参数 id（url）在 GET 请求中可注入，数据库为 MySQL。',
  '',
  '## 三、漏洞证明（PoC）',
  '',
  "```http\nGET /***?id=*** HTTP/1.1\nHost: <目标Host>\n```",
  '',
  '响应判据：真样本 1617B / 假样本 30B，首个差异偏移 214。',
  '',
  '## 四、影响评估',
  '',
  '可读取数据库数据，影响范围限于当前库。',
  '',
  '## 五、修复方案',
  '',
  '使用参数化查询；补充 WAF 与最小权限。',
].join('\n');

/**
 * 取「」里的章节标题（分步 writer / reviewer prompt 都带）。
 * @param {string} user 用户消息
 * @returns {string} 标题（取不到时给占位）
 */
function sectionTitle(user) {
  const m = user.match(/「([^」]+)」/);
  return m ? m[1] : 'Mock 章节';
}

/**
 * 从 `marker` 之后取原文（用于 reviewer 保留待审内容，而不是回一段空话）。
 * @param {string} user 用户消息
 * @param {string} marker 分隔标记
 * @returns {string} 标记后的内容（取不到时为空串）
 */
function after(user, marker) {
  const i = user.indexOf(marker);
  return i < 0 ? '' : user.slice(i + marker.length);
}

/**
 * 按 prompt 形态分类并产出确定性响应。
 * 分类判据是**开头前缀**：改了 prompt 文案就会落到 unknown → HTTP 500 → 套件红。
 * @param {string} user 用户消息
 * @returns {{kind:string, mode:string, content:string, status?:number, error?:string}} 分类与响应
 */
export function classifyPrompt(user) {
  const u = String(user || '');
  if (u.startsWith('【分步·分析】') || u.startsWith('分析下面的 SQL 注入扫描结果') || u.startsWith('你是漏洞分析师')) {
    return { kind: 'analyst', mode: u.startsWith('【分步·分析】') ? 'stepwise' : 'full', content: ANALYSIS_JSON };
  }
  if (u.startsWith('【分步·章节】审阅并修订')) {
    return { kind: 'reviewer', mode: 'stepwise', content: `（已审阅）${after(u, '本节：')}` };
  }
  if (u.startsWith('【分步·章节】写')) {
    return { kind: 'writer', mode: 'stepwise', content: `（mock 章节）${sectionTitle(u)}：本节由确定性 mock 网关生成。` };
  }
  if (u.startsWith('审阅并修订下面这份漏洞报告')) {
    return { kind: 'reviewer', mode: 'short', content: `（已审阅）${after(u, '报告节选：')}` };
  }
  if (u.startsWith('写一份简短的 SQL 注入漏洞报告')) {
    return { kind: 'writer', mode: 'short', content: `# SQL 注入漏洞报告（短）\n\n${WRITER_MD}` };
  }
  if (u.startsWith('你是安全审计专家。审阅以下')) {
    const draft = after(u, '## 待审阅报告\n').split('\n\n## 结论口径')[0];
    return { kind: 'reviewer', mode: 'full', content: `## 审阅意见\n\n- mock 网关：未发现夸大/编造。\n\n## 修订版报告\n\n${draft}` };
  }
  if (u.startsWith('你是渗透测试报告撰写专家。根据漏洞分析结果')) {
    return { kind: 'writer', mode: 'full', content: WRITER_MD };
  }
  return {
    kind: 'unknown',
    mode: 'unknown',
    content: '',
    status: 500,
    error: 'mock-gateway: 未识别的 prompt 前缀（prompt 文案改了？classifyPrompt 需同步）',
  };
}

/**
 * 读请求体（chat/completions 是小 JSON，直接拼接即可）。
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
 * 按字符数估 token（确定性，不依赖 tokenizer；只用于验证 usage 被累加）。
 * @param {string} s 文本
 * @returns {number} 估算 token 数（至少 1）
 */
function estimateTokens(s) {
  return Math.max(1, Math.ceil(String(s || '').length / 4));
}

/**
 * 构造 OpenAI 兼容响应体。
 * @param {string} content 正文
 * @param {string} system system 消息
 * @param {string} user user 消息
 * @returns {object} 响应 JSON
 */
function chatResponse(content, system, user) {
  const promptTokens = estimateTokens(system) + estimateTokens(user);
  const completionTokens = estimateTokens(content);
  return {
    model: MOCK_MODEL,
    choices: [{ message: { role: 'assistant', content }, finish_reason: 'stop' }],
    usage: {
      prompt_tokens: promptTokens,
      completion_tokens: completionTokens,
      total_tokens: promptTokens + completionTokens,
    },
  };
}

/**
 * 启动确定性 mock 网关。
 * @param {{port?:number, model?:string, failRole?:string, failMode?:'empty'|'http', delayMs?:number}} [opts] 选项
 *   port=0（默认）用临时端口；failRole 指定某类角色返回空内容或 503（自证失败路径用）；
 *   delayMs>0 时每个 chat 请求延迟响应（D277 并发判据需要真实重叠窗口）。
 * @returns {Promise<{url:string, port:number, model:string, state:{requests:Array<object>,inFlight:number,maxInFlight:number}, reset:()=>void, close:()=>Promise<void>}>} 网关句柄
 */
export function startMockGateway(opts = {}) {
  const model = opts.model || MOCK_MODEL;
  const failRole = opts.failRole || '';
  const failMode = opts.failMode || 'empty';
  const delayMs = Math.max(0, Number(opts.delayMs) || 0);
  /** @type {{requests:Array<object>,inFlight:number,maxInFlight:number}} */
  const state = { requests: [], inFlight: 0, maxInFlight: 0 };
  const server = http.createServer(async (req, res) => {
    const url = String(req.url || '');
    if (req.method === 'GET' && url.endsWith('/v1/models')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ data: [{ id: model }] }));
      return;
    }
    if (req.method === 'GET' && url.endsWith('/__state')) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ model, requests: state.requests, inFlight: state.inFlight, maxInFlight: state.maxInFlight }));
      return;
    }
    if (req.method !== 'POST' || !url.endsWith('/v1/chat/completions')) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'not found' } }));
      return;
    }
    const raw = await readBody(req);
    /** @type {any} */
    let body = {};
    try {
      body = JSON.parse(raw);
    } catch {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'invalid json' } }));
      return;
    }
    const system = String(body?.messages?.[0]?.content || '');
    const user = String(body?.messages?.[1]?.content || '');
    const cls = classifyPrompt(user);
    const record = { kind: cls.kind, mode: cls.mode, system, user, userLen: user.length };
    state.requests.push(record);
    state.inFlight++;
    state.maxInFlight = Math.max(state.maxInFlight, state.inFlight);
    try {
      if (delayMs > 0) await new Promise((r) => setTimeout(r, delayMs));
      if (cls.status && cls.status !== 200) {
        record.error = cls.error || `http:${cls.status}`;
        res.writeHead(cls.status, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: { message: cls.error || 'unknown prompt' } }));
        return;
      }
      if (failRole && cls.kind === failRole) {
        record.error = `injected:${failMode}`;
        if (failMode === 'http') {
          res.writeHead(503, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: { message: 'mock injected 503' } }));
          return;
        }
        // 空内容 + finish_reason=stop：模拟「200 但没产出」，验证上层不把它记成成功
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(chatResponse('', system, user)));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(chatResponse(cls.content, system, user)));
    } finally {
      state.inFlight--;
    }
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port ?? 0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      resolve({
        url: `http://127.0.0.1:${port}`,
        port,
        model,
        state,
        reset: () => { state.requests.length = 0; state.inFlight = 0; state.maxInFlight = 0; },
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

// ── CLI：手工联调用（CI 走 run-mock.mjs 的程序化入口）────────────────────────
const isMain = process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url;
if (isMain) {
  const port = Number(process.env.MOCK_PORT) || 18327;
  const delayMs = Number(process.env.MOCK_DELAY_MS) || 0;
  const gw = await startMockGateway({ port, delayMs });
  console.log(`[mock-gateway] listening on ${gw.url}（模型 ${gw.model}；确定性三角色 + 分步 5 章；delay=${delayMs}ms）`);
}
