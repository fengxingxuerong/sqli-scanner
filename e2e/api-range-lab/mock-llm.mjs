// ============================================================================
// e2e/api-range-lab/mock-llm.mjs —— OpenAI 兼容的本地 LLM 假端点
//
// 为什么接口靶场必须自带一个 LLM 假端点：
//   POST /scan/:id/report/ai 是九条对外接口里唯一会**把扫描数据发出本机**的一条。
//   拿真第三方端点测它有两重不可接受：① 测试数据（含目标 URL/证据）外泄；
//   ② 配额与网络抖动让门禁变红。而"跳过这条接口"更不行——它是交付项。
//   故：本地假端点承接真实 HTTPS-over-loopback 调用链（fetch → JSON → 角色流水线 →
//   validateAnalysisJson → 缓存 → 降级），把 ReportAI 的三角色流水线、429 冷却、
//   非 JSON 降级、超时这些**分支**全部真跑一遍。
//
// 控制面（测试用）：
//   POST /__llm/config {mode, models:{analyst,...}, latencyMs}
//     mode: 'ok' 三角色正常 | 'nonjson' analyst 返回散文（验 [B-11] 降级）
//           'fail' 全部 500（验三级降级后仍成功/失败的诚实形态）
//           '429'  全部 429（验 keyHealth 冷却与错误码）
//   GET  /__llm/stats  → 收到的请求清单（含 Authorization 头 presence、prompt 字节数）
//   POST /__llm/reset
// ============================================================================
import { createRequire } from 'node:module';
const _require = createRequire(new URL('../../server/package.json', import.meta.url));
const express = _require('express');

const ROLE_BY_MODEL = {
  'deepseek-v4-flash': 'analyst',
  'glm-5.2': 'writer',
  'sensenova-6.8-flash-lite': 'reviewer',
};

export function createMockLlmApp() {
  const app = express();
  app.use(express.json({ limit: '4mb' }));

  const state = { mode: 'ok', latencyMs: 0, requests: [] };

  const analystJson = (userPrompt) => ({
    overall_risk: 'High',
    vulns: [
      {
        technique: 'union',
        risk: 'High',
        summary: `靶场假端点解析到 union 通道（prompt 长度 ${userPrompt.length}）`,
        cvss: 8.6,
      },
    ],
    remediation: ['使用参数化查询', '收敛数据库账号权限'],
  });

  const markdown = (role, userPrompt) =>
    `# ${role} 生成的报告\n\n- 输入 prompt 字节：${userPrompt.length}\n- 结论：目标存在 SQL 注入（UNION 通道），证据已核对\n\n## PoC\n\`\`\`bash\ncurl -s 'http://127.0.0.1/lab?id=1 UNION SELECT 1,2,3-- -'\n\`\`\`\n\n## 修复建议\n1. 参数化查询\n2. 最小权限账号\n`;

  // 控制面必须先注册：下面的 chat 兜底会吃掉所有 POST/*
  app.get('/__llm/stats', (req, res) => res.json({ mode: state.mode, requests: state.requests }));
  app.post('/__llm/reset', (req, res) => {
    state.requests = [];
    state.mode = 'ok';
    state.latencyMs = 0;
    res.json({ ok: true });
  });
  app.post('/__llm/config', (req, res) => {
    if (typeof req.body?.mode === 'string') state.mode = req.body.mode;
    if (Number.isFinite(req.body?.latencyMs)) state.latencyMs = req.body.latencyMs;
    res.json({ ok: true, mode: state.mode, latencyMs: state.latencyMs });
  });

  app.use(async (req, res) => {
    if (req.method !== 'POST') return res.status(405).json({ error: 'mock llm 只接受 POST' });
    const model = String(req.body?.model || '');
    const role = ROLE_BY_MODEL[model] || 'unknown';
    const messages = Array.isArray(req.body?.messages) ? req.body.messages : [];
    const userPrompt = String(messages.find((m) => m.role === 'user')?.content || '');
    state.requests.push({
      ts: Date.now(),
      role,
      model,
      hasAuth: Boolean(req.headers.authorization && /^Bearer /.test(req.headers.authorization)),
      promptBytes: Buffer.byteLength(userPrompt, 'utf8'),
      systemSnippet: String(messages.find((m) => m.role === 'system')?.content || '').slice(0, 60),
    });

    if (state.latencyMs > 0) await new Promise((r) => setTimeout(r, state.latencyMs));

    if (state.mode === '429') return res.status(429).json({ error: { message: 'rate limited (mock)' } });
    if (state.mode === 'fail') return res.status(500).json({ error: { message: 'upstream exploded (mock)' } });

    let content;
    if (state.mode === 'nonjson') {
      content = role === 'analyst' ? '抱歉，我无法输出结构化 JSON，这是一段散文式描述。' : markdown(role, userPrompt);
    } else if (role === 'analyst') {
      content = JSON.stringify(analystJson(userPrompt));
    } else {
      content = markdown(role, userPrompt);
    }
    res.json({
      id: `chatcmpl-mock-${role}-${state.requests.length}`,
      object: 'chat.completion',
      model,
      choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }],
      usage: { prompt_tokens: Math.ceil(userPrompt.length / 4), completion_tokens: 128, total_tokens: 0 },
    });
  });

  app.get('/__llm/stats', (req, res) => res.json({ mode: state.mode, requests: state.requests }));
  app.post('/__llm/reset', (req, res) => {
    state.requests = [];
    state.mode = 'ok';
    state.latencyMs = 0;
    res.json({ ok: true });
  });
  app.post('/__llm/config', (req, res) => {
    if (typeof req.body?.mode === 'string') state.mode = req.body.mode;
    if (Number.isFinite(req.body?.latencyMs)) state.latencyMs = req.body.latencyMs;
    res.json({ ok: true, mode: state.mode, latencyMs: state.latencyMs });
  });

  return app;
}

export default createMockLlmApp;
