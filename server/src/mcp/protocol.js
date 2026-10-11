// ============================================================================
// protocol.js —— MCP（Model Context Protocol）协议层：JSON-RPC 2.0 信封 + MCP 生命周期
//
// [D43 2026-10-11] 对标 dalfox `dalfox mcp` / semgrep `mcp`（并入主二进制的形态）：
// MCP 是 CLI 的一个模式，不是独立服务 —— 入口 `node cli.js mcp`（stdio，NDJSON 分帧）。
//
// 设计约束：
//   · 本文件是**纯协议层**：不 import 引擎/IO —— 工具的实现在 tools.js，stdio 循环在
//     index.js。协议可单测（喂一行 JSON → 断一行 JSON），不碰任何全局状态。
//   · 零依赖（引擎红线）：JSON-RPC/MCP 握手手写，不引 SDK。
//   · 分帧：MCP stdio transport 是**换行分帧**（每条 JSON-RPC 消息恰好一行），
//     不是 LSP 的 Content-Length —— 混了会把客户端整个挂住。
//
// 语义红线：MCP 让 AI 代理直接驱动扫描器，工具层（tools.js）必须继承 CLI/REST 的
// 全部护栏（sanitizeStart 白名单、SSRF、高危池确认门）—— 协议层不做任何旁路。
// ============================================================================

/** 本服务支持的 MCP protocolVersion（新版本加入数组头部；客户端版本不在内时回落最新） */
export const SUPPORTED_PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
export const LATEST_PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0];

// JSON-RPC 2.0 标准错误码
export const RPC_ERRORS = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
};

/**
 * 创建 MCP 服务端处理器。
 * @param {object} opts
 * @param {{name: string, version: string}} opts.serverInfo
 * @param {() => Array<{name: string, description: string, inputSchema: object}>} opts.listTools
 * @param {(name: string, args: object) => Promise<{content: Array<{type: string, text: string}>, isError?: boolean}>} opts.callTool
 *        工具执行错误（目标不可达等）应返回 isError:true 的**结果**而不是抛协议错误；
 *        本函数抛出的异常按 INTERNAL_ERROR 处理（那属于工具层的 bug，不是调用方的错）。
 * @returns {{ handle: (line: string) => Promise<string|null> }}
 */
export function createMcpServer(opts) {
  const serverInfo = opts?.serverInfo || { name: 'sqli-scanner', version: '0.0.0' };
  const listTools = opts?.listTools || (() => []);
  const callTool = opts?.callTool;

  async function handle(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      return json({ jsonrpc: '2.0', id: null, error: rpcErr(RPC_ERRORS.PARSE_ERROR, 'Parse error') });
    }
    if (msg == null || typeof msg !== 'object' || Array.isArray(msg)) {
      return json({ jsonrpc: '2.0', id: null, error: rpcErr(RPC_ERRORS.INVALID_REQUEST, 'Invalid Request') });
    }
    const { id, method, params } = msg;
    // 通知（无 id）：按 JSON-RPC 语义不回复（initialized / cancelled 等）
    if (id === undefined || id === null) return null;

    switch (method) {
      case 'initialize': {
        const requested = params && typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
        const version = SUPPORTED_PROTOCOL_VERSIONS.includes(requested)
          ? requested
          : LATEST_PROTOCOL_VERSION;
        return json({
          jsonrpc: '2.0',
          id,
          result: {
            protocolVersion: version,
            capabilities: { tools: { listChanged: false } },
            serverInfo,
            instructions:
              'sqli-scanner：授权 SQL 注入检测。run_scan 启动扫描返回 scanId，' +
              'get_scan_status 轮询，get_findings 取结构化漏洞，get_report 取完整报告。' +
              '只允许扫描用户明确授权的目标；verdict=inconclusive 不等于「未检出」。',
          },
        });
      }
      case 'ping':
        return json({ jsonrpc: '2.0', id, result: {} });
      case 'tools/list':
        return json({ jsonrpc: '2.0', id, result: { tools: listTools() } });
      case 'tools/call': {
        const name = params && typeof params.name === 'string' ? params.name : '';
        if (!name) {
          return json({ jsonrpc: '2.0', id, error: rpcErr(RPC_ERRORS.INVALID_PARAMS, 'tools/call 缺少 name') });
        }
        const tool = listTools().find((t) => t.name === name);
        if (!tool) {
          return json({
            jsonrpc: '2.0',
            id,
            error: rpcErr(RPC_ERRORS.INVALID_PARAMS, `未知工具：${name}（tools/list 查看可用清单）`),
          });
        }
        const args = params.arguments && typeof params.arguments === 'object' ? params.arguments : {};
        try {
          const result = await callTool(name, args);
          return json({ jsonrpc: '2.0', id, result });
        } catch (e) {
          // 工具层抛出 = 实现 bug（工具自身的业务错误必须转成 isError 结果）
          return json({
            jsonrpc: '2.0',
            id,
            result: {
              content: [{ type: 'text', text: `工具内部错误：${e?.message || String(e)}` }],
              isError: true,
            },
          });
        }
      }
      default:
        return json({
          jsonrpc: '2.0',
          id,
          error: rpcErr(RPC_ERRORS.METHOD_NOT_FOUND, `未知方法：${method}`),
        });
    }
  }

  return { handle };
}

function rpcErr(code, message) {
  return { code, message };
}

function json(obj) {
  // NDJSON 分帧：一条消息必须恰好一行 —— 内容里的换行由 JSON.stringify 转义保证
  return JSON.stringify(obj);
}
