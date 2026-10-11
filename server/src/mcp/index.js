// ============================================================================
// index.js —— MCP stdio 入口：`node server/bin/cli.js mcp`
//
// [D43 2026-10-11] 对标 `dalfox mcp` / `semgrep mcp`：「MCP 是 CLI 的一个模式」——
// 不另起端口、不另起进程，stdin/stdout NDJSON 直连（AI 代理的宿主进程负责拉起）。
//
// 循环纪律：
//   · 一行 = 一条 JSON-RPC 消息（MCP stdio transport 分帧）；协议层保证输出恰好一行。
//   · 任何单条消息的失败都不得杀死循环 —— 代理侧一次 malformed 输入就断连太脆。
//   · stdout 只写 MCP 消息；日志一律走 stderr（logger 已是 stderr）—— 混流会把
//     客户端的解析器打炸，这是 stdio 服务的头号事故源。
// ============================================================================
import { createInterface } from 'node:readline';
import { ScanManager } from '../engine/ScanManager.js';
import { createMcpServer } from './protocol.js';
import { createToolContext, buildToolDispatch } from './tools.js';
import { ENGINE_VERSION as version } from '../core/version.js';

/**
 * 运行 MCP stdio 循环（阻塞至 stdin 关闭）。
 * @param {{scanManager?: object}} [deps] 测试可注入假 ScanManager
 */
export async function runMcpStdio(deps = {}) {
  const ctx = createToolContext({ scanManager: deps.scanManager || new ScanManager() });
  const dispatch = buildToolDispatch(ctx);
  const server = createMcpServer({
    serverInfo: { name: 'sqli-scanner', version: version || '0.0.0' },
    listTools: dispatch.listTools,
    callTool: dispatch.callTool,
  });

  const rl = createInterface({ input: process.stdin, terminal: false });
  const write = (s) => {
    if (!process.stdout.writableEnded) process.stdout.write(s + '\n');
  };

  const done = new Promise((resolve) => {
    rl.on('line', (line) => {
      const trimmed = line.trim();
      if (!trimmed) return; // 空行：静默跳过（有些客户端会发 keep-alive 空行）
      Promise.resolve(server.handle(trimmed))
        .then((out) => {
          if (out) write(out);
        })
        .catch((e) => {
          // handle 内部已兜底；这里只防协议层自身的意外崩溃
          write(JSON.stringify({
            jsonrpc: '2.0', id: null,
            error: { code: -32603, message: `协议层内部错误：${e?.message || String(e)}` },
          }));
        });
    });
    rl.on('close', resolve);
  });

  // 就绪信号走 stderr（stdout 是纯协议通道）
  process.stderr.write(`[mcp] sqli-scanner MCP server ready（stdio，工具数 ${dispatch.listTools().length}）\n`);
  await done;
}
