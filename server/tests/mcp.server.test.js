// [D43 2026-10-11] MCP server 单测：协议层（纯函数）+ 工具层（假 ScanManager）+ 真靶场端到端
// + stdio 装配冒烟（spawn 子进程走 cli.js mcp）。
// 端到端复用 .env.test 的 SSRF_ALLOW_PRIVATE=1（本地回环靶点）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMcpServer, LATEST_PROTOCOL_VERSION } from '../src/mcp/protocol.js';
import { createToolContext, buildToolDispatch } from '../src/mcp/tools.js';
import { ScanManager } from '../src/engine/ScanManager.js';

const SERVER_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// ===== 协议层 =====
const SERVER_INFO = { name: 'sqli-scanner', version: '1.1.0' };
const noopTools = () => [{ name: 'noop', description: 'x', inputSchema: { type: 'object' } }];
const proto = createMcpServer({
  serverInfo: SERVER_INFO,
  listTools: noopTools,
  callTool: async () => ({ content: [{ type: 'text', text: 'ok' }] }),
});
const req = (id, method, params) => JSON.stringify({ jsonrpc: '2.0', id, method, params });

test('协议：initialize 回显受支持的 protocolVersion + serverInfo + tools 能力', async () => {
  const out = JSON.parse(await proto.handle(req(1, 'initialize', { protocolVersion: '2025-03-26' })));
  assert.equal(out.result.protocolVersion, '2025-03-26');
  assert.deepEqual(out.result.serverInfo, SERVER_INFO);
  assert.ok(out.result.capabilities.tools);
  const out2 = JSON.parse(await proto.handle(req(2, 'initialize', { protocolVersion: '1999-01-01' })));
  assert.equal(out2.result.protocolVersion, LATEST_PROTOCOL_VERSION);
});

test('协议：tools/list 带全 inputSchema；ping 回空；通知不回复', async () => {
  const out = JSON.parse(await proto.handle(req(3, 'tools/list')));
  assert.equal(out.result.tools.length, 1);
  assert.equal(out.result.tools[0].name, 'noop');
  const ping = JSON.parse(await proto.handle(req(4, 'ping')));
  assert.deepEqual(ping.result, {});
  assert.equal(await proto.handle(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })), null);
});

test('协议：tools/call 未知工具 → -32602；工具层抛错 → isError 结果；JSON 坏行 → -32700', async () => {
  const unknown = JSON.parse(await proto.handle(req(5, 'tools/call', { name: 'nope', arguments: {} })));
  assert.equal(unknown.error.code, -32602);
  const throwing = createMcpServer({ serverInfo: SERVER_INFO, listTools: noopTools, callTool: async () => { throw new Error('boom'); } });
  const boomed = JSON.parse(await throwing.handle(req(6, 'tools/call', { name: 'noop', arguments: {} })));
  assert.equal(boomed.result.isError, true);
  assert.ok(boomed.result.content[0].text.includes('boom'));
  const bad = JSON.parse(await proto.handle('{not json'));
  assert.equal(bad.error.code, -32700);
  const unknownMethod = JSON.parse(await proto.handle(req(7, 'resources/list')));
  assert.equal(unknownMethod.error.code, -32601);
});

// ===== 工具层（假 ScanManager）=====
function fakeManager() {
  const started = [];
  return {
    started,
    scans: new Map(),
    async start(sanitized) {
      started.push(sanitized);
      return 'scan123';
    },
    status(id) { return id === 'scan123' ? { scanId: id, status: 'running', vulns: 0, points: 3 } : null; },
    getReport(id) {
      if (id !== 'scan123') return null;
      return {
        scanId: id,
        dbms: 'MySQL',
        summary: { verdict: 'vulnerability_found' },
        vulns: [{ id: 'v1', technique: 'error', vulnType: { nameZh: '报错注入', cwe: 'CWE-89', owasp: 'A03:2021-Injection' }, riskLevel: 'High', param: 'id', location: 'url', url: 'http://t/?id=1', method: 'GET', payloads: ['x'], poc: { curl: "curl 'http://t/?id=1'", payload: "x'" }, cvss: { score: 8.6, severity: 'High', vector: 'AV:N/AC:L' }, remediation: '参数化' }],
      };
    },
    exportReport(id, fmt, reportArg) { return fmt === 'markdown' ? '# r' : JSON.stringify(reportArg); },
    stop() { return true; },
    pause() { return true; },
    resume() { return true; },
  };
}

const ctx = createToolContext({ scanManager: fakeManager() });
const dispatch = buildToolDispatch(ctx);
const call = (name, args) => dispatch.callTool(name, args);
const parse = (r) => JSON.parse(r.content[0].text);

test('工具：run_scan 过 sanitizeStart 闸（level clamp / technique 数组化 / cookie 参数化 / 高危确认位）', async () => {
  const r = parse(await call('run_scan', {
    url: 'http://shop.example.com/item?id=1',
    method: 'POST',
    body: '{"id":1,"tag":"a"}',
    cookie: 'sid=1; theme=dark',
    level: 99,
    technique: 'Error,Boolean',
    risk: 3,
    confirmDestructive: true,
  }));
  assert.equal(r.scanId, 'scan123');
  const sent = ctx.scanManager.started[0];
  assert.equal(sent.config.level, 5); // clamp 到 5
  assert.deepEqual(sent.config.techniques, ['error', 'boolean']);
  assert.equal(sent.config.confirmDestructive, true);
  // sanitizeStart 产物是扁平对象（url/method/cookieParams/... 与 config 并列，无 target 包裹）
  assert.deepEqual(sent.cookieParams, { sid: '1', theme: 'dark' });
  // 扁平 body → bodyParams（嵌套才走 jsonBody）；值经 clampParams 字符串化（闸口归一化）
  assert.deepEqual(sent.bodyParams, { id: '1', tag: 'a' });
});

test('工具：run_scan 缺 URL → isError 结果（业务错误不是协议内部错误）', async () => {
  const r = await call('run_scan', {});
  assert.equal(r.isError, true);
  assert.ok(r.content[0].text.includes('目标 URL'));
});

test('工具：get_findings 出四要素紧凑形态；get_scan_status 回落台账形态；stop/pause/resume 打通', async () => {
  const f = parse(await call('get_findings', { scanId: 'scan123' }));
  assert.equal(f.totalVulns, 1);
  assert.equal(f.findings[0].vulnType.cwe, 'CWE-89');
  assert.equal(f.findings[0].poc.curl, "curl 'http://t/?id=1'");
  // [D153] nextSteps：假报告 1 条未裁决发现 → 至少 triage + export 两条建议
  assert.ok(Array.isArray(f.nextSteps));
  const kinds = f.nextSteps.map((h) => h.kind);
  assert.ok(kinds.includes('triage'));
  assert.ok(kinds.includes('export'));
  assert.ok(f.nextSteps.every((h) => typeof h.text === 'string' && typeof h.via === 'string'));
  const st = parse(await call('get_scan_status', { scanId: 'scan123' }));
  assert.equal(st.status, 'running');
  const st2 = parse(await call('get_scan_status', { scanId: 'nope' }));
  assert.equal(st2.status, 'unknown');
  const sp = parse(await call('stop_scan', { scanId: 'scan123' }));
  assert.equal(sp.stopped, true);
  const rep = await call('get_report', { scanId: 'scan123', format: 'markdown' });
  assert.equal(rep.content[0].text, '# r');
});

// ===== 真靶场端到端：in-process ScanManager + 本地易受攻击 HTTP 服务 =====
test('端到端：本地靶点 run_scan → 轮询 → get_findings 检出 error 注入', { timeout: 120000 }, async () => {
  // sqli-labs 形态：200 页内回显**真实 SQLite 报错文本**（sqlite3.OperationalError: unrecognized token）。
  // 注意两件事：① 必须 200 页内回显——500+JSON 会被 prefilter 判成输入校验（TODO D34 笔记）；
  // ② 报错文本必须命中通用 ERROR_SIG（含 "SQLite3"/"SQL syntax" 等真实形态）——裸
  //    "unrecognized token" 是 2026-10-01 收紧后的**指纹表专属**签名，通用判定不收（防前端 5xx 误报），
  //    故靶点用 Python sqlite3 驱动的真实报错前缀，而不是自造文案。
  const server = createServer((rq, rs) => {
    const u = new URL(rq.url, 'http://x');
    const id = u.searchParams.get('id') || '';
    rs.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    if (/'/.test(id)) {
      rs.end(`<html><body>Warning: sqlite3.OperationalError: unrecognized token: &quot;${id}&quot; in query SELECT * FROM items WHERE id=${id}</body></html>`);
    } else {
      rs.end(`<html><body><h1>Item ${id}</h1><p>static footer ${Math.random() > 2}</p></body></html>`);
    }
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const targetUrl = `http://127.0.0.1:${port}/item?id=1`;

  const e2eCtx = createToolContext({ scanManager: new ScanManager() });
  const e2e = buildToolDispatch(e2eCtx);

  // preflight 先行（零 payload）：必须可达且发现 id 参数
  const pre = JSON.parse((await e2e.callTool('preflight', { url: targetUrl })).content[0].text);
  assert.equal(pre.reachable, true);
  assert.equal(pre.baseline.status, 200);
  assert.ok(pre.points.some((p) => p.location === 'url' && p.param === 'id'), `preflight 应发现 id 参数：${JSON.stringify(pre.points)}`);

  const run = JSON.parse((await e2e.callTool('run_scan', { url: targetUrl, technique: 'error', level: 1, timeoutMs: 90000 })).content[0].text);
  assert.ok(run.scanId, 'run_scan 应返回 scanId');
  // 轮询到终态（上限 100s；本地靶点实测秒级）。终态值源：ScanManager（completed/error/stopped）
  const sm = e2eCtx.scanManager;
  let st = null;
  try {
    for (let i = 0; i < 200; i++) {
      await new Promise((r) => setTimeout(r, 500));
      st = sm.status(run.scanId);
      if (!st || ['completed', 'error', 'stopped'].includes(st.status)) break;
    }
    assert.ok(st && ['completed', 'error'].includes(st.status), `扫描应到终态，实际：${JSON.stringify(st)}`);
    assert.equal(st.status, 'completed');

    const findings = JSON.parse((await e2e.callTool('get_findings', { scanId: run.scanId })).content[0].text);
    assert.ok(findings.totalVulns >= 1, `本地注入靶点应至少检出 1 条，实际 ${findings.totalVulns}（verdict=${findings.verdict}）`);
    assert.equal(findings.findings[0].vulnType.cwe, 'CWE-89');
    assert.ok(findings.findings[0].affectedParam === 'id');
  } finally {
    // 清理必须无条件执行：监听中的 server 会钉住事件循环，测试进程永不退出
    //（上一版 server.close() 在断言之后，断言一抛就成了全文件挂死 + 零输出）
    server.close();
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
  }
});

// ===== stdio 装配冒烟：spawn cli.js mcp =====
test('stdio：spawn 子进程完成握手 + tools/list（NDJSON 分帧）', { timeout: 30000 }, async () => {
  const child = spawn(process.execPath, [path.join(SERVER_DIR, 'bin', 'cli.js'), 'mcp'], {
    env: { ...process.env },
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  try {
    const lines = [];
    let buf = '';
    child.stdout.setEncoding('utf-8');
    child.stdout.on('data', (c) => {
      buf += c;
      let idx;
      while ((idx = buf.indexOf('\n')) >= 0) {
        lines.push(buf.slice(0, idx));
        buf = buf.slice(idx + 1);
      }
    });
    const waitLines = async (n, ms = 15000) => {
      const t0 = Date.now();
      while (lines.length < n && Date.now() - t0 < ms) await new Promise((r) => setTimeout(r, 100));
      return lines;
    };
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }) + '\n');
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) + '\n');
    await waitLines(2);
    assert.equal(lines.length, 2, `应收到 2 条响应（通知不回复），实际 ${lines.length}`);
    const init = JSON.parse(lines[0]);
    assert.equal(init.result.protocolVersion, '2025-06-18');
    assert.equal(init.result.serverInfo.name, 'sqli-scanner');
    const tools = JSON.parse(lines[1]);
    const names = tools.result.tools.map((t) => t.name);
    for (const expected of ['run_scan', 'get_scan_status', 'get_findings', 'get_report', 'list_scans', 'stop_scan', 'pause_scan', 'resume_scan', 'preflight']) {
      assert.ok(names.includes(expected), `tools/list 应含 ${expected}，实际：${names.join(',')}`);
    }
  } finally {
    child.kill();
  }
});
