#!/usr/bin/env node
/**
 * mcp-client-compat.mjs —— MCP 客户端 / 智能体宿主「连接兼容性」矩阵（真 stdio 子进程）
 *
 * 为什么存在：docs/agent-装载.md §五 挂着「宿主矩阵未实测」——已有的
 * server/tests/mcp.server.test.js 只验了一条最规整的握手（initialize → initialized →
 * tools/list），而真实宿主在协议版本、id 形态、通知习惯、探测方法、行尾、坏输入后的
 * 存活上各不相同。装不装得上，取决于这些边角，而不是那条 happy path。
 *
 * 判据口径（不 mock 引擎）：每个画像都真 spawn `node server/bin/cli.js mcp`，
 * 按该宿主的真实字节序列写 stdin，读 stdout 的每一行；挂住 = 超时 = FAIL。
 * 边界：这是「客户端形态仿真」，不是 Claude Code / Cursor 真机装载；结论只覆盖
 * stdio 协议面，不覆盖宿主 GUI 的插件发现、信任弹窗与配置解析。
 *
 * 用法：
 *   node scripts/mcp-client-compat.mjs                 # 跑矩阵，结果落 logs/mcp-compat/
 *   node scripts/mcp-client-compat.mjs --selftest     # 自证判据有牙（坏 server 必须被抓）
 *   node scripts/mcp-client-compat.mjs --json         # 只输出 JSON（CI 消费）
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const CLI = path.join(ROOT, 'server', 'bin', 'cli.js');
const OUT_FILE = path.join(ROOT, 'logs', 'mcp-compat', 'compat-matrix.json');
const WAIT_MS = 3500;
const PROBE_ID = '__compat_probe__';

const j = (o) => JSON.stringify(o);
const req = (id, method, params) => j({ jsonrpc: '2.0', id, method, ...(params === undefined ? {} : { params }) });
const notif = (method, params) => j({ jsonrpc: '2.0', method, ...(params === undefined ? {} : { params }) });
const initFrame = (id, version, extra) => j({
  jsonrpc: '2.0', id, method: 'initialize',
  params: {
    ...(version === undefined ? {} : { protocolVersion: version }),
    clientInfo: { name: 'compat-probe', version: '1.0' },
    capabilities: {},
    ...(extra || {}),
  },
});
const fail = (code, msg) => ({ code, msg });

/**
 * 每个画像 = 一种智能体宿主的连接习惯。frames 是「完整一行」的原始字节（可带 BOM/\r）；
 * expectIds 是必须收到同 id 响应的请求；check 追加画像专属判据。
 */
const PROFILES = [
  {
    id: 'claude-code/2024-11-05',
    note: '旧协议版本 + 三步握手 + 资源/提示无脑探测',
    frames: [initFrame(1, '2024-11-05'), notif('notifications/initialized'), req(2, 'tools/list'), req(3, 'resources/list'), req(4, 'prompts/list')],
    expectIds: [1, 2, 3, 4],
    check: ({ byId }) => {
      const out = [];
      if (byId(1)?.result?.protocolVersion !== '2024-11-05') out.push(fail('version-echo', 'initialize 未回显客户端请求的 2024-11-05'));
      if (!Array.isArray(byId(2)?.result?.tools) || byId(2).result.tools.length < 1) out.push(fail('tools-list', 'tools/list 未返回工具清单'));
      if (byId(3)?.error) out.push(fail('resources-probe', 'resources/list 回 error；宽容宿主会把「不支持」当成握手失败'));
      if (byId(4)?.error) out.push(fail('prompts-probe', 'prompts/list 回 error；同上'));
      if (byId(1)?.result?.instructions !== undefined) out.push(fail('instructions-leak', '2024-11-05 响应带了 2025-03-26 才有的 instructions 字段'));
      return out;
    },
  },
  {
    id: 'cursor/2025-03-26',
    note: '省略 notifications/initialized，直接列工具',
    frames: [initFrame(1, '2025-03-26'), req(2, 'tools/list')],
    expectIds: [1, 2],
    check: ({ byId }) => (byId(1)?.result?.protocolVersion === '2025-03-26' ? [] : [fail('version-echo', '未回显 2025-03-26')]),
  },
  {
    id: 'vscode/2025-06-18',
    note: '字符串 id + ping + 一次真实 tools/call（list_scans，零网络副作用）',
    frames: [initFrame('init-1', '2025-06-18'), notif('notifications/initialized'), req(2, 'tools/list'), req(3, 'ping'), req(4, 'tools/call', { name: 'list_scans', arguments: {} })],
    expectIds: ['init-1', 2, 3, 4],
    check: ({ byId }) => {
      const out = [];
      if (byId('init-1')?.result?.protocolVersion !== '2025-06-18') out.push(fail('string-id', '字符串 id 未被正确回显'));
      if (!byId('init-1')?.result?.instructions) out.push(fail('instructions-missing', '2025-06-18 响应缺 instructions 使用说明'));
      if (byId(4)?.result?.isError) out.push(fail('tools-call', 'list_scans 返回 isError'));
      return out;
    },
  },
  {
    id: 'inspector/future-version',
    note: '客户端请求服务端不认识的未来版本，应协商回落且不挂住',
    frames: [initFrame(1, '2099-01-01'), req(2, 'tools/list')],
    expectIds: [1, 2],
    check: ({ byId }) => {
      const v = byId(1)?.result?.protocolVersion;
      return typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v)
        ? [] : [fail('version-fallback', `未来版本未回落到合法 protocolVersion：${String(v)}`)];
    },
  },
  {
    id: 'legacy/no-initialize-params',
    note: '老客户端 initialize 不带 params',
    frames: [initFrame(1, undefined), req(2, 'tools/list')],
    expectIds: [1, 2],
  },
  {
    id: 'jsonrpc/id-null',
    note: 'id 为 null 的合法请求（JSON-RPC 2.0 允许但不推荐）——等不到回复就会挂死宿主',
    frames: [initFrame(1, '2025-06-18'), req(null, 'tools/list')],
    expectIds: [1, null],
  },
  {
    id: 'jsonrpc/id-zero',
    note: 'id 为 0（falsy，常被误判成「无 id」）',
    frames: [initFrame(0, '2025-06-18'), req(0, 'tools/list')],
    expectIds: [0],
  },
  {
    id: 'notif/with-id',
    note: '把 initialized 通知误带 id 的宿主：通知不该收到响应',
    frames: [initFrame(1, '2025-06-18'), req('n1', 'notifications/initialized'), req(2, 'tools/list')],
    expectIds: [1, 2],
    check: ({ byId }) => (byId('n1') ? [fail('notif-replied', 'notifications/* 带了响应（宽容宿主会把它当失败响应）')] : []),
  },
  {
    id: 'windows/crlf-bom-blank',
    note: 'CRLF 行尾 + 首行 UTF-8 BOM + keep-alive 空行',
    frames: ['\uFEFF' + initFrame(1, '2025-06-18') + '\r', '', req(2, 'tools/list') + '\r'],
    expectIds: [1, 2],
  },
  {
    id: 'robust/malformed-then-valid',
    note: '先送坏 JSON，服务必须继续活着',
    frames: ['{not json', initFrame(1, '2025-06-18'), req(2, 'tools/list')],
    expectIds: [1, 2],
    check: ({ replies }) => (replies.some((r) => r?.error?.code === -32700) ? [] : [fail('parse-error', '坏 JSON 未回 -32700')]),
  },
  {
    id: 'robust/jsonrpc-batch',
    note: 'JSON-RPC batch（数组）：可不处理，但不得挂住后续请求',
    frames: [j([{ jsonrpc: '2.0', id: 1, method: 'ping' }, { jsonrpc: '2.0', id: 2, method: 'ping' }]), req(9, 'tools/list')],
    expectIds: [9],
  },
  {
    id: 'robust/lsp-framing',
    note: '误用 LSP Content-Length 分帧：每行都坏，但不能杀死 stdio 循环',
    frames: ['Content-Length: 2', '', '{}', req(2, 'tools/list')],
    expectIds: [2],
  },
  {
    id: 'robust/keepalive-and-unknown-notif',
    note: '空行 + cancelled/logging 等未知通知，之后仍可列工具',
    frames: ['', notif('notifications/cancelled', { requestId: 1 }), notif('logging/setLevel', { level: 'info' }), req(1, 'tools/list')],
    expectIds: [1],
  },
  {
    id: 'concurrent/pipeline',
    note: '三条请求连发（tools/call 异步）：每个 id 都必须有响应',
    frames: [req(1, 'tools/call', { name: 'list_scans', arguments: {} }), req(2, 'ping'), req(3, 'tools/list')],
    expectIds: [1, 2, 3],
  },
];

/** 启动一次 stdio 会话，返回可轮询的状态对象 */
function startSession(cmd, args) {
  const child = spawn(cmd, args, { cwd: ROOT, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  const state = { replies: [], rawLines: [], badLines: [], stderr: '', exited: false, exitCode: null };
  let buf = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      state.rawLines.push(line);
      const trimmed = line.trim();
      if (!trimmed) continue;
      try { state.replies.push(JSON.parse(trimmed)); } catch { state.badLines.push(line); }
    }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { state.stderr += chunk; });
  child.on('exit', (code) => { state.exited = true; state.exitCode = code; });
  child.on('error', (e) => { state.stderr += String(e?.message || e); });
  return { child, state };
}

async function waitFor(predicate, ms = WAIT_MS) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) {
    if (predicate()) return true;
    await new Promise((r) => setTimeout(r, 20));
  }
  return predicate();
}

const byIdOf = (state) => (id) => state.replies.find((r) => r && Object.prototype.hasOwnProperty.call(r, 'id') && r.id === id);
const hasId = (state, id) => Boolean(byIdOf(state)(id));

function evaluate(profile, state, mainOk, probeOk) {
  const failures = [];
  if (state.badLines.length) failures.push(fail('ndjson-impure', `stdout 有 ${state.badLines.length} 行非 JSON（日志混流会打炸宿主解析器）：${state.badLines[0].slice(0, 80)}`));
  const badEnvelope = state.replies.find((r) => r?.jsonrpc !== '2.0');
  if (badEnvelope) failures.push(fail('ndjson-envelope', 'stdout 出现非 JSON-RPC 2.0 信封的响应'));
  if (!mainOk) {
    const missing = profile.expectIds.filter((id) => !hasId(state, id));
    failures.push(fail('missing-id', `等不到响应（挂住）：id = ${JSON.stringify(missing)}`));
  }
  if (!probeOk) failures.push(fail('probe-dead', state.exited ? `服务提前退出（exit ${state.exitCode}），连接已断` : '握手后 tools/list 探针无响应，连接已挂'));
  if (profile.check) failures.push(...profile.check({ byId: byIdOf(state), replies: state.replies, state }));
  return failures;
}

/** 跑一个画像；cmd/args 可替换成 selftest 的坏 server 夹具 */
async function runProfile(profile, cmd = process.execPath, args = [CLI, 'mcp']) {
  const { child, state } = startSession(cmd, args);
  try {
    for (const frame of profile.frames) child.stdin.write(frame + '\n');
    const mainOk = await waitFor(() => profile.expectIds.every((id) => hasId(state, id)));
    child.stdin.write(req(PROBE_ID, 'tools/list') + '\n');
    const probeOk = await waitFor(() => hasId(state, PROBE_ID));
    const failures = evaluate(profile, state, mainOk, probeOk);
    return { id: profile.id, note: profile.note, ok: failures.length === 0, failures, stdoutLines: state.rawLines.length, replies: state.replies.length, stderr: state.stderr.slice(0, 400) };
  } finally {
    if (!child.killed) child.kill();
  }
}

function writeReport(report) {
  fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
  fs.writeFileSync(OUT_FILE, JSON.stringify(report, null, 2), 'utf8');
}

function printReport(report, asJson) {
  if (asJson) { console.log(JSON.stringify(report, null, 2)); return; }
  console.log(`[mcp-compat] MCP 客户端连接兼容性矩阵（真 stdio，${report.profiles.length} 个宿主画像）`);
  for (const p of report.profiles) {
    console.log(`  ${p.ok ? 'PASS' : 'FAIL'}  ${p.id.padEnd(38)} ${p.note}`);
    for (const f of p.failures) console.log(`        · [${f.code}] ${f.msg}`);
  }
  console.log(`[mcp-compat] ${report.passed}/${report.profiles.length} 通过；结果：${OUT_FILE}`);
}

async function main() {
  const asJson = process.argv.includes('--json');
  const profiles = [];
  for (const p of PROFILES) profiles.push(await runProfile(p));
  const report = {
    at: new Date().toISOString(),
    transport: 'stdio/NDJSON',
    entry: 'node server/bin/cli.js mcp',
    boundary: '客户端形态仿真（真子进程 + 真协议字节），非 Claude Code / Cursor 真机插件装载',
    profiles,
    passed: profiles.filter((p) => p.ok).length,
  };
  writeReport(report);
  printReport(report, asJson);
  if (report.passed !== profiles.length) process.exitCode = 1;
}

// ── 自证：判据不能空转 ───────────────────────────────────────────────────────
const ECHO_SERVER = `
const readline = require('node:readline');
const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  const t = line.trim();
  if (!t) return;
  let m; try { m = JSON.parse(t); } catch { return; }
  if (m == null || !Object.prototype.hasOwnProperty.call(m, 'id')) return;
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: {} }) + '\\n');
});
`;
const FIXTURES = {
  good: ECHO_SERVER,
  noisy: `process.stdout.write('LOG server ready\\n');\n` + ECHO_SERVER,
  deaf: ECHO_SERVER.replace("if (m == null || !Object.prototype.hasOwnProperty.call(m, 'id')) return;", "if (m == null || m.id !== 1) return;"),
  dies: `const readline = require('node:readline');\nconst rl = readline.createInterface({ input: process.stdin, terminal: false });\nrl.on('line', () => process.exit(0));\n`,
};

// 缺陷注入复验夹具：把 D252 修前的协议行为原样注回去，
// 用来证明「空能力面 / id:null / 误带 id 的通知 / instructions 泄漏」四条新判据有牙。
const REGRESSION_SERVER = `
const readline = require('node:readline');
const rl = readline.createInterface({ input: process.stdin, terminal: false });
const send = (o) => process.stdout.write(JSON.stringify(o) + '\\n');
rl.on('line', (line) => {
  const t = line.trim();
  if (!t) return;
  let m; try { m = JSON.parse(t); } catch { send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); return; }
  if (m == null || !Object.prototype.hasOwnProperty.call(m, 'id')) return;
  if (m.id === null) return;
  if (m.method === 'initialize') {
    send({ jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2024-11-05', capabilities: { tools: {} }, serverInfo: { name: 'x', version: '0' }, instructions: 'inconclusive 不等于未检出' } });
  } else if (m.method === 'resources/list' || m.method === 'prompts/list') {
    send({ jsonrpc: '2.0', id: m.id, error: { code: -32601, message: 'Method not found' } });
  } else if (m.method === 'tools/list') {
    send({ jsonrpc: '2.0', id: m.id, result: { tools: [{ name: 'x' }] } });
  } else {
    send({ jsonrpc: '2.0', id: m.id, result: {} });
  }
});
`;

async function selftest() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mcp-compat-selftest-'));
  const probe = { id: 'selftest', note: 'ping + 探针', frames: [req(1, 'ping'), req(2, 'ping')], expectIds: [1, 2] };
  const results = {};
  const injected = {};
  try {
    for (const [name, src] of Object.entries(FIXTURES)) {
      const file = path.join(dir, `${name}.cjs`);
      fs.writeFileSync(file, src, 'utf8');
      results[name] = await runProfile(probe, process.execPath, [file]);
    }
    const regression = path.join(dir, 'regression.cjs');
    fs.writeFileSync(regression, REGRESSION_SERVER, 'utf8');
    for (const id of ['claude-code/2024-11-05', 'jsonrpc/id-null', 'notif/with-id']) {
      const p = PROFILES.find((x) => x.id === id);
      injected[id] = await runProfile(p, process.execPath, [regression]);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const problems = [];
  if (!results.good.ok) problems.push(`合格夹具被误判：${results.good.failures.map((f) => f.code).join('/')}`);
  if (!results.noisy.failures.some((f) => f.code === 'ndjson-impure')) problems.push('stdout 混日志未被检出');
  if (!results.deaf.failures.some((f) => f.code === 'missing-id')) problems.push('缺 id 响应未被检出');
  if (!results.dies.failures.some((f) => f.code === 'probe-dead')) problems.push('服务提前退出未被检出');
  const codes = (id) => injected[id].failures.map((f) => f.code);
  for (const c of ['resources-probe', 'prompts-probe', 'instructions-leak']) {
    if (!codes('claude-code/2024-11-05').includes(c)) problems.push(`缺陷注入后「${c}」判据未变红（判据恒绿）`);
  }
  if (!codes('jsonrpc/id-null').includes('missing-id')) problems.push('缺陷注入后「missing-id」判据未变红');
  if (!codes('notif/with-id').includes('notif-replied')) problems.push('缺陷注入后「notif-replied」判据未变红');
  if (problems.length) {
    console.error('[mcp-compat] ✗ selftest 失败：');
    for (const p of problems) console.error('  · ' + p);
    process.exitCode = 1;
    return;
  }
  console.log('[mcp-compat] ✓ selftest 通过：合格夹具不误判 + 混流/缺 id/提前退出被检出 + D252 四处缺陷注入后判据各自变红（共 5 条）');
}

if (process.argv.includes('--selftest')) await selftest();
else await main();
