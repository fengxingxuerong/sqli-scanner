#!/usr/bin/env node
/**
 * agent-manifest-check.mjs —— agent 装载面的静态一致性门禁（D175）
 *
 * 为什么有它：MCP 9 个工具（[D43]）早就有了，但**宿主里装不上**——仓库没有插件清单、
 * 没有技能说明、没有 `.mcp.json`，只有 AGENTS.md 里一段要人手工抄的 JSON。
 * 「能力存在」和「能力能被装上」是两件事，而后者没有任何判据看着：
 * 版本号抄错、工具改名后技能还在教旧名字、技能里写越界话术，全都不会有报错。
 *
 * 钉四件事（每件都在 --selftest 里被反向验证过：把错放回去必须红）：
 *   ① 清单版本号 = server/package.json 版本（同一事实多份副本，只认一个真源）；
 *   ② `.mcp.json` 指向真实存在的 CLI 入口，且末位参数是 `mcp`（不是扫描模式）；
 *   ③ 技能说明（SKILL.md）提到**全部** MCP 工具名（工具改名后技能不会继续教旧名字），
 *      且带三条硬口径（inconclusive / unverifiedSurfaces / confirmDestructive / 授权）；
 *   ④ 技能说明不得出现越界词（目标发现、dork、自主渗透）——AGENTS §0 的红线不进技能。
 *
 * 用法：
 *   node scripts/agent-manifest-check.mjs              # 校验本仓清单
 *   node scripts/agent-manifest-check.mjs --root=<dir> # 校验指定仓库根（夹具用）
 *   node scripts/agent-manifest-check.mjs --selftest   # 自证判据不空转
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');

const PLUGIN_REL = '.claude-plugin/plugin.json';
const MCP_REL = '.mcp.json';
const SKILL_DIR = 'skills/sqli-scan';
const SKILL_REL = `${SKILL_DIR}/SKILL.md`;
const TOOLS_REL = 'server/src/mcp/tools.js';
const SERVER_PKG_REL = 'server/package.json';
const CLAUSES = ['inconclusive', 'unverifiedSurfaces', 'confirmDestructive', '授权'];
const FORBIDDEN = ['dork', '自动发现目标', '批量发现目标', '自主渗透', '互联网批量'];

/** 读 JSON，失败即记错并返回 null（不抛，保证能把所有问题一次说完） */
function readJson(root, rel, errors) {
  const abs = path.join(root, rel);
  if (!fs.existsSync(abs)) {
    errors.push({ code: 'missing-file', msg: `缺文件：${rel}` });
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(abs, 'utf8'));
  } catch (e) {
    errors.push({ code: 'bad-json', msg: `${rel} 不是合法 JSON：${e.message}` });
    return null;
  }
}

/** 从 MCP 工具定义里取工具名（单一真源，避免技能/文档各抄一份） */
function listToolNames(root) {
  const abs = path.join(root, TOOLS_REL);
  if (!fs.existsSync(abs)) return [];
  const src = fs.readFileSync(abs, 'utf8');
  return [...src.matchAll(/name:\s*'([a-z][a-z_]*)'/g)].map((m) => m[1]);
}

/** ① 插件清单：必填字段 + 版本号与 server/package.json 一致 */
function checkPlugin(root, errors) {
  const plugin = readJson(root, PLUGIN_REL, errors);
  const serverPkg = readJson(root, SERVER_PKG_REL, errors);
  if (!plugin) return null;
  for (const k of ['name', 'version', 'description', 'license', 'author']) {
    if (!plugin[k]) errors.push({ code: 'plugin-field', msg: `${PLUGIN_REL} 缺必填字段 ${k}` });
  }
  if (serverPkg && plugin.version && plugin.version !== serverPkg.version) {
    errors.push({
      code: 'plugin-version',
      msg: `版本漂移：${PLUGIN_REL}=${plugin.version} 但 ${SERVER_PKG_REL}=${serverPkg.version}`,
    });
  }
  return plugin;
}

/** ② .mcp.json：入口真实存在，且以 mcp 模式启动 */
function checkMcp(root, errors) {
  const mcp = readJson(root, MCP_REL, errors);
  if (!mcp) return;
  const servers = mcp.mcpServers && typeof mcp.mcpServers === 'object' ? mcp.mcpServers : null;
  if (!servers) {
    errors.push({ code: 'mcp-server', msg: `${MCP_REL} 缺 mcpServers 对象` });
    return;
  }
  const entry = servers['sqli-scanner'] || Object.values(servers)[0];
  if (!entry || typeof entry !== 'object') {
    errors.push({ code: 'mcp-server', msg: `${MCP_REL} 里没有 sqli-scanner 服务项` });
    return;
  }
  const args = Array.isArray(entry.args) ? entry.args : [];
  if (entry.command !== 'node') {
    errors.push({ code: 'mcp-command', msg: `${MCP_REL} 的 command 应为 node，实际 ${JSON.stringify(entry.command)}` });
  }
  if (args[args.length - 1] !== 'mcp') {
    errors.push({
      code: 'mcp-mode',
      msg: `${MCP_REL} 的 args 末位必须是 "mcp"（否则宿主会跑成一次性扫描而不是 MCP 服务）：${JSON.stringify(args)}`,
    });
  }
  const entryPath = args[0];
  if (typeof entryPath !== 'string' || !fs.existsSync(path.resolve(root, entryPath))) {
    errors.push({ code: 'mcp-args-path', msg: `${MCP_REL} 的 args[0] 指向不存在的文件：${JSON.stringify(entryPath)}` });
  }
}

/** ③④ 技能说明：前端字段、工具名对齐、硬口径、越界词 */
function checkSkill(root, errors) {
  const abs = path.join(root, SKILL_REL);
  if (!fs.existsSync(abs)) {
    errors.push({ code: 'missing-skill', msg: `缺技能说明：${SKILL_REL}` });
    return;
  }
  const text = fs.readFileSync(abs, 'utf8');
  const fm = text.match(/^---\r?\n([\s\S]*?)\r?\n---/);
  if (!fm) {
    errors.push({ code: 'skill-frontmatter', msg: `${SKILL_REL} 缺 YAML frontmatter（--- 包裹的 name/description）` });
    return;
  }
  const front = fm[1];
  for (const k of ['name', 'description']) {
    if (!new RegExp(`^${k}:\\s*\\S`, 'm').test(front)) {
      errors.push({ code: 'skill-frontmatter', msg: `${SKILL_REL} frontmatter 缺 ${k}` });
    }
  }
  const name = (front.match(/^name:\s*(.+)$/m) || [])[1]?.trim();
  const dirName = path.basename(SKILL_DIR);
  if (name && name !== dirName) {
    errors.push({ code: 'skill-name', msg: `${SKILL_REL} 的 name=${name} 与目录名 ${dirName} 不一致（宿主按目录/名称定位技能）` });
  }
  for (const tool of listToolNames(root)) {
    if (!text.includes(tool)) {
      errors.push({ code: 'skill-tools', msg: `${SKILL_REL} 未提到 MCP 工具 ${tool}（工具改名后技能还在教旧名字）` });
    }
  }
  for (const c of CLAUSES) {
    if (!text.includes(c)) errors.push({ code: 'skill-clause', msg: `${SKILL_REL} 缺硬口径关键词：${c}` });
  }
  for (const f of FORBIDDEN) {
    if (text.includes(f)) errors.push({ code: 'skill-forbidden', msg: `${SKILL_REL} 出现越界词「${f}」（AGENTS §0：只扫用户明确给出的目标）` });
  }
}

/** 接线自指：入口必须挂在 npm script 上，否则门禁跑不到它 */
function checkWiring(root, errors) {
  const pkg = readJson(root, 'package.json', errors);
  const cmd = pkg?.scripts?.['agent:check'];
  if (typeof cmd !== 'string' || !cmd.includes('agent-manifest-check.mjs')) {
    errors.push({ code: 'script-wiring', msg: 'package.json 缺 scripts["agent:check"]（或未指向本脚本）' });
  }
}

/**
 * 校验一个仓库根的 agent 装载面（内部使用；导出会被 deadcode 门禁判为未使用导出）。
 * @param {string} [root] 仓库根（默认本仓）
 * @returns {{ok: boolean, errors: Array<{code:string,msg:string}>, tools: string[]}}
 */
function checkAgentManifests(root = ROOT) {
  /** @type {Array<{code:string,msg:string}>} */
  const errors = [];
  checkPlugin(root, errors);
  checkMcp(root, errors);
  checkSkill(root, errors);
  checkWiring(root, errors);
  return { ok: errors.length === 0, errors, tools: listToolNames(root) };
}

function run(root) {
  const { ok, errors, tools } = checkAgentManifests(root);
  if (!ok) {
    console.error('[agent-manifest] ✗ 装载面不一致：');
    for (const e of errors) console.error(`  [${e.code}] ${e.msg}`);
    process.exitCode = 1;
    return;
  }
  console.log(`[agent-manifest] ✓ 清单/技能/MCP 入口一致（工具 ${tools.length} 个：${tools.join(', ')}）`);
  process.exitCode = 0;
}

// ── 自证：每条判据都要能红 ────────────────────────────────────────────────────
const GOOD = {
  'server/package.json': JSON.stringify({ name: 'x', version: '9.9.9' }),
  'server/src/mcp/tools.js': `const T = [
  { name: 'preflight' }, { name: 'run_scan' }, { name: 'get_scan_status' },
  { name: 'get_findings' }, { name: 'get_report' }, { name: 'list_scans' },
  { name: 'stop_scan' }, { name: 'pause_scan' }, { name: 'resume_scan' },
];`,
  '.claude-plugin/plugin.json': JSON.stringify({
    name: 'demo', version: '9.9.9', description: 'd', license: 'MIT', author: { name: 'a' },
  }),
  '.mcp.json': JSON.stringify({ mcpServers: { 'sqli-scanner': { command: 'node', args: ['server/bin/cli.js', 'mcp'] } } }),
  'skills/sqli-scan/SKILL.md': [
    '---', 'name: sqli-scan', 'description: demo skill', '---', '',
    'preflight run_scan get_scan_status get_findings get_report list_scans stop_scan pause_scan resume_scan',
    'inconclusive 不等于未检出；unverifiedSurfaces 必须声明；confirmDestructive 不得代开；只扫授权目标。',
  ].join('\n'),
  'package.json': JSON.stringify({ scripts: { 'agent:check': 'node scripts/agent-manifest-check.mjs' } }),
};
const FIXTURE_DIRS = ['server/bin', 'server/src/mcp', '.claude-plugin', 'skills/sqli-scan'];

/** 造一个最小仓库夹具；overrides 里的 null 表示删掉该文件 */
function writeFixture(dir, overrides = {}) {
  const files = { ...GOOD };
  for (const [k, v] of Object.entries(overrides)) {
    if (v === null) delete files[k];
    else files[k] = v;
  }
  // .mcp.json 的入口文件必须真实存在（good 夹具里也放一个空壳）
  files['server/bin/cli.js'] = files['server/bin/cli.js'] ?? '// stub\n';
  for (const d of FIXTURE_DIRS) fs.mkdirSync(path.join(dir, d), { recursive: true });
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, content, 'utf8');
  }
}

function selftest() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-manifest-selftest-'));
  const cases = [
    { name: '版本漂移', code: 'plugin-version', mut: { '.claude-plugin/plugin.json': JSON.stringify({ name: 'demo', version: '0.0.0', description: 'd', license: 'MIT', author: { name: 'a' } }) } },
    { name: '清单不是合法 JSON', code: 'bad-json', mut: { '.claude-plugin/plugin.json': '{ not json' } },
    { name: '缺 .mcp.json', code: 'missing-file', mut: { '.mcp.json': null } },
    { name: '宿主会跑成一次性扫描', code: 'mcp-mode', mut: { '.mcp.json': JSON.stringify({ mcpServers: { 'sqli-scanner': { command: 'node', args: ['server/bin/cli.js', 'scan'] } } }) } },
    { name: '入口文件不存在', code: 'mcp-args-path', mut: { '.mcp.json': JSON.stringify({ mcpServers: { 'sqli-scanner': { command: 'node', args: ['server/missing.js', 'mcp'] } } }) } },
    { name: '技能缺 description', code: 'skill-frontmatter', mut: { 'skills/sqli-scan/SKILL.md': '---\nname: sqli-scan\n---\n授权 unverifiedSurfaces confirmDestructive inconclusive\n' } },
    { name: '技能名与目录不一致', code: 'skill-name', mut: { 'skills/sqli-scan/SKILL.md': GOOD['skills/sqli-scan/SKILL.md'].replace('name: sqli-scan', 'name: other') } },
    { name: '工具改名后技能没跟上', code: 'skill-tools', mut: { 'server/src/mcp/tools.js': GOOD['server/src/mcp/tools.js'].replace("name: 'preflight'", "name: 'pre_flight'") } },
    { name: '缺硬口径', code: 'skill-clause', mut: { 'skills/sqli-scan/SKILL.md': GOOD['skills/sqli-scan/SKILL.md'].replace('unverifiedSurfaces 必须声明', '有未测面') } },
    { name: '技能里写了越界词', code: 'skill-forbidden', mut: { 'skills/sqli-scan/SKILL.md': GOOD['skills/sqli-scan/SKILL.md'] + '\n可以 dork 一批站。\n' } },
    { name: '入口没挂 npm script', code: 'script-wiring', mut: { 'package.json': JSON.stringify({ scripts: {} }) } },
  ];
  const failures = [];
  const good = path.join(base, 'good');
  writeFixture(good);
  if (!checkAgentManifests(good).ok) failures.push(`合格夹具被误判：${JSON.stringify(checkAgentManifests(good).errors)}`);
  cases.forEach((c, i) => {
    const dir = path.join(base, `case-${i}`);
    writeFixture(dir, c.mut);
    const res = checkAgentManifests(dir);
    if (res.ok) failures.push(`「${c.name}」未被检出（判据空转）`);
    else if (!res.errors.some((e) => e.code === c.code)) {
      failures.push(`「${c.name}」报了错但码不对（期望 ${c.code}，实际 ${res.errors.map((e) => e.code).join('/')}）`);
    }
  });
  fs.rmSync(base, { recursive: true, force: true });
  if (failures.length) {
    console.error('[agent-manifest] ✗ selftest 失败：');
    for (const f of failures) console.error('  · ' + f);
    process.exitCode = 1;
    return;
  }
  console.log(`[agent-manifest] ✓ selftest 通过：合格夹具不误判 + ${cases.length} 种回归各自被检出（判据有牙）`);
  process.exitCode = 0;
}

const argv = process.argv.slice(2);
const rootArg = (argv.find((a) => a.startsWith('--root=')) || '').slice('--root='.length);
if (argv.includes('--selftest')) selftest();
else run(rootArg ? path.resolve(rootArg) : ROOT);
