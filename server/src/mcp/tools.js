// ============================================================================
// tools.js —— MCP 工具层：把 ScanManager / 台账 / TargetParser 暴露为 MCP tools
//
// [D43 2026-10-11] 工具集对标 dalfox mcp 的形态（run + 进度 + 结果 + **preflight**）：
//   run_scan / get_scan_status / get_findings / get_report / list_scans /
//   stop_scan / pause_scan / resume_scan / preflight
//
// 护栏继承（红线：MCP 不是旁路）：
//   · run_scan 走 **sanitizeStart 同一条闸**（KNOWN_CFG_KEYS 白名单 + clamp），与 REST 同源；
//   · SSRF/scope 由 ScanManager→HttpClient 在请求时逐跳执行（与 CLI/REST 相同，MCP 不加闸也不拆闸）；
//   · confirmDestructive / authorized 必须**显式传入**（代理不得替用户解锁高危池/利用面）；
//   · preflight 只做可达性 + 注入点发现（零 payload 投放），是代理安全用枪的第一步。
//
// 数据源口径与 REST 相同：内存里活着的扫描读 ScanManager，上下文回收后读台账
//（scanLedger.readReport），不存在「REST 有、MCP 没有」的取数面漂移。
// ============================================================================
import { sanitizeStart } from '../api/scanRoutes.js';
import { createTarget } from '../engine/models.js';
import { TargetParser } from '../engine/TargetParser.js';
import { httpClient } from '../core/httpClient.js';
import { listScans, readReport } from '../services/scanLedger.js';
import { parseHeaders } from '../../bin/cli/args.js';
import { parseCookiePairs, resolveBodyChannel } from '../../bin/cli/config.js';

const AUTH_NOTE =
  '仅限授权测试：只扫描你被明确授权的目标；verdict=inconclusive（会话失效/签名被拒等）不等于「未检出」。';

/**
 * 组装工具依赖（测试可注入假 ScanManager）。
 * @param {{scanManager?: object}} [deps]
 */
export function createToolContext(deps = {}) {
  const scanManager = deps.scanManager || null; // 由 index.js 传入（避免 import 期实例化）
  return { scanManager };
}

/** 报告三元取数：内存 → 台账（回收后）→ null */
function loadReport(ctx, scanId) {
  let report = ctx.scanManager ? ctx.scanManager.getReport(scanId) : null;
  if (!report) report = readReport(scanId);
  return report || null;
}

/** 漏洞条目 → 代理可读的紧凑形态（与 manifest 的 findings 四要素同源口径） */
function compactVuln(v) {
  const t = v.vulnType || {};
  return {
    id: v.id,
    technique: v.technique,
    vulnType: { nameZh: t.nameZh || null, nameEn: t.nameEn || null, cwe: t.cwe || null, owasp: t.owasp || null },
    riskLevel: v.riskLevel,
    cvss: v.cvss ? { score: v.cvss.score, severity: v.cvss.severity, vector: v.cvss.vector } : null,
    affectedParam: v.param || null,
    affectedLocation: v.location || null,
    url: v.url || null,
    method: v.method || null,
    payloads: v.payloads || [],
    poc: v.poc ? { method: v.poc.method, url: v.poc.url, payload: v.poc.payload, curl: v.poc.curl } : null,
    remediation: v.remediation || null,
  };
}

/**
 * @param {object} ctx createToolContext 产物
 * @returns {Array<{name,description,inputSchema,run}>}
 */
export function buildTools(ctx) {
  return [
    {
      name: 'run_scan',
      description:
        '启动一次 SQL 注入扫描（异步，立即返回 scanId）。走与 REST 相同的配置白名单与 SSRF/scope 护栏。' +
        '扫描进行中用 get_scan_status 轮询，结束后用 get_findings/get_report 取结果。' + AUTH_NOTE,
      inputSchema: {
        type: 'object',
        required: ['url'],
        properties: {
          url: { type: 'string', description: '目标 URL（含注入参数，如 http://host/page?id=1）' },
          method: { type: 'string', enum: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] },
          body: { type: 'string', description: '请求体（JSON 对象字符串；嵌套对象自动走叶子路径发现）' },
          cookie: { type: 'string', description: '会话 Cookie（a=b; c=d），同时是注入面（level>=2 生成 cookie 注入点）' },
          headers: { type: 'string', description: '额外请求头（k:v,k:v）' },
          level: { type: 'integer', minimum: 1, maximum: 5, description: '检测等级（默认 1；2=Cookie 点，4=全部头）' },
          risk: { type: 'integer', minimum: 1, maximum: 3, description: '风险等级（3=高危池，需 confirmDestructive=true）' },
          technique: {
            type: 'string',
            description: '检测技术子集，逗号分隔：union,error,boolean,time,stacked,oob,inline,second_order',
          },
          tamper: { type: 'string', description: 'tamper 插件链（逗号分隔，如 space2comment,charencode）' },
          timeoutMs: { type: 'integer', description: '整场扫描等待上限毫秒（0=不限）' },
          testParameter: { type: 'string', description: '只测指定参数（逗号分隔，对标 sqlmap -p）' },
          paramExclude: { type: 'string', description: '按正则排除参数' },
          paramFilter: { type: 'string', description: '按位置筛选（url/body/header/cookie/path）' },
          dump: { type: 'boolean', description: '检测到注入后提取数据（拖库，显式 opt-in）' },
          scope: { type: 'string', description: '授权范围（逗号分隔域名/CIDR/URL 前缀；缺省按目标同源）' },
          confirmDestructive: {
            type: 'boolean',
            description: '高危 payload 池确认（risk=3 必需）。**必须用户明确同意后才能设 true**——代理不得代答',
          },
        },
      },
      run: async (args) => {
        const target = { url: String(args.url || '') };
        if (args.method) target.method = String(args.method).toUpperCase();
        // body：JSON 解析 → 嵌套走 jsonBody、扁平走 bodyParams（与 CLI [JSON-BODY-FIX] 同一判定）
        if (typeof args.body === 'string' && args.body.trim()) {
          let parsed = null;
          try { parsed = JSON.parse(args.body); } catch { parsed = null; }
          const ch = resolveBodyChannel(parsed);
          if (ch.jsonBody) target.jsonBody = ch.jsonBody;
          else if (Object.keys(ch.bodyParams).length) target.bodyParams = ch.bodyParams;
        }
        if (typeof args.cookie === 'string' && args.cookie.trim()) {
          target.cookieParams = parseCookiePairs(args.cookie, {});
        }
        if (typeof args.headers === 'string' && args.headers.trim()) {
          const h = parseHeaders(args.headers);
          if (h) target.headerParams = h;
        }
        const cfg = {};
        if (args.level != null) cfg.level = args.level;
        if (args.risk != null) cfg.risk = args.risk;
        if (typeof args.technique === 'string' && args.technique.trim()) {
          cfg.techniques = String(args.technique).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
        }
        if (typeof args.tamper === 'string' && args.tamper.trim()) {
          cfg.wafEvasion = {
            tamper: {
              enabled: true,
              plugins: String(args.tamper).split(',').map((s) => s.trim()).filter(Boolean),
              intensity: 'medium',
            },
          };
        }
        if (args.timeoutMs != null) cfg.timeoutMs = args.timeoutMs;
        if (typeof args.testParameter === 'string' && args.testParameter.trim()) {
          cfg.testParameter = String(args.testParameter).split(',').map((s) => s.trim()).filter(Boolean);
        }
        if (typeof args.paramExclude === 'string' && args.paramExclude.trim()) cfg.paramExclude = args.paramExclude;
        if (typeof args.paramFilter === 'string' && args.paramFilter.trim()) cfg.paramFilter = args.paramFilter;
        if (args.dump === true) cfg.enableExtract = true;
        if (typeof args.scope === 'string' && args.scope.trim()) cfg.scope = String(args.scope).split(',').map((s) => s.trim()).filter(Boolean);
        if (args.confirmDestructive === true) cfg.confirmDestructive = true;

        // 与 REST /scan/start 同一条闸（白名单/clamp/直连判定全在其中）
        const sanitized = sanitizeStart({ target, config: cfg });
        const scanId = await ctx.scanManager.start(sanitized);
        return text({
          scanId,
          status: 'started',
          next: 'get_scan_status 轮询 → get_findings 取漏洞 → get_report 取完整报告',
          note: AUTH_NOTE,
        });
      },
    },
    {
      name: 'get_scan_status',
      description: '查询扫描运行状态（status/paused/points/vulns/dbms/elapsedMs）。上下文回收后回落台账。',
      inputSchema: { type: 'object', required: ['scanId'], properties: { scanId: { type: 'string' } } },
      run: async ({ scanId }) => {
        const st = ctx.scanManager ? ctx.scanManager.status(String(scanId)) : null;
        if (st) return text(st);
        // 台账回落（与 REST /scan/:id 的 source 回退同语义）
        const row = listScans(500).find((r) => r.id === String(scanId));
        if (!row) return text({ scanId: String(scanId), status: 'unknown' }, { isError: true });
        return text({ ...row, status: 'finished', source: 'ledger' });
      },
    },
    {
      name: 'get_findings',
      description:
        '取扫描的结构化漏洞清单（CWE/CVSS/受影响参数/PoC curl）。注意：verdict=inconclusive 不等于「未检出」。',
      inputSchema: { type: 'object', required: ['scanId'], properties: { scanId: { type: 'string' } } },
      run: async ({ scanId }) => {
        const report = loadReport(ctx, String(scanId));
        if (!report) return text({ error: `找不到扫描 ${scanId}（内存与台账均无）` }, { isError: true });
        const validity = report.summary?.validity || null;
        return text({
          scanId: report.scanId,
          verdict: report.summary?.verdict || null,
          verdictNote:
            validity && validity.reliable === false
              ? `结论可信度=${validity.status}（不可信，见 get_report 的「结论可信度」节）`
              : null,
          dbms: report.dbms || null,
          totalVulns: (report.vulns || []).length,
          findings: (report.vulns || []).map(compactVuln),
        });
      },
    },
    {
      name: 'get_report',
      description: '取完整报告文本（format=json|markdown|md|html|csv|sarif；默认 json）。超 20 万字符截断。',
      inputSchema: {
        type: 'object',
        required: ['scanId'],
        properties: { scanId: { type: 'string' }, format: { type: 'string', enum: ['json', 'markdown', 'md', 'html', 'csv', 'sarif'] } },
      },
      run: async ({ scanId, format }) => {
        const fmt = typeof format === 'string' && format ? format : 'json';
        const report = loadReport(ctx, String(scanId));
        if (!report) return text({ error: `找不到扫描 ${scanId}` }, { isError: true });
        let out = ctx.scanManager.exportReport(String(scanId), fmt, report);
        if (out == null) out = JSON.stringify(report);
        out = String(out);
        if (out.length > 200000) {
          out = out.slice(0, 200000) + `\n…[截断，完整内容共 ${out.length} 字符，请用更小的 format 或分节读取]`;
        }
        return { content: [{ type: 'text', text: out }] };
      },
    },
    {
      name: 'list_scans',
      description: '列出最近扫描（内存中在途的 + 台账已归档的，新→旧）。',
      inputSchema: { type: 'object', properties: { limit: { type: 'integer', minimum: 1, maximum: 200 } } },
      run: async ({ limit }) => {
        const n = Math.min(Math.max(Number(limit) || 20, 1), 200);
        const rows = listScans(n).map((r) => ({
          scanId: r.id, target: r.target, finishedAt: r.finishedAt, vulns: r.vulns,
          verdict: r.verdict || null, source: 'ledger',
        }));
        const inflight = [];
        if (ctx.scanManager && typeof ctx.scanManager.scans?.forEach === 'function') {
          for (const id of ctx.scanManager.scans.keys()) {
            const st = ctx.scanManager.status(id);
            if (st && !st.retired) inflight.push({ ...st, source: 'memory' });
          }
        }
        return text({ inflight, recent: rows });
      },
    },
    {
      name: 'stop_scan',
      description: '停止一次进行中的扫描（终态扫描不改写状态）。',
      inputSchema: { type: 'object', required: ['scanId'], properties: { scanId: { type: 'string' } } },
      run: async ({ scanId }) => {
        const ok = ctx.scanManager.stop(String(scanId));
        return text({ scanId: String(scanId), stopped: ok === true, status: ctx.scanManager.status(String(scanId)) });
      },
    },
    {
      name: 'pause_scan',
      description: '暂停扫描（在请求边界生效：期间不再向目标发包）。',
      inputSchema: { type: 'object', required: ['scanId'], properties: { scanId: { type: 'string' } } },
      run: async ({ scanId }) => {
        const ok = ctx.scanManager.pause(String(scanId));
        return text({ scanId: String(scanId), paused: ok === true, status: ctx.scanManager.status(String(scanId)) });
      },
    },
    {
      name: 'resume_scan',
      description: '恢复已暂停的扫描。',
      inputSchema: { type: 'object', required: ['scanId'], properties: { scanId: { type: 'string' } } },
      run: async ({ scanId }) => {
        const ok = ctx.scanManager.resume(String(scanId));
        return text({ scanId: String(scanId), resumed: ok === true, status: ctx.scanManager.status(String(scanId)) });
      },
    },
    {
      name: 'preflight',
      description:
        '扫描前侦察（**零 payload 投放**）：目标可达性（1 次基线 GET）+ 注入点发现（URL/body/Cookie 解析，' +
        '不投放任何注入 payload）。开打前先跑这个：确认目标可达、有哪些参数、SSRF/scope 是否放行。',
      inputSchema: {
        type: 'object',
        required: ['url'],
        properties: {
          url: { type: 'string' },
          method: { type: 'string' },
          body: { type: 'string', description: 'JSON 请求体（发现 body 叶子注入点）' },
          cookie: { type: 'string' },
          headers: { type: 'string' },
          level: { type: 'integer', minimum: 1, maximum: 5 },
        },
      },
      run: async (args) => {
        const url = String(args.url || '');
        const notes = [];
        // ① 可达性：1 次基线 GET（SSRF 防护在 httpClient 内逐请求执行——内网目标在这里就会被拒）
        let baseline = null;
        try {
          const res = await httpClient.request({
            url,
            method: 'GET',
            timeoutMs: 8000,
            retry: 1,
            headers: typeof args.headers === 'string' && args.headers.trim() ? parseHeaders(args.headers) || {} : {},
          });
          baseline = { status: res?.status ?? null, bytes: String(res?.data ?? '').length };
        } catch (e) {
          return text(
            { reachable: false, error: e?.message || String(e), hint: '内网/回环目标需 SSRF_ALLOW_PRIVATE=1（引擎进程环境变量）或显式授权 CIDR' },
            { isError: true }
          );
        }
        // ② 注入点发现（TargetParser 纯解析，不投 payload）
        const target = { url };
        if (args.method) target.method = String(args.method).toUpperCase();
        if (typeof args.body === 'string' && args.body.trim()) {
          let parsed = null;
          try { parsed = JSON.parse(args.body); } catch { parsed = null; }
          const ch = resolveBodyChannel(parsed);
          if (ch.jsonBody) target.jsonBody = ch.jsonBody;
          else if (Object.keys(ch.bodyParams).length) target.bodyParams = ch.bodyParams;
        }
        if (typeof args.cookie === 'string' && args.cookie.trim()) {
          target.cookieParams = parseCookiePairs(args.cookie, {});
          notes.push('Cookie 已作为会话携带；要测 Cookie 注入点需 run_scan 的 level>=2');
        }
        if (typeof args.headers === 'string' && args.headers.trim()) {
          const h = parseHeaders(args.headers);
          if (h) target.headerParams = h;
        }
        target.config = { level: Number(args.level) || 1 };
        let points = [];
        try {
          const parser = new TargetParser();
          points = (await parser.discover(createTarget(target))).map((p) => ({
            location: p.location,
            param: p.param,
            originalValue: p.originalValue,
            precisionMarked: !!p.precisionMarked,
          }));
        } catch (e) {
          notes.push(`注入点发现失败：${e?.message || e}`);
        }
        return text({ reachable: true, baseline, points, pointCount: points.length, notes });
      },
    },
  ];
}

/**
 * 工具结果包装：JSON 序列化为唯一 text content（isError 语义见 protocol.js 注释）。
 * @param {unknown} obj
 * @param {{isError?: boolean}} [opts]
 * @returns {{content: Array<{type: string, text: string}>, isError?: boolean}}
 */
function text(obj, { isError } = {}) {
  /** @type {{content: Array<{type: string, text: string}>, isError?: boolean}} */
  const result = { content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] };
  if (isError) result.isError = true;
  return result;
}

/** 供 index.js：工具名 → run 闭包映射 */
export function buildToolDispatch(ctx) {
  const tools = buildTools(ctx);
  const byName = new Map(tools.map((t) => [t.name, t]));
  return {
    listTools: () =>
      tools.map(({ name, description, inputSchema }) => ({ name, description, inputSchema })),
    callTool: async (name, args) => {
      const tool = byName.get(name);
      if (!tool) throw new Error(`未知工具：${name}`);
      try {
        return await tool.run(args || {});
      } catch (e) {
        // 业务错误（目标不可达 / 配置被闸拒绝 / 点位筛光等）：按 MCP 语义转成 isError **结果**
        // —— 调用方（AI 代理）需要拿到可读原因并自行决定下一步，而不是收到协议层 INTERNAL。
        // 只有真正的实现 bug 才向上抛（protocol.js 兜成 INTERNAL_ERROR）。
        return text({ error: e?.message || String(e), tool: name }, { isError: true });
      }
    },
  };
}
