// ============================================================================
// fixPrompt.js —— 把一条 finding 变成「给写代码的人/agent 的修复指令」（D176）
//
// 为什么单独一层：报告是**给人读的交付物**（结论、证据、风险），修复提示词是
// **给执行者的动作清单**（改哪里、怎么改、改完怎么验、验到什么算过）。两者混在
// 一份文档里，agent 会把「风险描述」当成「修复方案」——这正是竞品里
// 「每条发现附 fix prompt」被单独立成一等产物的原因（见 docs/竞品对标-2026W44.md）。
//
// 三条纪律：
//   1. 不自动改代码、不猜业务语义：只给「这类通道的标准改法 + 复测命令」；
//   2. 复测命令必须能**原样复制执行**，且期望值是「0 条 finding」而不是「看起来好了」；
//   3. 结论不可信时（verdict=inconclusive / 有 unverifiedSurfaces）必须在提示词里先声明，
//      否则 agent 会对着「没测成」的结论去改代码。
// ============================================================================

/**
 * @typedef {object} FixGuidance
 * @property {string} why 为什么这个通道能注入（一句话，给人看）
 * @property {string[]} rewrite 按通道的改法（可执行、不猜业务）
 */

/** @type {Record<string, FixGuidance>} 按检测通道的修复要点（数据驱动，新增通道时补一条） */
const GUIDANCE = {
  union: {
    why: '参数被直接拼进 SQL 文本，UNION SELECT 可以追加一个结果集并把数据回显到页面。',
    rewrite: [
      '改成参数化查询/预编译语句（值走占位符，绝不参与 SQL 文本拼接）',
      '联合查询能成功说明列数与类型都对得上——顺手检查同一 DAO 里其它拼接点',
      '该接口的数据库账号降权：只保留它真正需要的表权限',
    ],
  },
  error: {
    why: '服务端把数据库报错原样回显，报错信息里带出了库名/表名/数据。',
    rewrite: [
      '改成参数化查询（报错注入的根因还是拼接，不是报错本身）',
      '统一异常处理：对外只返回不透明的错误码，堆栈与 DB 错误只进服务端日志',
      '关掉驱动层的详细错误回显（如 MySQL `show warnings`、PG `VERBOSITY`）',
    ],
  },
  boolean: {
    why: '真假条件让响应内容出现可区分的差异（条数/文案/长度），据此可逐位推断数据。',
    rewrite: [
      '改成参数化查询，让条件表达式无法被注入',
      '对「有结果/无结果」的响应做同形化（同样的状态码与页面骨架），减少可区分信号',
      '分页/筛选参数校验类型与范围（数字参数就按整数解析，不要当字符串拼）',
    ],
  },
  time: {
    why: '条件成立时数据库被要求延迟（如 SLEEP），响应时间差成为数据通道。',
    rewrite: [
      '改成参数化查询',
      '给查询加超时与并发限制，异常长耗时请求应被拒绝并告警（缩短可观测窗口）',
      '数据库层禁用普通业务账号执行延迟/重型函数（如 MySQL 的 `SLEEP`）',
    ],
  },
  stacked: {
    why: '驱动允许一次执行多条语句，注入点后面可以堆叠任意 SQL（含写库/调过程）。',
    rewrite: [
      '改成参数化查询',
      '连接串关闭多语句执行（如 MySQL `multipleStatements: false`、PG 单语句批处理）',
      '业务账号去掉写权限与存储过程执行权，写操作走独立凭据',
    ],
  },
  oob: {
    why: '数据库进程能主动发起 DNS/HTTP 请求，把数据带出到攻击者控制的端点。',
    rewrite: [
      '改成参数化查询（这是根因）',
      '数据库出网收窄：业务实例不允许主动外联，DNS 只走内网解析',
      '禁用高危原语（如 MySQL `LOAD_FILE` 的 UNC 路径、MSSQL `xp_dirtree`）',
    ],
  },
  second_order: {
    why: '写入时被转义/过滤，但读取到另一处 SQL 时又被拼进语句——注入在「触发点」生效。',
    rewrite: [
      '触发点的查询同样改参数化（存储点干净不等于使用点安全）',
      '把「存进来的值」和「拼进 SQL 的值」当成两条独立路径分别校验',
      '对来自库内的值做二次编码/白名单（列名、排序方向这类标识符必须白名单）',
    ],
  },
  inline: {
    why: '注入落在派生表/子查询等内联上下文，传统的引号闭合在那里不成立但表达式仍被求值。',
    rewrite: [
      '改成参数化查询；内联视图里的值同样不能拼',
      '把动态 SQL 收敛到一个构造器，禁止调用方传 SQL 片段',
      '对动态拼接的每一段做白名单（表/列/排序/聚合函数）',
    ],
  },
  nosql: {
    why: '用户输入被直接并入查询对象（`$where`、操作符注入），文档型数据库同样可被改写语义。',
    rewrite: [
      '不要直接把请求体展开进查询条件（`{...req.body}` 是典型形态）',
      '按字段白名单取值并做类型校验（操作符一律丢弃，不接受 `$` 开头的键）',
      '`$where` / `mapReduce` 这类执行字符串的入口在生产环境禁用',
    ],
  },
};

/** 未知通道的兜底改法（不静默归类：提示词里会写明「通道未收录，按通用改法处理」） */
const FALLBACK = {
  why: '该注入点命中了未收录的检测通道，具体机制见报告里的证据字段。',
  rewrite: [
    '统一改参数化查询/预编译语句（绝大多数注入的根因）',
    '标识符位置（表名/列名/排序）改白名单映射',
    '复核该接口的异常回显与数据库账号权限',
  ],
};

/**
 * 取某通道的修复要点；未收录通道回落到通用改法。
 * @param {string} [technique] 检测通道（union/error/…）
 * @returns {FixGuidance & {known: boolean}} 修复要点；`known=false` 表示通道未收录
 */
export function guidanceFor(technique) {
  const g = GUIDANCE[String(technique || '')];
  return g ? { ...g, known: true } : { ...FALLBACK, known: false };
}

/**
 * 从漏洞条目里取一个可用于 shell 的 URL（缺失时回落到报告级 URL）。
 * @param {object} vuln 漏洞条目
 * @param {object} [ctx] 报告级上下文（`{ url }`）
 * @returns {string} 目标 URL（可能为空串）
 */
function urlOf(vuln, ctx) {
  return String(vuln?.url || ctx?.url || '');
}

/**
 * 复测命令：只测这个参数、只测这个通道，期望 0 条 finding。
 * @param {object} vuln 漏洞条目
 * @param {object} [ctx] 报告级上下文
 * @returns {string} 可直接复制执行的命令
 */
export function buildRetestCommand(vuln, ctx) {
  const url = urlOf(vuln, ctx);
  const param = String(vuln?.param || vuln?.affectedParam || '');
  const technique = String(vuln?.technique || '');
  const parts = ['node server/bin/cli.js', `-u "${url}"`];
  if (param) parts.push(`-p "${param}"`);
  if (technique) parts.push(`--technique ${technique}`);
  return parts.join(' ');
}

/**
 * 生成单条 finding 的修复提示词（Markdown，可直接交给编码代理）。
 * @param {object} vuln 漏洞条目（含 vulnType/param/location/technique/poc）
 * @param {object} [ctx] 报告级上下文：`{ url, verdict, unverifiedSurfaces }`
 * @returns {string} Markdown 正文
 */
export function buildFixPrompt(vuln, ctx = {}) {
  const g = guidanceFor(vuln?.technique);
  const type = vuln?.vulnType || {};
  const title = type.nameZh || type.nameEn || 'SQL 注入';
  const lines = [
    `# 修复：${title}${type.cwe ? ` · ${type.cwe}` : ''}`,
    '',
    `- 目标：\`${urlOf(vuln, ctx)}\``,
    `- 受影响参数：\`${vuln?.param || vuln?.affectedParam || '(未知)'}\`（${vuln?.location || '位置未标注'}）`,
    `- 检测通道：\`${vuln?.technique || '未标注'}\`${g.known ? '' : '（**未收录通道，按通用改法处理**）'}`,
  ];
  if (vuln?.riskLevel) lines.push(`- 风险等级：${vuln.riskLevel}`);
  lines.push('', '## 为什么能注入', '', g.why, '');
  if (vuln?.poc?.curl) {
    lines.push('## 证据（PoC，可直接重放）', '', '```bash', String(vuln.poc.curl), '```', '');
  }
  lines.push('## 该怎么改', '');
  for (const r of g.rewrite) lines.push(`- ${r}`);
  lines.push(
    '',
    '## 改完怎么验（复制即用）',
    '',
    '```bash',
    buildRetestCommand(vuln, ctx),
    '```',
    '',
    '**期望**：该参数 **0 条 finding**（`vulns: []`）。',
    '若仍命中：先看 `verdict` 是否为 `inconclusive` / `session_expired`——那是**没测成**，不是没修好；',
    '修好但结论为 `unverifiedSurfaces` 时同样不能算通过。',
    '',
  );
  if (ctx.verdict || (ctx.unverifiedSurfaces && ctx.unverifiedSurfaces.length)) {
    lines.push(
      '## 结论口径（不要忽略）',
      '',
      `- 本次扫描 verdict：\`${ctx.verdict || '未标注'}\``,
      `- 未验证面：\`${(ctx.unverifiedSurfaces || []).join('; ') || '(无)'}\``,
      '',
      '上述未验证面里的「未检出」**不能**当作修复已验证的依据。',
      '',
    );
  }
  return lines.join('\n');
}

/**
 * 文件名安全化：只留字母数字与 `. _ -`；折叠连续点、去掉开头点号、限长。
 * 参数名来自目标应用（可以是任意字符串），文件名必须构造上就逃不出目录。
 * @param {string} raw 原始片段
 * @returns {string} 可安全落盘的片段
 */
function safeName(raw) {
  const cleaned = String(raw || '')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/\.{2,}/g, '_')
    .replace(/^[._]+/, '')
    .slice(0, 60);
  return cleaned || 'finding';
}

/**
 * 把整份报告渲染成「索引 + 每条一份」的修复提示词集合。
 * @param {object} report 引擎报告（含 `vulns` / `summary`）
 * @param {object} [ctx] 报告级上下文（`{ url }`）
 * @returns {{index: string, items: Array<{file: string, content: string}>}} 索引与逐条文件
 */
export function renderFixPrompts(report, ctx = {}) {
  const vulns = Array.isArray(report?.vulns) ? report.vulns : [];
  const summary = report?.summary || {};
  /** @type {Array<{file: string, content: string}>} */
  const items = vulns.map((v, i) => {
    const seq = String(i + 1).padStart(2, '0');
    const file = `fix-${seq}-${safeName(v?.param || v?.technique)}.md`;
    return {
      file,
      content: buildFixPrompt(v, {
        url: urlOf(v, ctx),
        verdict: summary.verdict,
        unverifiedSurfaces: summary.unverifiedSurfaces,
      }),
    };
  });
  const head = [
    '# 修复提示词索引',
    '',
    `- 目标：\`${ctx.url || urlOf({}, ctx) || '(见各条)'}\``,
    `- findings：${items.length} 条`,
    `- 结论口径：\`verdict=${summary.verdict || '未标注'}\``,
    '',
    '> 每条提示词都包含：为什么能注入 / 该怎么改 / 改完怎么验（含期望值）。',
    '> 本文件由扫描器生成，**不自动修改代码**；改完请按提示词里的复测命令重扫。',
    '',
  ];
  if (items.length) head.push('## 清单', '', ...items.map((it, i) => `${i + 1}. \`${it.file}\` — ${vulns[i]?.vulnType?.nameZh || 'SQL 注入'} · ${vulns[i]?.param || ''}`), '');
  else head.push('本次扫描没有 findings，因此没有修复提示词。', '');
  return { index: head.join('\n'), items };
}
