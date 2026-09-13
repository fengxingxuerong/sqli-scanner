// ============================================================================
// reportDelivery.js —— 报告交付层（[2026-09-13] 「检测报告」→「渗透测试交付物」补全）
// ============================================================================
// 职责：把引擎已经产出的原始数据（summary.validity / blockPolicy / wafDetected /
// data 拖库树 / vulns）加工成客户可直接交付的四要素，供 ReportGenerator 的
// markdown / html / csv 渲染器共用（单一取数源，避免三侧漂移）：
//   ① 报告元信息（起止时间/耗时/请求总数/测试范围/授权声明）
//   ② 执行摘要（管理层视角：影响实证 + 结论可信度，一句能读的话）
//   ③ WAF 交战记录（识别到的厂商 / 被拦次数 / 自动换链处置）
//   ④ 修复建议（按技术通道的针对性措施 + 通用加固基线）与 CVSS v3.1 启发式评分
// 纯函数、只读 report：不写回任何字段，不触碰引擎与检测流程。
// ============================================================================

/** 技术通道 → 修复建议（针对性措施；通用基线另行追加） */
export const REMEDIATION_BY_TECHNIQUE = {
  union: [
    '改用参数化查询/预编译语句，禁止用字符串拼接把用户输入并入 SQL 文本',
    '应用数据库账号最小权限：禁用 FILE 权限与跨库访问，限制 information_schema 可见范围',
    '注意：关键字过滤（UNION/SELECT）只能缓解已知特征，不能作为修复依据',
  ],
  error: [
    '关闭生产环境的数据库报错回显，统一改为通用错误页 + 服务端日志记录',
    '改用参数化查询/预编译语句，从根源上消除注入点',
    '注意：报错回显泄露 SQL 上下文与数据库指纹，是定库与后续利用的跳板',
  ],
  boolean: [
    '改用参数化查询/预编译语句',
    '排查响应差异的来源（业务分支依赖了原始 SQL 拼接结果）',
    '注意：布尔通道不依赖回显与报错，关闭报错/过滤关键字都挡不住它',
  ],
  time: [
    '改用参数化查询/预编译语句',
    '为数据库会话设置语句级超时，对慢查询/异常延迟做监控告警',
    '注意：时间通道在无任何内容差异的页面上依然可达，响应一致性无法修复它',
  ],
  stacked: [
    '改用参数化查询/预编译语句',
    '禁用多语句执行能力（如 JDBC allowMultiQueries=false、驱动默认关闭多语句）',
    '堆叠通道意味着攻击者可直接写数据/调过程，按最高优先级处置',
  ],
  oob: [
    '改用参数化查询/预编译语句',
    '限制数据库进程的对外网络连接（出网白名单），切断 DNS/HTTP 回连通道',
    '注意：OOB 说明目标数据库进程具备外连能力，需同时收网权限',
  ],
  second_order: [
    '所有读写路径一律参数化——包括使用二阶存储值的查询（存储时转义不等于安全）',
    '对用户可控的存储值在「使用处」再做一次参数化绑定',
  ],
  inline: [
    '改用参数化查询/预编译语句',
    '避免把用户输入拼进派生表/子查询等内联上下文',
  ],
  nosql: [
    '对 NoSQL 查询使用类型化操作符与白名单字段，禁止把用户输入直接并入查询对象',
    '禁止 `$where`/JS 执行类查询接口接收用户输入',
  ],
};

/** 通用加固基线（每次交付都附，不受检出技术影响） */
export const GENERAL_REMEDIATION = [
  '所有 SQL 一律参数化/预编译，或经 ORM 的绑定参数接口；代码审计重点排查字符串拼接构造 SQL 的路径',
  '数据库账号最小权限：应用账号禁用 FILE/写权限、限制可见库表、禁用多语句',
  '生产环境关闭数据库报错回显，统一错误页 + 服务端日志',
  '输入校验在服务端做（类型强转/白名单），前端校验仅作体验优化',
  'WAF/输入过滤只能缓解已知特征，不能替代代码层修复',
  '修复后对本次命中的注入点做回归复扫，确认为 0 命中后关闭工单',
];

// CVSS v3.1 启发式映射（非官方逐条评定，口径在报告里注明）：
//   有数据读出/可执行链（stacked）→ C:H/I:H/A:H；读出型（union/error 等）→ C:H/I:L/A:N；
//   仅确认可达（boolean/time/oob）→ C:H/I:N/A:N；未知技术保守 C:L。
// 环境项一律不设（交付方按自身资产重要性调整），得分随技术通道确定性给出、可复算。
const CVSS_BY_TECHNIQUE = {
  stacked: { score: 9.8, vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
  union: { score: 8.2, vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N' },
  error: { score: 8.2, vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N' },
  second_order: { score: 8.2, vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N' },
  inline: { score: 8.2, vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N' },
  nosql: { score: 8.2, vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N' },
  boolean: { score: 7.5, vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
  time: { score: 7.5, vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
  oob: { score: 7.5, vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
};
const CVSS_DEFAULT = { score: 5.3, vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' };

/** 由得分段给严重度标签（CVSS v3.1 官方分段） */
export function severityOf(score) {
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  return 'Low';
}

/**
 * 单条漏洞的 CVSS v3.1 启发式评分。
 * @param {{technique?: string}} vuln
 * @returns {{score: number, severity: string, vector: string, note: string}}
 */
export function cvssFor(vuln) {
  const base = CVSS_BY_TECHNIQUE[vuln?.technique] || CVSS_DEFAULT;
  return { ...base, severity: severityOf(base.score), note: '启发式评分（按技术通道映射，供排期排序；非逐条人工评定）' };
}

const isoTime = (s) => {
  const t = Date.parse(String(s ?? ''));
  return Number.isNaN(t) ? null : t;
};

const fmtDuration = (ms) => {
  if (ms == null) return null;
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m${Math.round((ms % 60000) / 1000)}s`;
};

/** 从 data 拖库树汇总影响面（表数/行数/样例表名） */
export function dataImpactOf(data) {
  const rows = data && typeof data === 'object' ? data.rows : null;
  if (!rows || typeof rows !== 'object') return null;
  const tables = Object.entries(rows).filter(([, v]) => Array.isArray(v) && v.length);
  if (!tables.length) return null;
  let rowCount = 0;
  for (const [, v] of tables) rowCount += v.length;
  return {
    tableCount: tables.length,
    rowCount,
    sampleTables: tables.slice(0, 3).map(([k]) => k),
  };
}

/**
 * 汇总交付四要素。纯只读：不修改 report。
 * @param {object} report ScanManager.getReport() 的报告对象（可缺字段，全程容错）
 */
// [P1-FIX 2026-09-13] 同一份 report 多次导出必须逐字节一致：meta.generatedAt 在报告缺
// finishedAt/startedAt 时会落到 new Date()，相隔毫秒即产生差异——实测 CLI 的
// 「md 别名与 markdown 等价」断言因此偶发失败（flaky），也让「同一份报告渲染两次结果
// 不同」成为交付层缺陷。delivery 是纯只读派生结果，以 report 对象为键缓存最省且安全。
const DELIVERY_CACHE = new WeakMap();

export function buildDelivery(report) {
  if (report && typeof report === 'object') {
    const cached = DELIVERY_CACHE.get(report);
    if (cached) return cached;
  }
  const summary = report?.summary || {};
  const validity = summary.validity || null;
  const cfg = report?.target?.config || {};
  const data = report?.data || null;

  // —— ① 元信息 ——
  const startT = isoTime(report?.startedAt);
  const endT = isoTime(report?.finishedAt);
  const durationMs = startT != null && endT != null && endT >= startT ? endT - startT : null;
  const scopeList = Array.isArray(cfg.scope) ? cfg.scope.filter(Boolean) : [];
  const meta = {
    scanId: report?.scanId || '-',
    target: report?.target?.baseUrl || '-',
    startedAt: report?.startedAt || null,
    finishedAt: report?.finishedAt || null,
    durationText: fmtDuration(durationMs),
    requestCount: validity?.counts?.total ?? null,
    level: cfg.level ?? null,
    risk: cfg.risk ?? null,
    techniques: Array.isArray(cfg.techniques) ? cfg.techniques.join('/') : null,
    scope: scopeList.length ? scopeList.join(', ') : '未显式配置——按「目标 URL 同源」口径执行',
    // 生成时间取报告自身的确定性时间戳（finishedAt → startedAt → now）：
    // 同一份报告两次渲染必须逐字节一致（CLI 的 md/markdown 等价测试锁此行为），
    // 用 Date.now() 会在跨毫秒边界时令等价性偶发失败——实测复现过，勿回退。
    generatedAt: report?.finishedAt || report?.startedAt || new Date().toISOString(),
  };

  // —— ② 执行摘要 ——
  const vulns = Array.isArray(report?.vulns) ? report.vulns : [];
  const impact = dataImpactOf(data);
  const exec = {
    riskLevel: report?.riskLevel || null,
    dbms: report?.dbms || null,
    vulnCount: vulns.length,
    pointCount: Array.isArray(report?.points) ? report.points.length : 0,
    techniques: [...new Set(vulns.map((v) => v.technique).filter(Boolean))],
    impact,
    validity: validity
      ? { status: validity.status, reliable: validity.reliable, reason: validity.reason || null }
      : null,
    dbmsEvidence: summary.dbmsEvidence || null,
  };

  // —— ③ WAF 交战 ——
  const vendors = Array.isArray(summary.wafDetected) ? summary.wafDetected : [];
  const blockHits = validity?.counts?.blockHits ?? null;
  const blockPolicy = summary.blockPolicy || null;
  const waf = {
    detected: vendors.map((v) => ({ vendor: v.vendor || v.name || '?', confidence: v.confidence })),
    blockHits,
    blockPolicy,
    engaged:
      vendors.length > 0 ||
      (blockHits != null && blockHits > 0) ||
      !!(blockPolicy && blockPolicy.action && blockPolicy.action !== 'none'),
  };

  // —— ④ 修复建议 + CVSS ——
  const remediation = {
    perVuln: vulns.map((v) => ({
      pointId: v.pointId,
      technique: v.technique,
      cvss: cvssFor(v),
      actions: REMEDIATION_BY_TECHNIQUE[v.technique] || [
        '改用参数化查询/预编译语句（未识别技术通道，按通用基线处置）',
      ],
    })),
    general: GENERAL_REMEDIATION,
  };

  const delivery = { meta, exec, waf, remediation };
  if (report && typeof report === 'object') DELIVERY_CACHE.set(report, delivery);
  return delivery;
}