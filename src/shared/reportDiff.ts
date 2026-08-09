import type { ReportModel, InjectionPoint, Vulnerability, InjectionLocation, TechniqueType } from './types';
import { RISK_LABEL, TECHNIQUE_LABEL } from './constants';

// ── 报告对比工具（两次扫描快照 diff）──────────────────────────────
// 对标 sqlmap 的多次扫描对照：以「注入点参数（location::param）」为连接键，以
// 「注入点 + 技术」为漏洞连接键，产出新增 / 消失 / 变化三类差异，便于回归审计。

const RISK_RANK: Record<string, number> = { Low: 1, Medium: 2, High: 3, Critical: 4 };

/** 注入点连接键：位置 + 参数（同目标不同次扫描的同一注入点） */
export function pointKey(p: InjectionPoint): string {
  return `${p.location}::${p.param}`;
}

/** 漏洞连接键：注入点连接键 + 技术 */
export function vulnKey(report: ReportModel, v: Vulnerability): string {
  const p = report.points.find((pp) => pp.id === v.pointId);
  const pk = p ? pointKey(p) : v.pointId;
  return `${pk}::${v.technique}`;
}

export interface FieldChange {
  field: string;
  before: string;
  after: string;
}

export interface PointDiffEntry {
  key: string;
  param: string;
  location: InjectionLocation;
  status: 'added' | 'removed' | 'changed';
  pointA?: InjectionPoint;
  pointB?: InjectionPoint;
  changes?: FieldChange[];
}

export interface VulnDiffEntry {
  key: string;
  param: string;
  technique: TechniqueType;
  status: 'added' | 'removed' | 'changed';
  vulnA?: Vulnerability;
  vulnB?: Vulnerability;
  changes?: FieldChange[];
}

export interface ReportDiffResult {
  targetA: string;
  targetB: string;
  points: PointDiffEntry[];
  vulns: VulnDiffEntry[];
  summary: {
    pointsAdded: number;
    pointsRemoved: number;
    pointsChanged: number;
    vulnsAdded: number;
    vulnsRemoved: number;
    vulnsChanged: number;
  };
}

function diffPointFields(a: InjectionPoint, b: InjectionPoint): FieldChange[] {
  const changes: FieldChange[] = [];
  if (!!a.isStorePoint !== !!b.isStorePoint) {
    changes.push({ field: '是否存储点', before: a.isStorePoint ? '是' : '否', after: b.isStorePoint ? '是' : '否' });
  }
  if ((a.storeKind ?? null) !== (b.storeKind ?? null)) {
    changes.push({ field: '存储分类', before: a.storeKind ?? '—', after: b.storeKind ?? '—' });
  }
  if (!!a.confirmed !== !!b.confirmed) {
    changes.push({ field: '已确认注入', before: a.confirmed ? '是' : '否', after: b.confirmed ? '是' : '否' });
  }
  return changes;
}

function diffVulnFields(a: Vulnerability, b: Vulnerability): FieldChange[] {
  const changes: FieldChange[] = [];
  if (a.dbms !== b.dbms) {
    changes.push({ field: '数据库', before: a.dbms ?? '—', after: b.dbms ?? '—' });
  }
  const ra = RISK_RANK[a.riskLevel] ?? 0;
  const rb = RISK_RANK[b.riskLevel] ?? 0;
  if (ra !== rb) {
    changes.push({
      field: '风险等级',
      before: RISK_LABEL[a.riskLevel] ?? a.riskLevel,
      after: RISK_LABEL[b.riskLevel] ?? b.riskLevel,
    });
  }
  const pa = (a.payloads || []).length;
  const pb = (b.payloads || []).length;
  if (pa !== pb) {
    changes.push({ field: '载荷数', before: String(pa), after: String(pb) });
  }
  return changes;
}

/** 对比两份报告，返回注入点与漏洞的增/删/改差异 */
export function diffReports(a: ReportModel, b: ReportModel): ReportDiffResult {
  const mapA = new Map<string, InjectionPoint>();
  const mapB = new Map<string, InjectionPoint>();
  a.points.forEach((p) => mapA.set(pointKey(p), p));
  b.points.forEach((p) => mapB.set(pointKey(p), p));

  const pointDiffs: PointDiffEntry[] = [];
  const allKeys = new Set([...mapA.keys(), ...mapB.keys()]);
  for (const key of allKeys) {
    const pa = mapA.get(key);
    const pb = mapB.get(key);
    const loc = (pb ?? pa)!.location;
    const param = (pb ?? pa)!.param;
    if (pa && !pb) {
      pointDiffs.push({ key, param, location: loc, status: 'removed', pointA: pa });
    } else if (!pa && pb) {
      pointDiffs.push({ key, param, location: loc, status: 'added', pointB: pb });
    } else if (pa && pb) {
      const changes = diffPointFields(pa, pb);
      if (changes.length) pointDiffs.push({ key, param, location: loc, status: 'changed', pointA: pa, pointB: pb, changes });
    }
  }

  // 漏洞 diff：以 a/b 各自的 vulnKey 建立映射
  const vMapA = new Map<string, VulnDiffEntry['vulnA']>();
  const vMapB = new Map<string, VulnDiffEntry['vulnB']>();
  a.vulns.forEach((v) => vMapA.set(vulnKey(a, v), v));
  b.vulns.forEach((v) => vMapB.set(vulnKey(b, v), v));

  const vulnDiffs: VulnDiffEntry[] = [];
  const vAllKeys = new Set([...vMapA.keys(), ...vMapB.keys()]);
  for (const key of vAllKeys) {
    const va = vMapA.get(key);
    const vb = vMapB.get(key);
    const param = va ? paramOf(a, va.pointId) : paramOf(b, vb!.pointId);
    const technique = (vb ?? va)!.technique;
    if (va && !vb) {
      vulnDiffs.push({ key, param, technique, status: 'removed', vulnA: va });
    } else if (!va && vb) {
      vulnDiffs.push({ key, param, technique, status: 'added', vulnB: vb });
    } else if (va && vb) {
      const changes = diffVulnFields(va, vb);
      if (changes.length) vulnDiffs.push({ key, param, technique, status: 'changed', vulnA: va, vulnB: vb, changes });
    }
  }

  return {
    targetA: a.target.baseUrl,
    targetB: b.target.baseUrl,
    points: pointDiffs,
    vulns: vulnDiffs,
    summary: {
      pointsAdded: pointDiffs.filter((d) => d.status === 'added').length,
      pointsRemoved: pointDiffs.filter((d) => d.status === 'removed').length,
      pointsChanged: pointDiffs.filter((d) => d.status === 'changed').length,
      vulnsAdded: vulnDiffs.filter((d) => d.status === 'added').length,
      vulnsRemoved: vulnDiffs.filter((d) => d.status === 'removed').length,
      vulnsChanged: vulnDiffs.filter((d) => d.status === 'changed').length,
    },
  };
}

// 复用的小助手：定位注入点参数名
function paramOf(report: ReportModel, pointId: string): string {
  return report.points.find((p) => p.id === pointId)?.param ?? pointId;
}

const STATUS_LABEL: Record<string, string> = { added: '新增', removed: '消失', changed: '变化' };

function changeText(changes: FieldChange[] | undefined): string {
  if (!changes || !changes.length) return '';
  return changes.map((c) => `${c.field}: ${c.before} → ${c.after}`).join('；');
}

/** 生成差异报告 Markdown（纯前端，供对比页「导出差异」按钮使用，复用 diffReports 结果） */
export function diffToMarkdown(r: ReportDiffResult): string {
  const lines: string[] = [];
  lines.push('# SQL 注入检测报告差异');
  lines.push('');
  lines.push('| 维度 | 基准 (A) | 对比 (B) |');
  lines.push('| --- | --- | --- |');
  lines.push(`| 目标 | ${r.targetA} | ${r.targetB} |`);
  lines.push('');
  lines.push('## 概览');
  lines.push('');
  lines.push(`- 注入点：新增 ${r.summary.pointsAdded} / 消失 ${r.summary.pointsRemoved} / 变化 ${r.summary.pointsChanged}`);
  lines.push(`- 漏洞：新增 ${r.summary.vulnsAdded} / 消失 ${r.summary.vulnsRemoved} / 变化 ${r.summary.vulnsChanged}`);
  lines.push('');

  lines.push('## 注入点差异');
  lines.push('');
  if (r.points.length === 0) {
    lines.push('无差异（两次扫描注入点一致）。');
  } else {
    lines.push('| 状态 | 参数 | 位置 | 变化 |');
    lines.push('| --- | --- | --- | --- |');
    r.points.forEach((d) => {
      lines.push(`| ${STATUS_LABEL[d.status]} | ${d.param} | ${d.location} | ${changeText(d.changes)} |`);
    });
  }
  lines.push('');

  lines.push('## 漏洞差异');
  lines.push('');
  if (r.vulns.length === 0) {
    lines.push('无差异（两次扫描漏洞一致）。');
  } else {
    lines.push('| 状态 | 参数 | 技术 | 风险 | 变化 |');
    lines.push('| --- | --- | --- | --- | --- |');
    r.vulns.forEach((d) => {
      const risk = d.vulnA || d.vulnB;
      const riskText = risk ? RISK_LABEL[risk.riskLevel] ?? risk.riskLevel : '';
      lines.push(
        `| ${STATUS_LABEL[d.status]} | ${d.param} | ${d.technique} | ${riskText} | ${changeText(d.changes)} |`,
      );
    });
  }
  lines.push('');

  return lines.join('\n');
}

/** 生成差异报告 JSON（结构化，便于程序化归档/再比对） */
export function diffToJson(r: ReportDiffResult): string {
  return JSON.stringify(r, null, 2);
}

/** CSV 字段转义：含逗号/引号/换行时用双引号包裹，内部引号转义为双引号（与 reportExport.csvEscape 同规则） */
function csvEscape(value: string | number | null | undefined): string {
  const s = value === null || value === undefined ? '' : String(value);
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

/**
 * 生成差异报告 CSV（纯前端，供对比页「导出差异 CSV」按钮使用，与 reportToCsv 同风格）。
 * 单文件内含三段：概览统计 + 注入点差异表 + 漏洞差异表，可直接贴 Excel 做回归追踪。
 */
export function diffToCsv(r: ReportDiffResult): string {
  const lines: string[] = [];

  // 概览：目标对照 + 增减统计
  lines.push(['维度', '基准 (A)', '对比 (B)'].map(csvEscape).join(','));
  lines.push([csvEscape('目标'), csvEscape(r.targetA), csvEscape(r.targetB)].join(','));
  lines.push('');
  lines.push(['类型', '新增', '消失', '变化'].map(csvEscape).join(','));
  lines.push(['注入点', r.summary.pointsAdded, r.summary.pointsRemoved, r.summary.pointsChanged].map(csvEscape).join(','));
  lines.push(['漏洞', r.summary.vulnsAdded, r.summary.vulnsRemoved, r.summary.vulnsChanged].map(csvEscape).join(','));
  lines.push('');

  // 注入点差异表
  lines.push('注入点差异');
  lines.push(['状态', '参数', '位置', '变化'].map(csvEscape).join(','));
  if (r.points.length === 0) {
    lines.push(csvEscape('无差异（两次扫描注入点一致）。'));
  } else {
    r.points.forEach((d) => {
      lines.push([STATUS_LABEL[d.status], d.param, d.location, changeText(d.changes)].map(csvEscape).join(','));
    });
  }
  lines.push('');

  // 漏洞差异表
  lines.push('漏洞差异');
  lines.push(['状态', '参数', '技术', '风险', '变化'].map(csvEscape).join(','));
  if (r.vulns.length === 0) {
    lines.push(csvEscape('无差异（两次扫描漏洞一致）。'));
  } else {
    r.vulns.forEach((d) => {
      const risk = d.vulnA || d.vulnB;
      const riskText = risk ? RISK_LABEL[risk.riskLevel] ?? risk.riskLevel : '';
      lines.push(
        [STATUS_LABEL[d.status], d.param, TECHNIQUE_LABEL[d.technique] ?? d.technique, riskText, changeText(d.changes)]
          .map(csvEscape)
          .join(','),
      );
    });
  }
  lines.push('');

  return lines.join('\n');
}
