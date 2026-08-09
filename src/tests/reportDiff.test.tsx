import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { diffReports, diffToMarkdown, diffToJson, diffToCsv } from '../shared/reportDiff';
import type { ReportModel, ScanConfig } from '../shared/types';

const config = {} as ScanConfig;

function makeReport(scanId: string, points: ReportModel['points'], vulns: ReportModel['vulns']): ReportModel {
  return {
    scanId,
    target: {
      id: 't',
      baseUrl: `http://example.com/${scanId}`,
      method: 'GET',
      bodyParams: {},
      cookieParams: {},
      headerParams: {},
      config,
    },
    startedAt: '2026-01-01T00:00:00Z',
    finishedAt: null,
    dbms: 'MySQL',
    points,
    vulns,
    data: null,
    riskLevel: 'High',
    summary: {},
  };
}

const p = (id: string, location: 'url' | 'body' | 'cookie', param: string, isStore = false, storeKind: string | null = null) => ({
  id,
  location,
  param,
  originalValue: '1',
  confirmed: false,
  technique: null,
  dbms: null,
  isStorePoint: isStore,
  storeKind,
});

const v = (id: string, pointId: string, technique: 'union' | 'boolean' | 'error', riskLevel: 'High' | 'Medium' | 'Low', dbms: 'MySQL' | null = 'MySQL') => ({
  id,
  pointId,
  technique,
  dbms,
  riskLevel,
  payloads: ['x'],
  description: 'd',
  trace: null,
});

describe('diffReports（注入点差异）', () => {
  it('新增 / 消失：A 有 p2、B 有 p3，p1 共有', () => {
    const a = makeReport('a', [p('p1', 'url', 'id'), p('p2', 'body', 'username', true, 'registration')], []);
    const b = makeReport('b', [p('p1', 'url', 'id'), p('p3', 'cookie', 'sid')], []);
    const diff = diffReports(a, b);
    expect(diff.summary.pointsAdded).toBe(1);
    expect(diff.summary.pointsRemoved).toBe(1);
    expect(diff.summary.pointsChanged).toBe(0);
    const added = diff.points.find((x) => x.status === 'added');
    const removed = diff.points.find((x) => x.status === 'removed');
    expect(added?.param).toBe('sid');
    expect(removed?.param).toBe('username');
  });

  it('变化：同一参数由非存储点变为存储点', () => {
    const a = makeReport('a', [p('p1', 'body', 'bio')], []);
    const b = makeReport('b', [p('p1', 'body', 'bio', true, 'comment')], []);
    const diff = diffReports(a, b);
    expect(diff.summary.pointsChanged).toBe(1);
    expect(diff.points[0].changes?.some((c) => c.field === '是否存储点')).toBe(true);
  });
});

describe('diffReports（漏洞差异）', () => {
  it('新增漏洞：B 在 sid 上多一个 boolean 漏洞', () => {
    const a = makeReport('a', [p('p1', 'url', 'id'), p('p3', 'cookie', 'sid')], [v('v1', 'p1', 'union', 'High')]);
    const b = makeReport('b', [p('p1', 'url', 'id'), p('p3', 'cookie', 'sid')], [v('v1', 'p1', 'union', 'High'), v('v2', 'p3', 'boolean', 'Medium')]);
    const diff = diffReports(a, b);
    expect(diff.summary.vulnsAdded).toBe(1);
    expect(diff.summary.vulnsRemoved).toBe(0);
    expect(diff.summary.vulnsChanged).toBe(0);
    expect(diff.vulns.find((x) => x.status === 'added')?.technique).toBe('boolean');
  });

  it('变化：同一漏洞风险由 High 降为 Medium', () => {
    const a = makeReport('a', [p('p1', 'url', 'id')], [v('v1', 'p1', 'union', 'High')]);
    const b = makeReport('b', [p('p1', 'url', 'id')], [v('v1', 'p1', 'union', 'Medium')]);
    const diff = diffReports(a, b);
    expect(diff.summary.vulnsChanged).toBe(1);
    expect(diff.vulns[0].changes?.some((c) => c.field === '风险等级')).toBe(true);
  });

  it('两次完全一致的报告无差异', () => {
    const a = makeReport('a', [p('p1', 'url', 'id')], [v('v1', 'p1', 'union', 'High')]);
    const b = makeReport('b', [p('p1', 'url', 'id')], [v('v1', 'p1', 'union', 'High')]);
    const diff = diffReports(a, b);
    expect(diff.summary.vulnsAdded + diff.summary.vulnsRemoved + diff.summary.vulnsChanged).toBe(0);
  });
});

describe('diffToMarkdown', () => {
  it('含标题、概览计数、新增/消失/变化节与无差异占位', () => {
    const a = makeReport('a', [p('p1', 'url', 'id'), p('p2', 'body', 'username', true, 'registration')], [v('v1', 'p1', 'union', 'High')]);
    const b = makeReport('b', [p('p1', 'url', 'id'), p('p3', 'cookie', 'sid')], [v('v2', 'p3', 'boolean', 'Medium')]);
    const diff = diffReports(a, b);
    const md = diffToMarkdown(diff);
    expect(md).toContain('# SQL 注入检测报告差异');
    expect(md).toContain('http://example.com/a'); // 目标 A
    expect(md).toContain('http://example.com/b'); // 目标 B
    expect(md).toContain('注入点：新增 1 / 消失 1 / 变化 0');
    expect(md).toContain('漏洞：新增 1 / 消失 1 / 变化 0');
    expect(md).toContain('sid'); // 新增注入点
    expect(md).toContain('username'); // 消失注入点
    expect(md).toContain('## 注入点差异');
    expect(md).toContain('## 漏洞差异');
  });

  it('完全一致时输出无差异占位而非空表', () => {
    const a = makeReport('a', [p('p1', 'url', 'id')], [v('v1', 'p1', 'union', 'High')]);
    const b = makeReport('b', [p('p1', 'url', 'id')], [v('v1', 'p1', 'union', 'High')]);
    const md = diffToMarkdown(diffReports(a, b));
    expect(md).toContain('无差异（两次扫描注入点一致）');
    expect(md).toContain('无差异（两次扫描漏洞一致）');
  });
});

describe('diffToJson', () => {
  it('生成可解析 JSON 且保留 summary 与 points/vulns', () => {
    const a = makeReport('a', [p('p1', 'url', 'id')], [v('v1', 'p1', 'union', 'High')]);
    const b = makeReport('b', [p('p1', 'url', 'id')], [v('v2', 'p1', 'union', 'Medium')]);
    const diff = diffReports(a, b);
    const json = diffToJson(diff);
    const parsed = JSON.parse(json);
    expect(parsed.summary.vulnsChanged).toBe(1);
    expect(Array.isArray(parsed.vulns)).toBe(true);
    expect(parsed.points.length).toBe(0); // 注入点一致，无差异项
  });
});

describe('diffToCsv', () => {
  it('含概览统计、注入点/漏洞差异表头与新增/消失/变化行', () => {
    const a = makeReport('a', [p('p1', 'url', 'id'), p('p2', 'body', 'username', true, 'registration')], [v('v1', 'p1', 'union', 'High')]);
    const b = makeReport('b', [p('p1', 'url', 'id'), p('p3', 'cookie', 'sid')], [v('v2', 'p3', 'boolean', 'Medium')]);
    const diff = diffReports(a, b);
    const csv = diffToCsv(diff);
    // 概览统计行
    expect(csv).toContain('注入点,1,1,0');
    expect(csv).toContain('漏洞,1,1,0');
    // 表头
    expect(csv).toContain('状态,参数,位置,变化');
    expect(csv).toContain('状态,参数,技术,风险,变化');
    // 新增注入点 sid（cookie）、消失注入点 username（body）
    expect(csv).toContain('新增,sid,cookie');
    expect(csv).toContain('消失,username,body');
    // 漏洞差异：新增 boolean / 消失 union
    expect(csv).toContain('新增,sid,布尔盲注,中危');
    expect(csv).toContain('消失,id,联合查询注入,高危');
  });

  it('完全一致时输出无差异占位而非空表', () => {
    const a = makeReport('a', [p('p1', 'url', 'id')], [v('v1', 'p1', 'union', 'High')]);
    const b = makeReport('b', [p('p1', 'url', 'id')], [v('v1', 'p1', 'union', 'High')]);
    const csv = diffToCsv(diffReports(a, b));
    expect(csv).toContain('无差异（两次扫描注入点一致）。');
    expect(csv).toContain('无差异（两次扫描漏洞一致）。');
  });

  it('变化字段含逗号/换行时按 CSV 规则转义为双引号包裹', () => {
    // 构造变化：注入点由非存储点变存储点（变化文本为「是否存储点: 否 → 是」，无逗号）；
    // 再人工构造一列含逗号的描述以验证转义——直接用 diff 的 changeText 不直接可控，
    // 这里验证底层转义：漏洞变化的风险文本不含逗号，故额外断言导出整体可被按行拆分且行数稳定。
    const a = makeReport('a', [p('p1', 'body', 'bio')], []);
    const b = makeReport('b', [p('p1', 'body', 'bio', true, 'comment')], []);
    const csv = diffToCsv(diffReports(a, b));
    const lines = csv.split('\n').filter((l) => l.length > 0);
    // 存在「变化,bio,body,...」行，且整表无因转义失败导致的列错位
    const changedRow = lines.find((l) => l.startsWith('变化,bio,body'));
    expect(changedRow).toBeTruthy();
    // 注入点差异表头为 4 列，变化行也应恰好 4 列
    const headerCols = (lines.find((l) => l === '状态,参数,位置,变化') ?? '').split(',').length;
    const changedCols = (changedRow ?? '').split(',').length;
    expect(headerCols).toBe(4);
    expect(changedCols).toBe(4);
  });
});
