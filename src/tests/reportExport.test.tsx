import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { reportToMarkdown, reportToCsv, downloadText } from '../shared/reportExport';
import ReportExport from '../components/ReportExport';
import { useScanStore } from '../store/scanStore';
import type { ReportModel, ScanConfig } from '../shared/types';

// 最小报告快照（覆盖注入点 / 漏洞 / 存储点 / 二阶）
function sampleReport(): ReportModel {
  const config = {} as ScanConfig;
  return {
    scanId: 'scan-1',
    target: {
      id: 't1',
      baseUrl: 'http://example.com/a?id=1',
      method: 'GET',
      bodyParams: {},
      cookieParams: {},
      headerParams: {},
      config,
    },
    startedAt: '2026-01-01T00:00:00Z',
    finishedAt: '2026-01-01T00:05:00Z',
    dbms: 'MySQL',
    points: [
      { id: 'p1', location: 'url', param: 'id', originalValue: '1', confirmed: true, technique: 'union', dbms: 'MySQL', isStorePoint: false, storeKind: null },
      { id: 'p2', location: 'body', param: 'username', originalValue: 'x', confirmed: false, technique: null, dbms: null, isStorePoint: true, storeKind: 'registration' },
      { id: 'p3', location: 'url', param: 'role,admin', originalValue: '2', confirmed: false, technique: null, dbms: null, isStorePoint: false, storeKind: null },
    ],
    vulns: [
      { id: 'v1', pointId: 'p1', technique: 'union', dbms: 'MySQL', riskLevel: 'High', payloads: ["' UNION SELECT 1-- "], description: 'union 注入', trace: null },
      { id: 'v2', pointId: 'p1', technique: 'oob', dbms: 'MySQL', riskLevel: 'Critical', payloads: ['...'], description: 'OOB 带外确认', trace: null, oob: { token: 'tok-abc123', callback: 'http://recv:8899/oob/tok-abc123' } },
    ],
    data: null,
    riskLevel: 'Critical',
    summary: {
      safeProbeAlerts: [
        { url: 'http://example.com/safe', reason: 'response length drift', baselineStatus: 200, baselineLen: 120, actualStatus: 200, actualLen: 880, ts: '2026-01-01T00:02:00Z' },
      ],
      wafDetected: [{ vendor: 'Cloudflare', confidence: 0.92, evidence: 'header: cf-ray' }],
      wafEvasion: { randomUA: true, jitterMs: 0, obfuscate: false, tamper: { enabled: true, plugins: ['space2comment'], intensity: 'medium' } },
    },
  };
}

describe('reportToMarkdown', () => {
  it('包含目标、注入点参数、漏洞技术标签与风险标签', () => {
    const md = reportToMarkdown(sampleReport());
    expect(md).toContain('# SQL 注入检测报告');
    expect(md).toContain('http://example.com/a?id=1');
    expect(md).toContain('username'); // 存储点参数
    expect(md).toContain('联合查询注入'); // TECHNIQUE_LABEL.union
    expect(md).toContain('高危'); // RISK_LABEL.High
  });

  it('含 OOB 回连确认（token + 回连地址）、安全间隔告警、WAF 标注指纹', () => {
    const md = reportToMarkdown(sampleReport());
    // 五、OOB
    expect(md).toContain('## OOB 带外回连确认');
    expect(md).toContain('tok-abc123'); // OOB token
    expect(md).toContain('http://recv:8899/oob/tok-abc123'); // 回连地址
    // 六、安全间隔告警
    expect(md).toContain('## 安全间隔探测告警');
    expect(md).toContain('http://example.com/safe');
    expect(md).toContain('response length drift');
    expect(md).toContain('120'); // 基线长度
    expect(md).toContain('880'); // 实际长度
    // 七、WAF
    expect(md).toContain('## WAF 规避与指纹');
    expect(md).toContain('space2comment'); // tamper 组合
    expect(md).toContain('Cloudflare'); // WAF 厂商
    expect(md).toContain('cf-ray'); // WAF 证据
  });
});

describe('reportToCsv', () => {
  it('含表头且每个注入点一行；含逗号的参数被双引号包裹', () => {
    const csv = reportToCsv(sampleReport());
    const lines = csv.split('\r\n');
    expect(lines[0]).toContain('注入点ID');
    expect(lines[0]).toContain('确认漏洞');
    // 前 4 行 = 表头 + 3 个注入点数据行（OOB/告警/WAF 为末尾独立块）
    expect(lines[0]).toContain('位置');
    expect(lines[1]).toContain('p1');
    expect(lines[2]).toContain('p2');
    expect(lines[3]).toContain('p3');
    expect(lines[4]).toBe(''); // 注入点块与告警块之间的空行分隔
    // 含逗号的参数 role,admin 应当被引号包裹
    expect(csv).toContain('"role,admin"');
  });

  it('主表含 OOB 两列且 OOB 漏洞行写入 token/回连地址；末尾追加告警与 WAF 块', () => {
    const csv = reportToCsv(sampleReport());
    // 表头含 OOB 两列
    expect(csv).toContain('OOB Token');
    expect(csv).toContain('OOB 回连地址');
    // OOB 漏洞所在注入点（p1）行写入 token/回连地址
    expect(csv).toContain('tok-abc123');
    expect(csv).toContain('http://recv:8899/oob/tok-abc123');
    // 末尾告警块
    expect(csv).toContain('安全间隔探测告警');
    expect(csv).toContain('http://example.com/safe');
    // 末尾 WAF 块
    expect(csv).toContain('WAF 规避与指纹');
    expect(csv).toContain('Cloudflare');
  });
});

describe('downloadText', () => {
  beforeEach(() => {
    // jsdom 未实现 createObjectURL，直接挂载 mock 函数（spyOn 对不存在属性会报错）
    (URL as unknown as { createObjectURL: ReturnType<typeof vi.fn> }).createObjectURL = vi.fn(() => 'blob:mock');
    (URL as unknown as { revokeObjectURL: ReturnType<typeof vi.fn> }).revokeObjectURL = vi.fn(() => {});
    // jsdom 未实现 a.click 副作用，mock 避免噪声
    HTMLAnchorElement.prototype.click = vi.fn();
  });
  afterEach(() => vi.restoreAllMocks());

  it('创建 Blob 对象 URL 并触发下载', () => {
    downloadText('test.md', '# hi', 'text/markdown;charset=utf-8');
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    expect(URL.revokeObjectURL).toHaveBeenCalledTimes(1);
  });
});

describe('ReportExport 组件', () => {
  beforeEach(() => {
    (URL as unknown as { createObjectURL: ReturnType<typeof vi.fn> }).createObjectURL = vi.fn(() => 'blob:mock');
    (URL as unknown as { revokeObjectURL: ReturnType<typeof vi.fn> }).revokeObjectURL = vi.fn(() => {});
    HTMLAnchorElement.prototype.click = vi.fn();
  });
  afterEach(() => {
    vi.restoreAllMocks();
    useScanStore.setState({ report: null, scanId: null });
  });

  it('「导出 Markdown」按钮触发下载', () => {
    useScanStore.setState({ report: sampleReport(), scanId: 'scan-1' });
    render(<ReportExport />);
    const btn = screen.getByRole('button', { name: /导出 Markdown/ });
    fireEvent.click(btn);
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
  });

  it('「导出 CSV」按钮触发下载', () => {
    useScanStore.setState({ report: sampleReport(), scanId: 'scan-1' });
    render(<ReportExport />);
    const btn = screen.getByRole('button', { name: /导出 CSV/ });
    fireEvent.click(btn);
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
  });

  it('未加载报告时 Markdown/CSV 按钮禁用', () => {
    useScanStore.setState({ report: null, scanId: null });
    render(<ReportExport />);
    expect((screen.getByRole('button', { name: /导出 Markdown/ }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: /导出 CSV/ }) as HTMLButtonElement).disabled).toBe(true);
  });
});
