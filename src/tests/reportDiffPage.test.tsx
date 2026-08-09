import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ReportDiffPage from '../pages/ReportDiffPage';
import { useScanStore } from '../store/scanStore';
import type { ReportModel, ScanConfig, HistoryRecord } from '../shared/types';

// 仅 mock downloadPdf（保留 downloadText 真实，以维持现有 createObjectURL 断言）
vi.mock('../shared/reportExport', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../shared/reportExport')>();
  return { ...actual, downloadPdf: vi.fn().mockResolvedValue(undefined) };
});

const config = {} as ScanConfig;

function makeRecord(scanId: string): HistoryRecord {
  const report: ReportModel = {
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
    points: [
      { id: 'p1', location: 'url', param: 'id', originalValue: '1', confirmed: true, technique: 'union', dbms: 'MySQL' },
    ],
    vulns: [
      { id: 'v1', pointId: 'p1', technique: 'union', dbms: 'MySQL', riskLevel: 'High', payloads: ['x'], description: 'd', trace: null },
    ],
    data: null,
    riskLevel: 'High',
    summary: {},
  };
  return {
    schemaVersion: 1,
    scanId,
    target: report.target.baseUrl,
    riskLevel: 'High',
    finishedAt: null,
    report,
  };
}

describe('ReportDiffPage 导出按钮', () => {
  beforeEach(() => {
    (URL as unknown as { createObjectURL: ReturnType<typeof vi.fn> }).createObjectURL = vi.fn(() => 'blob:mock');
    (URL as unknown as { revokeObjectURL: ReturnType<typeof vi.fn> }).revokeObjectURL = vi.fn(() => {});
    HTMLAnchorElement.prototype.click = vi.fn();
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
  });
  afterEach(() => {
    vi.restoreAllMocks();
    useScanStore.setState({ history: [] });
  });

  it('选中 A/B 后「导出差异 Markdown / JSON」按钮可点击触发下载', async () => {
    useScanStore.setState({ history: [makeRecord('a'), makeRecord('b')] });
    render(
      <MemoryRouter>
        <ReportDiffPage />
      </MemoryRouter>,
    );
    // MUI Select：mouseDown 展开 → 点选项（同 TargetForm 测试模式；用 getByLabelText 避开 label/占位双文本歧义）
    fireEvent.mouseDown(screen.getByLabelText('基准报告 (A)'));
    fireEvent.click(await screen.findByText('a · http://example.com/a'));
    fireEvent.mouseDown(screen.getByLabelText('对比报告 (B)'));
    fireEvent.click(await screen.findByText('b · http://example.com/b'));

    expect(URL.createObjectURL).toHaveBeenCalledTimes(0);
    fireEvent.click(screen.getByRole('button', { name: /导出差异 Markdown/ }));
    expect(URL.createObjectURL).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: /导出差异 JSON/ }));
    expect(URL.createObjectURL).toHaveBeenCalledTimes(2);
    fireEvent.click(screen.getByRole('button', { name: /导出差异 CSV/ }));
    expect(URL.createObjectURL).toHaveBeenCalledTimes(3);

    // PDF 导出走 downloadPdf（mock），不触发 createObjectURL
    const { downloadPdf } = await import('../shared/reportExport');
    fireEvent.click(screen.getByRole('button', { name: /导出差异 PDF/ }));
    await new Promise((r) => setTimeout(r, 0));
    expect(downloadPdf).toHaveBeenCalledTimes(1);
    expect((downloadPdf as unknown as ReturnType<typeof vi.fn>).mock.calls[0][1]).toBe('diff-a-vs-b.pdf');

    // 复制 Markdown 走 navigator.clipboard.writeText，按钮短暂显示「已复制 ✓」
    fireEvent.click(screen.getByRole('button', { name: /复制 Markdown/ }));
    await screen.findByText('已复制 ✓');
    expect(navigator.clipboard.writeText).toHaveBeenCalled();
  });

  it('未选齐 A/B 时导出按钮禁用', () => {
    useScanStore.setState({ history: [makeRecord('a'), makeRecord('b')] });
    render(
      <MemoryRouter>
        <ReportDiffPage />
      </MemoryRouter>,
    );
    // 未选择任何报告时，概览未渲染、导出按钮随概览 Paper 未出现（页面提示「请选择两份报告」）
    expect(screen.queryByRole('button', { name: /导出差异 Markdown/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /导出差异 JSON/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /导出差异 CSV/ })).toBeNull();
  });
});
