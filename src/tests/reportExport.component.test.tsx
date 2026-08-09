import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import ReportExport from '../components/ReportExport';
import { useScanStore } from '../store/scanStore';
import type { ReportModel } from '../shared/types';

// 组件依赖 store 与导出函数；统一 mock
const downloadPdfMock = vi.fn().mockResolvedValue(undefined);
vi.mock('../shared/reportExport', async (importOriginal) => {
  const mod = await importOriginal<typeof import('../shared/reportExport')>();
  return {
    ...mod,
    downloadPdf: (node: HTMLElement, filename: string) => downloadPdfMock(node, filename),
  };
});
vi.mock('../hooks/useScan', () => ({
  useScan: () => ({ exportReport: vi.fn() }),
}));

function setStore(over: Partial<ReportModel> = {}) {
  const report = {
    scanId: 's1',
    target: { baseUrl: 'http://t/' },
    points: [],
    vulns: [],
    summary: {},
    ...over,
  } as ReportModel;
  // 直接 setState 注入（绕过 getReport 副作用），与 reportPage 测试同手法
  useScanStore.setState({ scanId: 's1', report });
}

// contentRef 指向一个真实 DOM（按钮点击时 downloadPdf 需 contentRef.current 非空）
function makeRef() {
  const el = document.createElement('div');
  return { current: el } as React.RefObject<HTMLElement>;
}

describe('ReportExport 组件', () => {
  beforeEach(() => {
    downloadPdfMock.mockReset();
  });

  it('无报告 / 无 contentRef 时「导出 PDF」按钮 disabled', () => {
    useScanStore.setState({ scanId: null, report: null });
    render(<ReportExport />);
    const btn = screen.getByText('导出 PDF').closest('button')!;
    expect(btn?.hasAttribute('disabled')).toBe(true);
  });

  it('有报告且有 contentRef 时「导出 PDF」可点击，点击触发 downloadPdf(node, 文件名)', async () => {
    setStore();
    const ref = makeRef();
    render(<ReportExport contentRef={ref} />);
    const btn = screen.getByText('导出 PDF').closest('button')!;
    expect(btn?.hasAttribute('disabled')).toBe(false);
    await fireEvent.click(btn!);
    expect(downloadPdfMock).toHaveBeenCalledTimes(1);
    expect(downloadPdfMock.mock.calls[0][0]).toBe(ref.current);
    expect(downloadPdfMock.mock.calls[0][1]).toBe('report-s1.pdf');
  });

  it('保留原有 JSON/Markdown/CSV 导出按钮', () => {
    setStore();
    render(<ReportExport contentRef={makeRef()} />);
    expect(screen.getByText('导出 JSON')).toBeTruthy();
    expect(screen.getByText('导出 Markdown')).toBeTruthy();
    expect(screen.getByText('导出 CSV')).toBeTruthy();
  });
});
