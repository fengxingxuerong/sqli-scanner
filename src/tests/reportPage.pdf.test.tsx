import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ReportPage from '../pages/ReportPage';
import { useScanStore } from '../store/scanStore';
import type { ReportModel } from '../shared/types';

// ReportPage 通过 useScan().getReport 拉报告；测试里注入 store.report 即可，
// 因此把 getReport mock 成 noop，避免 useEffect 副作用（与 reportPage.safeProbe 测试同手法）。
vi.mock('../hooks/useScan', () => ({
  useScan: () => ({ getReport: vi.fn() }),
}));

function baseReport(over: Partial<ReportModel> = {}): ReportModel {
  const r: any = {
    scanId: 's1',
    target: { baseUrl: 'http://t/', method: 'GET' },
    startedAt: '',
    finishedAt: '',
    dbms: null,
    points: [],
    vulns: [],
    data: null,
    riskLevel: 'Low',
    summary: {},
    ...over,
  };
  return r as ReportModel;
}

beforeEach(() => useScanStore.getState().reset());

describe('ReportPage PDF 导出接线', () => {
  it('有报告时渲染「导出 PDF」按钮（位于导出区）', () => {
    useScanStore.setState({ scanId: 's1', report: baseReport() });
    const { container } = render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    expect(screen.getByText('导出 PDF')).toBeTruthy();
    // 导出区 Paper 带 data-pdf-exclude：避免 PDF 栅格化时把自身导出按钮截进 PDF
    // （页面上有两处 data-pdf-exclude：目录锚点栏 + 导出 Paper；导出按钮在后者）
    const excluded = Array.from(container.querySelectorAll('[data-pdf-exclude="true"]')).filter((n) =>
      n.textContent?.includes('导出报告'),
    );
    expect(excluded.length).toBe(1);
    expect(excluded[0].textContent).toContain('导出 PDF');
  });
});
