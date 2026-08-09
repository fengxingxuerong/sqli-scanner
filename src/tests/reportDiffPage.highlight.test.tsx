import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ReportDiffPage from '../pages/ReportDiffPage';
import { useScanStore } from '../store/scanStore';
import type { ReportModel, ScanConfig, HistoryRecord, InjectionPoint, Vulnerability } from '../shared/types';

// 仅 mock downloadPdf（与 reportDiffPage.test.tsx 同约定），保留 downloadText 真实
vi.mock('../shared/reportExport', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../shared/reportExport')>();
  return { ...actual, downloadPdf: vi.fn().mockResolvedValue(undefined) };
});

const config = {} as ScanConfig;
function makeRecord(scanId: string, points: InjectionPoint[], vulns: Vulnerability[]): HistoryRecord {
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
    points,
    vulns,
    data: null,
    riskLevel: 'High',
    summary: {},
  };
  return { schemaVersion: 1, scanId, target: report.target.baseUrl, riskLevel: 'High', finishedAt: null, report };
}

// A：p1(id)/p2(x) + v1(p1,High)/v2(p2,Medium)
const recA = makeRecord(
  'a',
  [
    { id: 'p1', location: 'url', param: 'id', originalValue: '1', confirmed: true, technique: 'union', dbms: 'MySQL' },
    { id: 'p2', location: 'url', param: 'x', originalValue: '1', confirmed: true, technique: 'boolean', dbms: 'MySQL' },
  ],
  [
    { id: 'v1', pointId: 'p1', technique: 'union', dbms: 'MySQL', riskLevel: 'High', payloads: ['x'], description: 'd', trace: null },
    { id: 'v2', pointId: 'p2', technique: 'boolean', dbms: 'MySQL', riskLevel: 'Medium', payloads: ['y'], description: 'd', trace: null },
  ],
);
// B：p1(id,同)/p3(y) + v1(p1,Critical 变化)/v3(p3,新增) → p2 消失、v2 消失、v3 新增、v1 变化
const recB = makeRecord(
  'b',
  [
    { id: 'p1', location: 'url', param: 'id', originalValue: '1', confirmed: true, technique: 'union', dbms: 'MySQL' },
    { id: 'p3', location: 'url', param: 'y', originalValue: '1', confirmed: true, technique: 'error', dbms: 'MySQL' },
  ],
  [
    { id: 'v1', pointId: 'p1', technique: 'union', dbms: 'MySQL', riskLevel: 'Critical', payloads: ['x'], description: 'd', trace: null },
    { id: 'v3', pointId: 'p3', technique: 'error', dbms: 'MySQL', riskLevel: 'Low', payloads: ['z'], description: 'd', trace: null },
  ],
);

async function selectAndDiff() {
  fireEvent.mouseDown(screen.getByLabelText('基准报告 (A)'));
  fireEvent.click(await screen.findByText('a · http://example.com/a'));
  fireEvent.mouseDown(screen.getByLabelText('对比报告 (B)'));
  fireEvent.click(await screen.findByText('b · http://example.com/b'));
}

describe('ReportDiffPage 差异行行内高亮', () => {
  beforeEach(() => {
    (URL as unknown as { createObjectURL: ReturnType<typeof vi.fn> }).createObjectURL = vi.fn(() => 'blob:mock');
    (URL as unknown as { revokeObjectURL: ReturnType<typeof vi.fn> }).revokeObjectURL = vi.fn(() => {});
    HTMLAnchorElement.prototype.click = vi.fn();
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: vi.fn().mockResolvedValue(undefined) },
    });
    useScanStore.setState({ history: [recA, recB] });
  });
  afterEach(() => {
    vi.restoreAllMocks();
    useScanStore.setState({ history: [] });
  });

  it('差异行携带 data-diff-status（新增/消失/变化），用于行内底色高亮', async () => {
    render(
      <MemoryRouter>
        <ReportDiffPage />
      </MemoryRouter>,
    );
    await selectAndDiff();
    const statuses = Array.from(document.querySelectorAll('[data-diff-status]')).map(
      (el) => (el as HTMLElement).getAttribute('data-diff-status'),
    );
    // 期望覆盖三种变动状态（p2 消失 / p3 新增 / v2 消失 / v3 新增 / v1 变化）
    expect(statuses).toContain('added');
    expect(statuses).toContain('removed');
    expect(statuses).toContain('changed');
  });
});
