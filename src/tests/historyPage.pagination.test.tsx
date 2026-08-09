// HistoryPage 分页 QA：单页上限、翻页、搜索后分页随筛选结果变化、越界回退。
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import HistoryPage from '../pages/HistoryPage';
import { useScanStore } from '../store/scanStore';
import type { HistoryRecord, ReportModel, RiskLevel } from '../shared/types';

const PAGE_SIZE = 10;

function makeReport(scanId: string, target: string, risk: RiskLevel): ReportModel {
  return {
    scanId,
    target: { baseUrl: target } as ReportModel['target'],
    startedAt: '',
    finishedAt: '',
    dbms: null,
    points: [],
    vulns: [],
    data: null,
    riskLevel: risk,
    summary: {},
  } as ReportModel;
}

function makeRecord(scanId: string, target: string, risk: RiskLevel): HistoryRecord {
  return {
    schemaVersion: 1,
    scanId,
    target,
    riskLevel: risk,
    finishedAt: null,
    report: makeReport(scanId, target, risk),
  };
}

// 25 条：scan-00..scan-24，URL http://00..24.com，风险按序号取 Critical/High/Medium/Low 循环
function seed(n: number): HistoryRecord[] {
  const risks: RiskLevel[] = ['Critical', 'High', 'Medium', 'Low'];
  return Array.from({ length: n }, (_, i) =>
    makeRecord(`scan-${String(i).padStart(2, '0')}`, `http://${String(i).padStart(2, '0')}.com`, risks[i % 4]),
  );
}

beforeEach(() => {
  document.body.innerHTML = '';
  useScanStore.setState({ history: [], report: null, status: 'pending' });
});

describe('HistoryPage 分页', () => {
  it('25 条 → 第 1 页仅展示前 10 条，scan-00 可见、scan-10 不可见', () => {
    useScanStore.setState({ history: seed(25) });
    render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    expect(screen.getByText('scan-00')).toBeTruthy();
    expect(screen.queryByText('scan-10')).toBeNull();
    // 分页器出现（共 3 页）
    expect(screen.getByLabelText('Go to page 2')).toBeTruthy();
    expect(screen.getByLabelText('Go to page 3')).toBeTruthy();
  });

  it('点击第 2 页 → scan-10..scan-19 可见，scan-00 不可见', async () => {
    useScanStore.setState({ history: seed(25) });
    render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    fireEvent.click(screen.getByLabelText('Go to page 2'));
    await waitFor(() => expect(screen.getByText('scan-10')).toBeTruthy());
    expect(screen.queryByText('scan-00')).toBeNull();
    expect(screen.getByText('scan-19')).toBeTruthy();
    expect(screen.queryByText('scan-20')).toBeNull();
  });

  it('搜索「scan-0」→ 命中 10 条（scan-00..09）恰好 1 页，分页器隐藏', () => {
    useScanStore.setState({ history: seed(25) });
    const { container } = render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索 scanId / 目标 URL') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'scan-0' } });
    // scan-00..09 共 10 条，等于单页上限 → 不分页（命中片段被 <mark> 拆分，用 textContent 判断）
    expect(container.textContent).toContain('scan-00');
    expect(container.textContent).toContain('scan-09');
    expect(screen.queryByLabelText('Go to page 2')).toBeNull();
  });

  it('搜索「scan-23」→ 仅 1 条匹配，无分页器', () => {
    useScanStore.setState({ history: seed(25) });
    const { container } = render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索 scanId / 目标 URL') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'scan-23' } });
    expect(container.textContent).toContain('scan-23');
    expect(container.textContent).not.toContain('scan-00');
    expect(screen.queryByLabelText('Go to page 2')).toBeNull();
  });

  it('搜索后翻页状态重置：先翻到第 2 页，再搜索 → 回到第 1 页', async () => {
    useScanStore.setState({ history: seed(25) });
    const { container } = render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    fireEvent.click(screen.getByLabelText('Go to page 2'));
    await waitFor(() => expect(screen.getByText('scan-10')).toBeTruthy());
    // 搜索一个跨页词，结果少 → 回到第 1 页且 scan-00 可见（命中片段被 <mark> 拆分，用 textContent 判断）
    const input = screen.getByLabelText('搜索 scanId / 目标 URL') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'scan-0' } });
    await waitFor(() => expect(container.textContent).toContain('scan-00'));
    expect(screen.queryByText('scan-10')).toBeNull();
  });
});
