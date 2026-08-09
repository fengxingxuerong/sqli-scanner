// HistoryPage 搜索/筛选 QA：scanId/URL 文本搜索、风险等级筛选、组合过滤。
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import HistoryPage from '../pages/HistoryPage';
import { useScanStore } from '../store/scanStore';
import type { HistoryRecord, ReportModel, RiskLevel } from '../shared/types';

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

const records: HistoryRecord[] = [
  makeRecord('scan-aaa', 'http://aaa.com', 'Critical'),
  makeRecord('scan-bbb', 'http://bbb.com', 'High'),
  makeRecord('scan-ccc', 'http://ccc.com', 'Low'),
];

beforeEach(() => {
  document.body.innerHTML = '';
  useScanStore.setState({ history: [], report: null, status: 'pending' });
});

describe('HistoryPage 搜索', () => {
  it('默认渲染全部 3 条', () => {
    useScanStore.setState({ history: records });
    render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    expect(screen.getByText('http://aaa.com')).toBeTruthy();
    expect(screen.getByText('http://bbb.com')).toBeTruthy();
    expect(screen.getByText('http://ccc.com')).toBeTruthy();
  });

  it('按 URL 片段「aaa」过滤 → 仅 aaa 可见', () => {
    useScanStore.setState({ history: records });
    const { container } = render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索 scanId / 目标 URL') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'aaa' } });
    // 命中片段被 <mark> 拆分，改用 textContent 判断
    expect(container.textContent).toContain('http://aaa.com');
    expect(container.textContent).not.toContain('http://bbb.com');
    expect(container.textContent).not.toContain('http://ccc.com');
  });

  it('按 scanId「scan-ccc」过滤 → 仅 ccc 可见', () => {
    useScanStore.setState({ history: records });
    render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索 scanId / 目标 URL') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'scan-ccc' } });
    expect(screen.queryByText('http://aaa.com')).toBeNull();
    expect(screen.getByText('http://ccc.com')).toBeTruthy();
  });

  it('命中高亮：搜索「aaa」后，匹配 URL 片段被 <mark> 包裹', () => {
    useScanStore.setState({ history: records });
    const { container } = render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索 scanId / 目标 URL') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'aaa' } });
    const marks = container.querySelectorAll('mark');
    expect(marks.length).toBeGreaterThan(0);
    expect(Array.from(marks).some((m) => m.textContent === 'aaa')).toBe(true);
  });
});

describe('HistoryPage 风险筛选', () => {
  it('选「高危」→ 仅 High 风险记录可见', async () => {
    useScanStore.setState({ history: records });
    render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    fireEvent.mouseDown(screen.getByRole('combobox'));
    const opt = await screen.findByText('高危');
    fireEvent.click(opt);
    await waitFor(() => expect(screen.queryByText('http://aaa.com')).toBeNull());
    expect(screen.getByText('http://bbb.com')).toBeTruthy();
    expect(screen.queryByText('http://ccc.com')).toBeNull();
  });

  it('选「全部」→ 恢复 3 条', async () => {
    useScanStore.setState({ history: records });
    render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    fireEvent.mouseDown(screen.getByRole('combobox'));
    fireEvent.click(await screen.findByText('高危'));
    await waitFor(() => expect(screen.queryByText('http://aaa.com')).toBeNull());
    // 切回全部
    fireEvent.mouseDown(screen.getByRole('combobox'));
    fireEvent.click(await screen.findByText('全部'));
    await waitFor(() => expect(screen.getByText('http://aaa.com')).toBeTruthy());
    expect(screen.getByText('http://bbb.com')).toBeTruthy();
    expect(screen.getByText('http://ccc.com')).toBeTruthy();
  });

  it('风险筛选出现「清除风险筛选」按钮并一键重置', async () => {
    useScanStore.setState({ history: records });
    render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    // 默认（全部）无清除按钮
    expect(screen.queryByLabelText('清除风险筛选')).toBeNull();
    // 选高危 → 仅 bbb；清除按钮出现
    fireEvent.mouseDown(screen.getByRole('combobox'));
    fireEvent.click(await screen.findByText('高危'));
    await waitFor(() => expect(screen.queryByText('http://aaa.com')).toBeNull());
    expect(screen.getByLabelText('清除风险筛选')).toBeTruthy();
    // 点清除 → 恢复全部 3 条，清除按钮消失
    fireEvent.click(screen.getByLabelText('清除风险筛选'));
    await waitFor(() => expect(screen.getByText('http://aaa.com')).toBeTruthy());
    expect(screen.getByText('http://bbb.com')).toBeTruthy();
    expect(screen.getByText('http://ccc.com')).toBeTruthy();
    expect(screen.queryByLabelText('清除风险筛选')).toBeNull();
  });
});

describe('HistoryPage 组合过滤', () => {
  it('搜索「com」+ 风险「高危」→ bbb 可见，其余隐藏', async () => {
    useScanStore.setState({ history: records });
    const { container } = render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索 scanId / 目标 URL') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'com' } });
    fireEvent.mouseDown(screen.getByRole('combobox'));
    fireEvent.click(await screen.findByText('高危'));
    await waitFor(() => expect(container.textContent).toContain('http://bbb.com'));
    expect(container.textContent).not.toContain('http://aaa.com');
    expect(container.textContent).not.toContain('http://ccc.com');
  });

  it('无匹配 → 显示「无匹配记录」占位文案', () => {
    useScanStore.setState({ history: records });
    render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索 scanId / 目标 URL') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'zzz-nomatch' } });
    expect(screen.getByText('无匹配记录（请调整搜索词或风险筛选）')).toBeTruthy();
  });
});

describe('HistoryPage 搜索框清除按钮与 Esc', () => {
  it('搜索「aaa」后出现「清除搜索」按钮，点击 → 恢复全部 3 条', () => {
    useScanStore.setState({ history: records });
    const { container } = render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索 scanId / 目标 URL') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'aaa' } });
    expect(container.textContent).toContain('http://aaa.com');
    expect(container.textContent).not.toContain('http://bbb.com');
    fireEvent.click(screen.getByRole('button', { name: '清除搜索' }));
    // 命中片段恢复为完整文本，三 URL 均可见；输入框清空
    expect(container.textContent).toContain('http://aaa.com');
    expect(container.textContent).toContain('http://bbb.com');
    expect(container.textContent).toContain('http://ccc.com');
    expect((screen.getByLabelText('搜索 scanId / 目标 URL') as HTMLInputElement).value).toBe('');
  });

  it('聚焦搜索框按 Esc → 清空并恢复全部 3 条', () => {
    useScanStore.setState({ history: records });
    const { container } = render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索 scanId / 目标 URL') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'scan-ccc' } });
    expect(container.textContent).toContain('http://ccc.com');
    expect(container.textContent).not.toContain('http://aaa.com');
    fireEvent.keyDown(input, { key: 'Escape' });
    expect((screen.getByLabelText('搜索 scanId / 目标 URL') as HTMLInputElement).value).toBe('');
    expect(container.textContent).toContain('http://aaa.com');
    expect(container.textContent).toContain('http://bbb.com');
    expect(container.textContent).toContain('http://ccc.com');
  });

  it('按「/」快捷键聚焦搜索框', () => {
    useScanStore.setState({ history: records });
    render(
      <MemoryRouter>
        <HistoryPage />
      </MemoryRouter>
    );
    const input = screen.getByLabelText('搜索 scanId / 目标 URL') as HTMLInputElement;
    expect(document.activeElement).not.toBe(input);
    fireEvent.keyDown(document, { key: '/' });
    expect(document.activeElement).toBe(input);
  });
});
