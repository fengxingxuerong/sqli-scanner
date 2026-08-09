// ReportDiffPage 差异搜索 QA：搜索框过滤注入点/漏洞两张差异表 + 高亮 + 清除按钮 + Esc
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ReportDiffPage from '../pages/ReportDiffPage';
import { useScanStore } from '../store/scanStore';
import type { ReportModel, ScanConfig, HistoryRecord, RiskLevel } from '../shared/types';

const config = {} as ScanConfig;

// A 与 B 构造为「有差异」的两份报告（param / 风险 不同），确保 diff 非空
function makeRecord(scanId: string, pointParam: string, risk: RiskLevel): HistoryRecord {
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
    startedAt: '',
    finishedAt: null,
    dbms: 'MySQL',
    points: [
      { id: 'p1', location: 'url', param: pointParam, originalValue: '1', confirmed: true, technique: 'union', dbms: 'MySQL' },
    ],
    vulns: [
      { id: 'v1', pointId: 'p1', technique: 'union', dbms: 'MySQL', riskLevel: risk, payloads: ['x'], description: 'd', trace: null },
    ],
    data: null,
    riskLevel: risk,
    summary: {},
  } as ReportModel;
  return {
    schemaVersion: 1,
    scanId,
    target: report.target.baseUrl,
    riskLevel: risk,
    finishedAt: null,
    report,
  };
}

async function selectAB() {
  fireEvent.mouseDown(screen.getByLabelText('基准报告 (A)'));
  fireEvent.click(await screen.findByText('a · http://example.com/a'));
  fireEvent.mouseDown(screen.getByLabelText('对比报告 (B)'));
  fireEvent.click(await screen.findByText('b · http://example.com/b'));
}

beforeEach(() => {
  document.body.innerHTML = '';
  useScanStore.setState({ history: [], report: null, status: 'pending' });
});

describe('ReportDiffPage 差异搜索', () => {
  it('选 A/B 后，搜「id」→ 出现「清除差异搜索」按钮 + 命中计数；点击清除恢复', async () => {
    useScanStore.setState({ history: [makeRecord('a', 'id', 'High'), makeRecord('b', 'name', 'Critical')] });
    render(
      <MemoryRouter>
        <ReportDiffPage />
      </MemoryRouter>,
    );
    await selectAB();
    // 默认两张表渲染
    expect(screen.getByText('注入点差异')).toBeTruthy();
    expect(screen.getByText('漏洞差异')).toBeTruthy();

    const input = screen.getByLabelText('搜索差异（参数 / 位置 / 技术 / 风险 / 变化）') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'id' } });
    // 清除按钮出现 + 计数 caption 出现
    expect(screen.getByRole('button', { name: '清除差异搜索' })).toBeTruthy();
    expect(screen.getByText(/注入点差异 命中/)).toBeTruthy();
    // 点击清除 → 按钮消失、输入框清空
    fireEvent.click(screen.getByRole('button', { name: '清除差异搜索' }));
    await waitFor(() => expect(screen.queryByRole('button', { name: '清除差异搜索' })).toBeNull());
    expect(input.value).toBe('');
  });

  it('搜「union」→ 两张差异表均命中（计数 > 0）', async () => {
    useScanStore.setState({ history: [makeRecord('a', 'id', 'High'), makeRecord('b', 'name', 'Critical')] });
    render(
      <MemoryRouter>
        <ReportDiffPage />
      </MemoryRouter>,
    );
    await selectAB();
    const input = screen.getByLabelText('搜索差异（参数 / 位置 / 技术 / 风险 / 变化）') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'union' } });
    const hits = screen.getByText(/注入点差异 命中 (\d+) \/ \d+ · 漏洞差异 命中 (\d+) \/ \d+/);
    expect(hits).toBeTruthy();
    // 至少一张表有命中（union 是两者共有的技术）
    expect(input.value).toBe('union');
  });

  it('搜无匹配词 → 显示「无匹配差异」占位，两张表空', async () => {
    useScanStore.setState({ history: [makeRecord('a', 'id', 'High'), makeRecord('b', 'name', 'Critical')] });
    render(
      <MemoryRouter>
        <ReportDiffPage />
      </MemoryRouter>,
    );
    await selectAB();
    const input = screen.getByLabelText('搜索差异（参数 / 位置 / 技术 / 风险 / 变化）') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'zzz-nomatch' } });
    expect(screen.getByText('无匹配差异（请调整搜索词）')).toBeTruthy();
    expect(screen.getByText('无匹配的注入点差异')).toBeTruthy();
    expect(screen.getByText('无匹配的漏洞差异')).toBeTruthy();
  });

  it('聚焦搜索框按 Esc → 清空', async () => {
    useScanStore.setState({ history: [makeRecord('a', 'id', 'High'), makeRecord('b', 'name', 'Critical')] });
    render(
      <MemoryRouter>
        <ReportDiffPage />
      </MemoryRouter>,
    );
    await selectAB();
    const input = screen.getByLabelText('搜索差异（参数 / 位置 / 技术 / 风险 / 变化）') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'Critical' } });
    fireEvent.keyDown(input, { key: 'Escape' });
    expect(input.value).toBe('');
  });

  it('按「/」快捷键聚焦差异搜索框', async () => {
    useScanStore.setState({ history: [makeRecord('a', 'id', 'High'), makeRecord('b', 'name', 'Critical')] });
    render(
      <MemoryRouter>
        <ReportDiffPage />
      </MemoryRouter>,
    );
    await selectAB();
    const input = screen.getByLabelText('搜索差异（参数 / 位置 / 技术 / 风险 / 变化）') as HTMLInputElement;
    expect(document.activeElement).not.toBe(input);
    fireEvent.keyDown(document, { key: '/' });
    expect(document.activeElement).toBe(input);
  });
});
