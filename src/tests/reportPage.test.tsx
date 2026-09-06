// ReportPage 报告页补测（原覆盖 60.6%）：
//   ① 加载中 / 加载失败 / 未找到 三分支
//   ② builtin 报告：空漏洞 vs 有漏洞（展开详情 toggle）
//   ③ sqlmap 报告：SqlmapVulnCard 渲染 + sqlmap 日志 Tab
//   ④ 续跑按钮（仅 builtin + 会话配置）与失败提示
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import ReportPage from '../pages/ReportPage';
import { useScanStore } from '../store/scanStore';
import type { ReportModel } from '../shared/types';

const { getReportMock, startScanMock } = vi.hoisted(() => ({
  getReportMock: vi.fn(),
  startScanMock: vi.fn(),
}));

vi.mock('../hooks/useScan', () => ({
  useScan: () => ({ getReport: getReportMock, startScan: startScanMock }),
}));

function makeReport(overrides: Partial<ReportModel> = {}): ReportModel {
  return {
    scanId: 's1',
    engine: 'builtin',
    target: { baseUrl: 'http://t/a.php?id=1', method: 'GET', bodyParams: {}, cookieParams: {}, headerParams: {} },
    startedAt: '',
    finishedAt: '',
    dbms: null,
    points: [],
    vulns: [],
    data: null,
    riskLevel: 'High',
    summary: {},
    ...overrides,
  } as ReportModel;
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/report/s1']}>
      <Routes>
        <Route path="/report/:id" element={<ReportPage />} />
        <Route path="/scan" element={<div>SCAN_PAGE_PROBE</div>} />
        <Route path="/" element={<div>HOME_PROBE</div>} />
      </Routes>
    </MemoryRouter>
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.removeItem('sqli_scan_history_v1');
  useScanStore.setState({
    scanId: null, scanEngine: null, status: 'pending', engine: 'builtin',
    report: null, events: [], history: [], wafSuggestion: null,
  });
});

describe('ReportPage · 加载分支', () => {
  it('加载中显示进度条提示', () => {
    getReportMock.mockReturnValue(new Promise(() => undefined)); // 挂起
    renderPage();
    expect(screen.getByText('加载报告中...')).toBeTruthy();
  });

  it('加载失败：错误 Alert + 返回首页', async () => {
    getReportMock.mockRejectedValueOnce(new Error('boom'));
    renderPage();
    await waitFor(() => expect(screen.getByText('boom')).toBeTruthy());
    expect(screen.getByText('返回首页')).toBeTruthy();
  });

  it('报告不存在（getReport 返回 null）显示「未找到报告」', async () => {
    getReportMock.mockResolvedValueOnce(null);
    renderPage();
    await waitFor(() => expect(screen.getByText('未找到报告')).toBeTruthy());
  });
});

describe('ReportPage · builtin 报告渲染', () => {
  it('空漏洞列表显示「未发现漏洞」成功态', async () => {
    getReportMock.mockImplementation(async () => { useScanStore.getState().setReport(makeReport()); return makeReport(); });
    renderPage();
    await waitFor(() => expect(screen.getByText('未发现漏洞')).toBeTruthy());
  });

  it('有漏洞：卡片可展开详情（aria-expanded toggle）', async () => {
    const report = makeReport({
      vulns: [{ id: 'v1', param: 'id', technique: 'boolean', payload: "1' AND 1=1", riskLevel: 'High' }] as any,
    });
    getReportMock.mockResolvedValueOnce(report);
    useScanStore.getState().setReport(report);
    renderPage();
    await waitFor(() => expect(screen.getByRole('button', { expanded: false })).toBeTruthy());
    fireEvent.click(screen.getByRole('button', { expanded: false }));
    expect(screen.getByRole('button', { expanded: true })).toBeTruthy();
  });
});

describe('ReportPage · sqlmap 报告渲染', () => {
  it('sqlmap 命中：SqlmapVulnCard 展示参数与确认注入 + 日志 Tab 出现', async () => {
    const report = makeReport({
      engine: 'sqlmap',
      sqlmap: {
        status: 'completed',
        logs: [{ ts: 't1', level: 'info', message: '1' }, { ts: 't2', level: 'info', message: '2' }],
        vulns: [{ raw: 'Parameter: id', param: 'id', technique: 'B' }],
      } as any,
    });
    getReportMock.mockResolvedValueOnce(report);
    useScanStore.getState().setReport(report);
    renderPage();
    await waitFor(() => expect(screen.getByText('参数 id')).toBeTruthy());
    expect(screen.getByText('sqlmap 确认注入')).toBeTruthy();
    expect(screen.getByText('sqlmap 日志 (2)')).toBeTruthy();
  });

  it('sqlmap 未命中：显示「sqlmap 未确认注入点」', async () => {
    const report = makeReport({ engine: 'sqlmap', sqlmap: { status: 'completed', logs: [], vulns: [] } as any });
    getReportMock.mockResolvedValueOnce(report);
    useScanStore.getState().setReport(report);
    renderPage();
    await waitFor(() => expect(screen.getByText('sqlmap 未确认注入点')).toBeTruthy());
  });
});

describe('ReportPage · 续跑', () => {
  it('builtin + 会话配置：显示续跑按钮，点击发起扫描并跳转扫描页', async () => {
    const report = makeReport({ target: { baseUrl: 'http://t/a.php?id=1', method: 'GET', bodyParams: {}, cookieParams: {}, headerParams: {}, config: { sessionDefault: true } } as any });
    getReportMock.mockResolvedValueOnce(report);
    startScanMock.mockResolvedValueOnce('s1');
    useScanStore.getState().setReport(report);
    renderPage();
    await waitFor(() => expect(screen.getByText('续跑')).toBeTruthy());
    fireEvent.click(screen.getByText('续跑'));
    await waitFor(() => expect(screen.getByText('SCAN_PAGE_PROBE')).toBeTruthy());
    expect(startScanMock).toHaveBeenCalledTimes(1);
    expect(startScanMock.mock.calls[0][0].config.sessionFile).toBe('sqli-session-latest.json');
  });

  it('续跑失败：错误信息内联展示', async () => {
    const report = makeReport({ target: { baseUrl: 'u', method: 'GET', bodyParams: {}, cookieParams: {}, headerParams: {}, config: { sessionDefault: true } } as any });
    getReportMock.mockResolvedValueOnce(report);
    startScanMock.mockRejectedValueOnce(new Error('已有扫描正在运行'));
    useScanStore.getState().setReport(report);
    renderPage();
    await waitFor(() => expect(screen.getByText('续跑')).toBeTruthy());
    fireEvent.click(screen.getByText('续跑'));
    await waitFor(() => expect(screen.getByText('已有扫描正在运行')).toBeTruthy());
  });

  it('无会话配置 / sqlmap 报告：不显示续跑按钮', async () => {
    const report = makeReport();
    getReportMock.mockResolvedValueOnce(report);
    useScanStore.getState().setReport(report);
    renderPage();
    await waitFor(() => expect(screen.getByText('刷新')).toBeTruthy());
    expect(screen.queryByText('续跑')).toBeNull();
  });
});
