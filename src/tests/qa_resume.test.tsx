// P2-S11 会话续跑（--resume）前端闭环测试：
//   ① store：saveScanToHistory 保留 sessionFile/sessionDefault（脱敏不剥离会话配置）
//   ② HistoryPage UI：有 sessionFile/sessionDefault 的内置引擎记录显示「续跑」按钮，
//      无会话配置 / sqlmap 记录不显示；点击续跑携带原配置+sessionFile 重新发起扫描并跳转扫描页
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import HistoryPage from '../pages/HistoryPage';
import { useScanStore } from '../store/scanStore';
import { apiClient } from '../shared/apiClient';
import type { ReportModel, HistoryRecord } from '../shared/types';

// mock apiClient：useScan.startScan 经它向后端发起续跑
vi.mock('../shared/apiClient', () => ({
  API_BASE: 'http://test/api',
  apiClient: { get: vi.fn(), post: vi.fn() },
}));

const HISTORY_KEY = 'sqli_scan_history_v1';

// 构造内置引擎报告（config 可覆盖，含 bodyParams 等续跑所需字段）
function makeReport(scanId: string, cfg: Partial<ReportModel['target']['config']>): ReportModel {
  return {
    scanId,
    engine: 'builtin',
    target: {
      baseUrl: `http://target/?id=${scanId}`,
      method: 'GET',
      bodyParams: { id: '1' },
      cookieParams: {},
      headerParams: {},
      config: { sessionDefault: false, sessionFile: undefined, ...cfg } as ReportModel['target']['config'],
    },
    startedAt: '',
    finishedAt: '',
    dbms: null,
    points: [],
    vulns: [],
    data: null,
    riskLevel: 'Low',
    summary: {},
  } as ReportModel;
}

function makeRecord(scanId: string, report: ReportModel): HistoryRecord {
  return { schemaVersion: 1, scanId, target: report.target.baseUrl, riskLevel: report.riskLevel, finishedAt: null, report };
}

beforeEach(() => {
  localStorage.removeItem(HISTORY_KEY);
  useScanStore.setState({ history: [], report: null, status: 'pending', engine: 'builtin', scanId: null });
  vi.mocked(apiClient.get).mockReset();
  vi.mocked(apiClient.post).mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ===== ① store：会话配置随快照持久化 =====
describe('P2-S11 saveScanToHistory 保留会话配置', () => {
  it('sessionFile/sessionDefault 随快照落库，认证/代理仍被脱敏', () => {
    const { saveScanToHistory } = useScanStore.getState();
    const report = makeReport('s1', { sessionFile: 'sqli-session-abc.json', sessionDefault: true });
    // 原始报告携带认证，落库后应被剥离
    (report.target.config as any).auth = { basic: { username: 'u', password: 'p' } };
    saveScanToHistory(report);

    const stored = useScanStore.getState().history[0];
    expect(stored.report.target.config.sessionFile).toBe('sqli-session-abc.json');
    expect(stored.report.target.config.sessionDefault).toBe(true);
    expect(stored.report.target.config.auth).toBeNull(); // 明文凭证不落盘
  });
});

// ===== ② HistoryPage UI =====
describe('P2-S11 HistoryPage 续跑按钮', () => {
  it('有 sessionFile 的内置引擎记录显示「续跑」按钮', () => {
    useScanStore.setState({
      history: [makeRecord('a', makeReport('a', { sessionFile: 'sqli-session-abc.json' }))],
    });
    render(
      <MemoryRouter initialEntries={['/history']}>
        <HistoryPage />
      </MemoryRouter>
    );
    expect(screen.getByLabelText('续跑')).toBeTruthy();
  });

  it('仅 sessionDefault=true 的记录也显示「续跑」按钮（自动会话）', () => {
    useScanStore.setState({
      history: [makeRecord('a', makeReport('a', { sessionDefault: true }))],
    });
    render(
      <MemoryRouter initialEntries={['/history']}>
        <HistoryPage />
      </MemoryRouter>
    );
    expect(screen.getByLabelText('续跑')).toBeTruthy();
  });

  it('无会话配置或 sqlmap 记录不显示「续跑」按钮', () => {
    useScanStore.setState({
      history: [
        makeRecord('plain', makeReport('plain', {})), // 无会话
        {
          ...makeRecord('sql', makeReport('sql', { sessionFile: 'x.json' })),
          report: { ...makeReport('sql', { sessionFile: 'x.json' }), engine: 'sqlmap' },
        },
      ],
    });
    render(
      <MemoryRouter initialEntries={['/history']}>
        <HistoryPage />
      </MemoryRouter>
    );
    expect(screen.queryByLabelText('续跑')).toBeNull();
  });

  it('点击续跑 → POST /scan/start 携带原配置+sessionFile，并跳转扫描页', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({ scanId: 'resumed1' });
    useScanStore.setState({
      history: [makeRecord('a', makeReport('a', { sessionFile: 'sqli-session-abc.json', sessionDefault: true }))],
    });
    render(
      <MemoryRouter initialEntries={['/history']}>
        <Routes>
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/scan" element={<div>SCAN_PAGE</div>} />
        </Routes>
      </MemoryRouter>
    );

    fireEvent.click(screen.getByLabelText('续跑'));

    // 续跑请求：复用原配置 + 显式携带原 sessionFile
    await waitFor(() => expect(apiClient.post).toHaveBeenCalled());
    const [path, body] = vi.mocked(apiClient.post).mock.calls[0];
    expect(path).toBe('/scan/start');
    expect((body as any).url).toBe('http://target/?id=a');
    expect((body as any).method).toBe('GET');
    expect((body as any).bodyParams).toEqual({ id: '1' });
    expect((body as any).config.sessionFile).toBe('sqli-session-abc.json');
    expect((body as any).config.sessionDefault).toBe(true);

    // 跳转到扫描页查看实时进度
    expect(await screen.findByText('SCAN_PAGE')).toBeTruthy();
    expect(useScanStore.getState().scanId).toBe('resumed1');
    expect(useScanStore.getState().status).toBe('running');
  });

  it('sessionDefault 自动会话未落显式文件名时，续跑回退到后端默认会话文件名', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({ scanId: 'resumed2' });
    useScanStore.setState({
      history: [makeRecord('b', makeReport('b', { sessionDefault: true }))],
    });
    render(
      <MemoryRouter initialEntries={['/history']}>
        <HistoryPage />
      </MemoryRouter>
    );

    fireEvent.click(screen.getByLabelText('续跑'));
    await waitFor(() => expect(apiClient.post).toHaveBeenCalled());
    const [, body] = vi.mocked(apiClient.post).mock.calls[0];
    expect((body as any).config.sessionFile).toBe('sqli-session-latest.json');
  });
});
