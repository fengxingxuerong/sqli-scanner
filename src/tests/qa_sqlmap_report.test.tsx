// P0-U1/P0-U2 前端闭环测试：
//   ① sqlmap 模式 scan_completed 拉取 /sqlmap/:id/report → 包装为 ReportModel → 落库（useEvents）
//   ② ReportPage 渲染 sqlmap 报告分支（漏洞列表 + 日志）
//   ③ useScan.startScan sqlmap 分支透传 proxy/timeoutMs/retry/randomUA，代理留空时复用内置面板 proxy
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { renderHook } from '@testing-library/react';
import ReportPage from '../pages/ReportPage';
import { useScanStore } from '../store/scanStore';
import { useEvents } from '../hooks/useEvents';
import { useScan, wrapSqlmapReport } from '../hooks/useScan';
import { apiClient } from '../shared/apiClient';
import { DEFAULT_CONFIG, DEFAULT_SQLMAP_CONFIG } from '../shared/constants';
import type { ScanConfig, SqlmapReportData } from '../shared/types';

// mock apiClient 模块：useEvents/useScan/ReportPage 均通过它访问后端
vi.mock('../shared/apiClient', () => ({
  API_BASE: 'http://test/api',
  apiClient: { get: vi.fn(), post: vi.fn() },
}));

const HISTORY_KEY = 'sqli_scan_history_v1';

// sqlmap 桥 getReport 的原始返回（与 sqlmapBridge 契约一致）
const SQLMAP_RAW: SqlmapReportData = {
  status: 'completed',
  logs: [
    { level: 'info', text: 'starting sqlmap run', ts: '2026-01-01T00:00:00Z' },
    { level: 'success', text: "GET parameter 'id' is vulnerable", ts: '2026-01-01T00:00:01Z' },
  ],
  vulns: [
    {
      param: 'id',
      technique: 'U',
      raw: "GET parameter 'id' is vulnerable. Do you want to keep testing the others?",
    },
  ],
};

class FakeEventSource {
  static last: any = null;
  onmessage: ((ev: any) => void) | null = null;
  onerror: (() => void) | null = null;
  url: string;
  constructor(url: string) {
    this.url = url;
    FakeEventSource.last = this;
  }
  close() {}
}

function emit(ev: { type: string; scanId: string; payload: any }) {
  act(() => {
    FakeEventSource.last.onmessage({
      data: JSON.stringify({ ...ev, ts: String(Date.now()) }),
    });
  });
}

beforeEach(() => {
  localStorage.removeItem(HISTORY_KEY);
  useScanStore.setState({
    history: [],
    report: null,
    status: 'pending',
    engine: 'sqlmap',
    events: [],
  });
  vi.mocked(apiClient.get).mockReset();
  vi.mocked(apiClient.post).mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ===== ① useEvents：sqlmap 模式结果闭环 =====
describe('P0-U1 useEvents sqlmap 结果闭环', () => {
  it('scan_completed(engine=sqlmap) → GET /sqlmap/:id/report → 包装落库', async () => {
    vi.stubGlobal('EventSource', FakeEventSource as any);
    vi.mocked(apiClient.get).mockResolvedValue(SQLMAP_RAW);

    renderHook(() => useEvents('sq1'));
    expect(FakeEventSource.last.url).toBe('http://test/api/sqlmap/sq1/events');

    emit({
      type: 'scan_started',
      scanId: 'sq1',
      payload: { scanId: 'sq1', engine: 'sqlmap', target: { url: 'http://target/app?id=1', method: 'GET' } },
    });
    emit({
      type: 'scan_completed',
      scanId: 'sq1',
      payload: { scanId: 'sq1', engine: 'sqlmap', vulnCount: 1, logCount: 2 },
    });

    // 异步 IIFE 拉取报告并包装
    await vi.waitFor(() => {
      const st = useScanStore.getState();
      expect(st.report?.engine).toBe('sqlmap');
      expect(st.report?.sqlmap?.status).toBe('completed');
      expect(st.report?.sqlmap?.vulns).toHaveLength(1);
      expect(st.report?.sqlmap?.logs).toHaveLength(2);
      expect(st.report?.riskLevel).toBe('High'); // 命中注入点 → 高危
    });

    // 拉取端点确认为 sqlmap 命名空间
    expect(apiClient.get).toHaveBeenCalledWith('/sqlmap/sq1/report');

    // 历史落库（历史页可回溯），目标 URL 取自 scan_started 载荷
    const h = useScanStore.getState().history;
    expect(h.find((r) => r.scanId === 'sq1')?.report?.sqlmap?.vulns[0].param).toBe('id');
    expect(h[0].report.target.baseUrl).toBe('http://target/app?id=1');
  });
});

// ===== ② ReportPage：sqlmap 报告分支渲染 =====
describe('P0-U1 ReportPage sqlmap 报告分支', () => {
  it('渲染漏洞列表 + 日志（mock /sqlmap/:id/report 响应包装后的报告）', async () => {
    // 预置报告到 store，避免 getReport 发起 API 调用
    useScanStore.setState({
      scanId: 'sq1',
      report: wrapSqlmapReport('sq1', SQLMAP_RAW, {
        targetUrl: 'http://target/app?id=1',
        method: 'GET',
      }),
    });

    render(
      <MemoryRouter initialEntries={['/report/sq1']}>
        <ReportPage />
      </MemoryRouter>
    );

    // 报告页渲染风险等级卡片
    expect(await screen.findByText(/High/)).toBeTruthy();
    expect(screen.getByText(/http:\/\/target\/app\?id=1/)).toBeTruthy();
    // 漏洞列表标签页
    expect(screen.getByText(/漏洞列表/)).toBeTruthy();
  });
});

// ===== ③ useScan.startScan：SqlmapConfig 新字段序列化 + 代理复用 =====
describe('P0-U2 startScan sqlmap 参数透传', () => {
  it('透传 proxy/timeoutMs/retry/randomUA；代理留空时复用内置面板 proxy', async () => {
    useScanStore.setState({ engine: 'builtin' });
    vi.mocked(apiClient.post).mockResolvedValue({ scanId: 'sq2' });

    const { result } = renderHook(() => useScan());
    await act(async () => {
      await result.current.startScan({
        engine: 'sqlmap',
        url: 'http://target/app',
        method: 'GET',
        config: { ...DEFAULT_CONFIG, proxy: 'http://127.0.0.1:8080' } as ScanConfig,
        sqlmapConfig: {
          ...DEFAULT_SQLMAP_CONFIG,
          proxy: null, // 显式留空 → 复用内置面板 proxy
          timeoutMs: 5000,
          retry: 0,
          randomUA: true,
        },
      });
    });

    const [path, body] = vi.mocked(apiClient.post).mock.calls[0];
    expect(path).toBe('/sqlmap/start');
    const sqlmap = (body as any).config.sqlmap;
    expect(sqlmap.timeoutMs).toBe(5000);
    expect(sqlmap.retry).toBe(0);
    expect(sqlmap.randomUA).toBe(true);
    expect(sqlmap.proxy).toBe('http://127.0.0.1:8080');
    expect(sqlmap.threads).toBe(DEFAULT_SQLMAP_CONFIG.threads); // 原有字段不受影响
  });

  it('sqlmapConfig 显式指定代理时优先于内置面板 proxy', async () => {
    useScanStore.setState({ engine: 'builtin' });
    vi.mocked(apiClient.post).mockResolvedValue({ scanId: 'sq3' });

    const { result } = renderHook(() => useScan());
    await act(async () => {
      await result.current.startScan({
        engine: 'sqlmap',
        url: 'http://target/app',
        method: 'POST',
        bodyParams: { id: '1' },
        config: { ...DEFAULT_CONFIG, proxy: 'http://10.0.0.1:3128' } as ScanConfig,
        sqlmapConfig: { ...DEFAULT_SQLMAP_CONFIG, proxy: 'socks5://127.0.0.1:1080' },
      });
    });

    const [, body] = vi.mocked(apiClient.post).mock.calls[0];
    expect((body as any).config.sqlmap.proxy).toBe('socks5://127.0.0.1:1080');
    // POST body 序列化为 form-urlencoded
    expect((body as any).target.data).toBe('id=1');
  });
});
