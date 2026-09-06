// useEvents SSE 订阅 Hook 补测（原覆盖 49%，实时进度核心链路）：
//   ① scanId=null 不订阅；订阅 URL 按引擎快照选命名空间 + token 透传
//   ② 事件流：addEvent 写入 / 坏载荷跳过 / seq 游标推进
//   ③ waf_detected → wafSuggestion；scan_completed(builtin) → 报告落库 + completed
//   ④ scan_error(SCAN_NOT_FOUND) → 报告对账后置 completed（不误标 error）
//   ⑤ 断线指数退避重连（lastEventId 续传游标）+ 超限置 error
//   ⑥ 卸载清理：关连接、清退避定时器
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import { useEvents } from '../hooks/useEvents';
import { useScanStore } from '../store/scanStore';
import { apiClient } from '../shared/apiClient';

vi.mock('../shared/apiClient', () => ({
  API_BASE: 'http://test/api',
  apiClient: { get: vi.fn(), post: vi.fn() },
}));

const mockedGet = vi.mocked(apiClient.get);

// 最小 ReportModel 形状（scan_completed 载荷 / 对账报告）
const REPORT = {
  scanId: 's1',
  engine: 'builtin',
  target: { baseUrl: 'http://t/', method: 'GET' },
  finishedAt: '2026-08-31T00:00:00Z',
  riskLevel: 'High',
} as any;

class MockEventSource {
  static instances: MockEventSource[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onerror: ((ev: unknown) => void) | null = null;
  close = vi.fn();
  constructor(url: string) {
    this.url = url;
    MockEventSource.instances.push(this);
  }
  static get latest() {
    return this.instances[this.instances.length - 1];
  }
}

function resetStore() {
  useScanStore.setState({
    scanId: null,
    scanEngine: null,
    status: 'pending',
    engine: 'builtin',
    report: null,
    events: [],
    history: [],
    wafSuggestion: null,
    progressTotal: 0,
    processedPointIds: {},
  });
}

beforeEach(() => {
  resetStore();
  localStorage.removeItem('sqli_scan_history_v1');
  localStorage.removeItem('scanApiToken');
  vi.clearAllMocks();
  MockEventSource.instances = [];
  vi.stubGlobal('EventSource', MockEventSource);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

function startSessionBuiltin(id = 's1') {
  act(() => useScanStore.getState().startSession(id, 'builtin'));
}

describe('useEvents · 订阅建立', () => {
  it('scanId 为 null 时不建立连接', () => {
    renderHook(() => useEvents(null));
    expect(MockEventSource.instances).toHaveLength(0);
  });

  it('按引擎快照选命名空间（builtin → /scan）并透传 token', () => {
    localStorage.setItem('scanApiToken', 'tok 123');
    startSessionBuiltin();
    renderHook(() => useEvents('s1'));
    const es = MockEventSource.latest;
    expect(es.url).toBe('http://test/api/scan/s1/events?token=tok%20123');
  });

  it('订阅时清空上一次事件流与 WAF 建议', () => {
    act(() => {
      useScanStore.setState({ events: [{ type: 'scan_started', scanId: 'old' } as any] });
      useScanStore.getState().setWafSuggestion({ vendor: 'cloudflare' } as any);
      useScanStore.getState().startSession('s1', 'builtin');
    });
    renderHook(() => useEvents('s1'));
    const st = useScanStore.getState();
    expect(st.events).toEqual([]);
    expect(st.wafSuggestion).toBeNull();
  });
});

describe('useEvents · 事件流处理', () => {
  it('消息写入事件流；坏载荷跳过不中断；seq 推进游标', () => {
    startSessionBuiltin();
    renderHook(() => useEvents('s1'));
    const es = MockEventSource.latest;
    act(() => {
      es.onmessage!({ data: 'not-json' }); // 坏载荷
      es.onmessage!({ data: JSON.stringify({ type: 'point_testing', scanId: 's1', payload: { pointId: 'p1' }, seq: 7 }) });
    });
    const st = useScanStore.getState();
    expect(st.events).toHaveLength(1);
    expect(st.processedPointIds).toEqual({ p1: true });
  });

  it('waf_detected 写入 WAF 建议（仅推荐）', () => {
    startSessionBuiltin();
    renderHook(() => useEvents('s1'));
    act(() => MockEventSource.latest.onmessage!({ data: JSON.stringify({ type: 'waf_detected', payload: { vendor: 'cloudflare', plugins: ['space2comment'] } }) }));
    expect(useScanStore.getState().wafSuggestion).toEqual({ vendor: 'cloudflare', plugins: ['space2comment'] });
  });

  it('scan_completed（builtin）：报告快照落库 + 状态 completed', async () => {
    startSessionBuiltin();
    renderHook(() => useEvents('s1'));
    act(() => MockEventSource.latest.onmessage!({ data: JSON.stringify({ type: 'scan_completed', payload: REPORT }) }));
    await waitFor(() => expect(useScanStore.getState().status).toBe('completed'));
    const st = useScanStore.getState();
    expect(st.report!.scanId).toBe('s1');
    expect(st.history).toHaveLength(1);
  });

  it('scan_error(SCAN_NOT_FOUND)：报告对账后置 completed，不误标 error', async () => {
    startSessionBuiltin();
    renderHook(() => useEvents('s1'));
    mockedGet.mockResolvedValueOnce(REPORT); // 对账：报告已终态
    act(() => MockEventSource.latest.onmessage!({
      data: JSON.stringify({ type: 'scan_error', payload: { code: 2001, message: '扫描不存在或已结束' } }),
    }));
    await waitFor(() => expect(useScanStore.getState().status).toBe('completed'));
    expect(mockedGet).toHaveBeenCalledWith('/scan/s1/report');
  });

  it('其他 scan_error 直接置 error', () => {
    startSessionBuiltin();
    renderHook(() => useEvents('s1'));
    act(() => MockEventSource.latest.onmessage!({
      data: JSON.stringify({ type: 'scan_error', payload: { code: 5000, message: 'engine crashed' } }),
    }));
    expect(useScanStore.getState().status).toBe('error');
  });
});

describe('useEvents · 断线重连', () => {
  it('onerror 指数退避重连，重连 URL 携带 lastEventId 游标续传', () => {
    vi.useFakeTimers();
    startSessionBuiltin();
    renderHook(() => useEvents('s1'));
    // 先收一条 seq=7 的事件推进游标
    act(() => MockEventSource.latest.onmessage!({ data: JSON.stringify({ type: 'log', seq: 7 }) }));
    act(() => MockEventSource.latest.onerror!(new Event('error')));
    act(() => vi.advanceTimersByTime(1000)); // 第 1 次退避 1s
    expect(MockEventSource.instances).toHaveLength(2);
    expect(MockEventSource.latest.url).toContain('lastEventId=7');
  });

  it('连续失败超过 5 次：置 error 并追加提示事件，不再重连', () => {
    vi.useFakeTimers();
    startSessionBuiltin();
    renderHook(() => useEvents('s1'));
    for (let i = 1; i <= 5; i++) {
      act(() => MockEventSource.latest.onerror!(new Event('error')));
      act(() => vi.advanceTimersByTime(8000));
    }
    // 第 6 次失败 → 超限
    act(() => MockEventSource.latest.onerror!(new Event('error')));
    const st = useScanStore.getState();
    expect(st.status).toBe('error');
    expect(st.events.some((e) => e.type === 'scan_error' && String((e.payload as any)?.message).includes('5'))).toBe(true);
    const count = MockEventSource.instances.length;
    act(() => vi.advanceTimersByTime(30000));
    expect(MockEventSource.instances).toHaveLength(count); // 不再新建连接
  });

  it('卸载：关闭连接并清退避定时器（不再新建连接）', () => {
    vi.useFakeTimers();
    startSessionBuiltin();
    const { unmount } = renderHook(() => useEvents('s1'));
    const es = MockEventSource.latest;
    act(() => es.onerror!(new Event('error'))); // 安排 1s 后重连
    unmount();
    expect(es.close).toHaveBeenCalled();
    act(() => vi.advanceTimersByTime(10000));
    expect(MockEventSource.instances).toHaveLength(1); // 定时器已清，无新连接
  });

  it('scan_completed（sqlmap）：拉取最终报告包装落库（P0-U1 闭环）', async () => {
    act(() => useScanStore.getState().startSession('s1', 'sqlmap'));
    renderHook(() => useEvents('s1'));
    mockedGet.mockResolvedValueOnce({
      status: 'completed',
      logs: [{ ts: 't1', level: 'info', message: 'done' }],
      vulns: [{ raw: 'Parameter: id', param: 'id', technique: 'B' }],
    } as any);
    act(() => MockEventSource.latest.onmessage!({ data: JSON.stringify({ type: 'scan_completed' }) }));
    await waitFor(() => {
      const st = useScanStore.getState();
      expect(st.report?.engine).toBe('sqlmap');
    });
    expect(mockedGet).toHaveBeenCalledWith('/sqlmap/s1/report');
    const st = useScanStore.getState();
    expect(st.status).toBe('completed');
    expect(st.report!.sqlmap!.vulns).toHaveLength(1);
    expect(st.history).toHaveLength(1);
  });

  it('sqlmap 完成态拉报告失败：静默收尾，仍保有实时日志视图', async () => {
    act(() => useScanStore.getState().startSession('s1', 'sqlmap'));
    renderHook(() => useEvents('s1'));
    mockedGet.mockRejectedValueOnce(new Error('gone'));
    act(() => MockEventSource.latest.onmessage!({ data: JSON.stringify({ type: 'scan_completed' }) }));
    await waitFor(() => expect(mockedGet).toHaveBeenCalled());
    // 不崩溃、状态仍为 completed（由 scan_completed 事件本身置位）
    await waitFor(() => expect(useScanStore.getState().status).toBe('completed'));
    expect(useScanStore.getState().report).toBeNull();
  });
});
