// ============================================================================
// desktopRuntimeBase.test.tsx —— 运行期 API base 必须贯通到 SSE 与导出两个出口
//
// 存在理由：A3 加固把桌面版 sidecar 端口改成「4567 被占则随机」，并给了前端
// `setApiBase()` 这个运行期出口 —— 但只有 `apiClient` 的两个 axios 拦截器
// （apiClient.ts:62/97）调了 `getApiBase()`。另外两个出口拼的是**编译期常量**
// `API_BASE`（`.env.tauri` 把它钉成 `http://127.0.0.1:4567`）：
//   · src/hooks/useEvents.ts   —— EventSource 订阅 URL
//   · src/hooks/useScan.ts     —— 报告另存盘的 fetch URL
// ⇒ 端口退回随机时，桌面版「扫描能起、进度永远不动、导出永远 404」。
//
// 为什么既有测试没抓到（这条比缺陷本身更值得记）：
// `useEvents.test.tsx` / `useScan.export.test.tsx` 都 `vi.mock('../shared/apiClient', …)`
// 并把 `API_BASE` 提供一个常量 —— 把持有运行期值的模块整个换掉，自然就看不见"没读它"。
// 所以本文件刻意**不 mock apiClient**，用真模块 + 只桩住网络方法，断言落回外部可观测的请求形态。
// ============================================================================
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { apiClient, setApiBase, setApiToken, getApiBase } from '../shared/apiClient';
import { useEvents } from '../hooks/useEvents';
import { useScan } from '../hooks/useScan';
import { useScanStore } from '../store/scanStore';

// tauriBridge 只桩住落盘（jsdom 里没有原生 dialog/fs）；apiClient 保持真模块。
vi.mock('../shared/tauriBridge', () => ({
  tauriBridge: { saveFile: vi.fn().mockResolvedValue(undefined), isTauri: false },
}));

const RUNTIME = 'http://127.0.0.1:54321/api';

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
}

const CSV = 'url,param,technique\nhttp://t/?id=1,id,union\n';
const fetchMock = vi.fn();

describe('桌面版运行期 base 贯通（SSE + 导出）', () => {
  beforeEach(() => {
    useScanStore.setState({ scanId: 's1', scanEngine: 'builtin', engine: 'builtin', status: 'running', events: [] });
    localStorage.clear();
    MockEventSource.instances = [];
    fetchMock.mockReset();
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-disposition': 'attachment; filename="report_s1.csv"', 'content-type': 'text/csv' }),
      text: async () => CSV,
    });
    vi.stubGlobal('EventSource', MockEventSource);
    vi.stubGlobal('fetch', fetchMock);
    vi.spyOn(apiClient, 'get').mockResolvedValue({} as never);
    vi.spyOn(apiClient, 'post').mockResolvedValue({} as never);
    setApiToken('');
    setApiBase('');
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    setApiBase('');
    setApiToken('');
  });

  it('前置事实：未注入运行期 base 时两个出口用编译期值（回退路径正常）', async () => {
    expect(getApiBase()).toBe('/api');
    renderHook(() => useEvents('s1'));
    await waitFor(() => expect(MockEventSource.instances.length).toBeGreaterThan(0));
    expect(MockEventSource.instances[0].url.startsWith('/api/')).toBe(true);

    const { result } = renderHook(() => useScan());
    await result.current.exportReport('s1', 'csv');
    expect(String(fetchMock.mock.calls[0][0]).startsWith('/api/')).toBe(true);
  });

  it('★断链★ setApiBase 之后 SSE 必须连运行期端口', async () => {
    setApiBase(RUNTIME);
    renderHook(() => useEvents('s1'));
    await waitFor(() => expect(MockEventSource.instances.length).toBeGreaterThan(0));
    expect(MockEventSource.instances[0].url.startsWith(RUNTIME)).toBe(
      true,
      `SSE 仍在拼编译期常量，桌面版端口退回随机时进度永远不动。实际 URL=${MockEventSource.instances[0].url}`
    );
  });

  it('★断链★ setApiBase 之后报告导出必须打运行期端口', async () => {
    setApiBase(RUNTIME);
    const { result } = renderHook(() => useScan());
    await result.current.exportReport('s1', 'csv');
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url.startsWith(RUNTIME)).toBe(
      true,
      `导出 URL 仍拼编译期常量，随机端口下永远 404。实际 URL=${url}`
    );
  });
});
