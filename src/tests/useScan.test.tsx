// useScan 扫描控制 Hook 补测（原覆盖 55%，核心控制面逻辑）：
//   ① startScan 双引擎路由（builtin → /scan/start；sqlmap → /sqlmap/start + target 组装）
//   ② 重复扫描守卫 / API 失败置 error
//   ③ stop/pause/resume 引擎快照选端点 + best-effort 容错
//   ④ getReport 会话复用 / 引擎路由 / SCAN_NOT_FOUND→null / 其他错误上抛 / P1-1 竞态守卫
//   ⑤ exportReport 失败抛错 + 成功走 tauriBridge.saveFile
//   ⑥ wrapSqlmapReport 纯函数（风险推导 / 字段容错）
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook } from '@testing-library/react';
import { useScan, wrapSqlmapReport } from '../hooks/useScan';
import { useScanStore } from '../store/scanStore';
import { apiClient, ApiError } from '../shared/apiClient';
import { tauriBridge } from '../shared/tauriBridge';
import { DEFAULT_CONFIG } from '../shared/constants';
import { ErrorCode } from '../shared/types';

vi.mock('../shared/apiClient', () => ({
  API_BASE: 'http://test/api',
  ApiError: class MockApiError extends Error {
    code: number;
    constructor(code: number, message: string) {
      super(message);
      this.code = code;
    }
  },
  apiClient: { get: vi.fn(), post: vi.fn() },
}));

vi.mock('../shared/tauriBridge', () => ({
  tauriBridge: { saveFile: vi.fn() },
}));

const mockedPost = vi.mocked(apiClient.post);
const mockedGet = vi.mocked(apiClient.get);

const BASE_PAYLOAD = {
  engine: 'builtin' as const,
  url: 'http://target/item.php?id=1',
  method: 'GET' as const,
  config: { ...DEFAULT_CONFIG },
};

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
  vi.clearAllMocks();
});

describe('useScan · startScan', () => {
  it('builtin 引擎：POST /scan/start 并原子写入会话（scanId+scanEngine+running）', async () => {
    mockedPost.mockResolvedValueOnce({ scanId: 's1' } as any);
    const { result } = renderHook(() => useScan());
    const id = await result.current.startScan(BASE_PAYLOAD);
    expect(id).toBe('s1');
    expect(mockedPost).toHaveBeenCalledWith('/scan/start', BASE_PAYLOAD);
    const st = useScanStore.getState();
    expect(st.scanId).toBe('s1');
    expect(st.scanEngine).toBe('builtin');
    expect(st.status).toBe('running');
  });

  it('running 会话下再次启动被守卫拒绝且不发起请求', async () => {
    useScanStore.setState({ scanId: 'old', scanEngine: 'builtin', status: 'running' });
    const { result } = renderHook(() => useScan());
    await expect(result.current.startScan(BASE_PAYLOAD)).rejects.toThrow('已有扫描正在运行');
    expect(mockedPost).not.toHaveBeenCalled();
  });

  it('API 失败：状态置 error 并向上抛出', async () => {
    mockedPost.mockRejectedValueOnce(new Error('network down'));
    const { result } = renderHook(() => useScan());
    await expect(result.current.startScan(BASE_PAYLOAD)).rejects.toThrow('network down');
    expect(useScanStore.getState().status).toBe('error');
  });

  it('sqlmap 引擎：POST /sqlmap/start，POST body 组装为 URLSearchParams，Basic Auth 拼入 headers', async () => {
    mockedPost.mockResolvedValueOnce({ scanId: 'm1' } as any);
    const { result } = renderHook(() => useScan());
    const id = await result.current.startScan({
      engine: 'sqlmap',
      url: 'http://t/a.php',
      method: 'POST',
      bodyParams: { id: '1', u: 'x' },
      config: {
        ...DEFAULT_CONFIG,
        auth: { basic: { username: 'admin', password: 'p@ss' }, headers: { 'X-A': '1' } },
      },
    });
    expect(id).toBe('m1');
    const [url, body] = mockedPost.mock.calls[0] as [string, any];
    expect(url).toBe('/sqlmap/start');
    expect(body.target.data).toBe('id=1&u=x');
    // headers：自定义头与 Basic Auth 并存（换行拼接）
    expect(body.target.headers).toContain('X-A: 1');
    expect(body.target.headers).toContain(`Authorization: Basic ${btoa('admin:p@ss')}`);
    expect(body.config.sqlmap.proxy).toBeNull();
    expect(useScanStore.getState().scanEngine).toBe('sqlmap');
  });
});

describe('useScan · stop/pause/resume（引擎快照选端点）', () => {
  it('stopScan：会话快照为 sqlmap 时走 /sqlmap 路由；API 失败仍置 stopped（best-effort）', async () => {
    useScanStore.setState({ scanId: 'm1', scanEngine: 'sqlmap', status: 'running' });
    mockedPost.mockRejectedValueOnce(new Error('down'));
    const { result } = renderHook(() => useScan());
    await expect(result.current.stopScan('m1')).resolves.toBeUndefined();
    expect(mockedPost).toHaveBeenCalledWith('/sqlmap/m1/stop');
    expect(useScanStore.getState().status).toBe('stopped');
  });

  it('pauseScan 失败静默保持状态；resumeScan 成功置 running', async () => {
    useScanStore.setState({ scanId: 's1', scanEngine: 'builtin', status: 'running' });
    const { result } = renderHook(() => useScan());
    mockedPost.mockRejectedValueOnce(new Error('down'));
    await expect(result.current.pauseScan('s1')).resolves.toBeUndefined();
    expect(useScanStore.getState().status).toBe('running'); // 未被改为 paused

    mockedPost.mockResolvedValueOnce({} as any);
    await result.current.resumeScan('s1');
    expect(useScanStore.getState().status).toBe('running');
    expect(mockedPost).toHaveBeenLastCalledWith('/scan/s1/resume');
  });
});

describe('useScan · getReport', () => {
  const REPORT = { scanId: 's1', engine: 'builtin' } as any;

  it('当前会话已有同 id 报告时直接复用，不重复请求', async () => {
    useScanStore.setState({ report: REPORT });
    const { result } = renderHook(() => useScan());
    const r = await result.current.getReport('s1');
    expect(r).toBe(REPORT);
    expect(mockedGet).not.toHaveBeenCalled();
  });

  it('历史记录为 sqlmap 引擎时回溯走 /sqlmap 路由并包装报告', async () => {
    useScanStore.setState({
      history: [{ schemaVersion: 1, scanId: 'h1', target: 'u', riskLevel: 'High', finishedAt: null, report: { engine: 'sqlmap' } as any }],
    });
    mockedGet.mockResolvedValueOnce({ status: 'completed', logs: [], vulns: [{ id: 1 }] } as any);
    const { result } = renderHook(() => useScan());
    const r = await result.current.getReport('h1');
    expect(mockedGet).toHaveBeenCalledWith('/sqlmap/h1/report');
    expect(r!.engine).toBe('sqlmap');
    expect(r!.riskLevel).toBe('High');
    expect(useScanStore.getState().report!.scanId).toBe('h1');
  });

  it('SCAN_NOT_FOUND 返回 null；其他错误向上抛出', async () => {
    const { result } = renderHook(() => useScan());
    mockedGet.mockRejectedValueOnce(new ApiError(ErrorCode.SCAN_NOT_FOUND, 'not found'));
    await expect(result.current.getReport('ghost')).resolves.toBeNull();

    mockedGet.mockRejectedValueOnce(new ApiError(-1, 'boom'));
    await expect(result.current.getReport('s2')).rejects.toThrow('boom');
  });

  it('P1-1 竞态守卫：过期响应被丢弃（旧报告不得覆盖新报告）', async () => {
    let resolveA!: (v: unknown) => void;
    const pA = new Promise((res) => { resolveA = res; });
    mockedGet.mockImplementationOnce(() => pA as any); // 请求 A（慢）
    mockedGet.mockResolvedValueOnce({ scanId: 'b', engine: 'builtin' } as any); // 请求 B（快）

    const { result } = renderHook(() => useScan());
    const promiseA = result.current.getReport('a');
    const rB = await result.current.getReport('b');
    expect(rB!.scanId).toBe('b');
    resolveA({ scanId: 'a', engine: 'builtin' });
    const rA = await promiseA;
    expect(rA).toBeNull(); // A 已过期 → 丢弃
    expect(useScanStore.getState().report!.scanId).toBe('b');
  });
});

describe('useScan · exportReport', () => {
  it('HTTP 非 2xx 抛出带状态码的错误', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 500 }));
    const { result } = renderHook(() => useScan());
    await expect(result.current.exportReport('s1', 'json')).rejects.toThrow('HTTP 500');
    vi.unstubAllGlobals();
  });

  it('成功时按格式映射 MIME 并经 tauriBridge.saveFile 落盘', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, text: () => Promise.resolve('CSV,DATA') }));
    const { result } = renderHook(() => useScan());
    await result.current.exportReport('s1', 'csv');
    expect(tauriBridge.saveFile).toHaveBeenCalledWith('report_s1.csv', 'CSV,DATA', 'text/csv; charset=utf-8');
    vi.unstubAllGlobals();
  });
});

describe('wrapSqlmapReport 纯函数', () => {
  it('vulns 非空 → High；日志容错（非数组→空）；meta 目标回填', () => {
    const r = wrapSqlmapReport('m1', { status: 'completed', vulns: [{ id: 1 }] }, { targetUrl: 'http://t/' });
    expect(r.engine).toBe('sqlmap');
    expect(r.riskLevel).toBe('High');
    expect(r.target.baseUrl).toBe('http://t/');
    expect(r.sqlmap!.vulns).toHaveLength(1);

    const r2 = wrapSqlmapReport('m2', { logs: 'bad' as any });
    expect(r2.sqlmap!.logs).toEqual([]);
    expect(r2.riskLevel).toBe('Low');
  });
});
