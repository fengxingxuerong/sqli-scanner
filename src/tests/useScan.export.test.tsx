// ============================================================================
// useScan.export.test.tsx —— 报告另存盘的真行为（token / 错误体 / 产物判别式）
//
// 为什么值得单独测（2026-09-25，输出层审计执行复现）：
//   `exportReport` 是 src/ 里**唯一一处绕开 apiClient 的 fetch**（它要拿原始响应体做另存盘）。
//   代价是历史上它既不带鉴权头、也不看响应是不是产物：
//     · 服务端设了 SCAN_API_TOKEN ⇒ 所有导出必 401（实测：裸 fetch 401 / 带 x-api-token 200）
//     · 扫描已被回收 ⇒ 后端旧行为返回 **200 + JSON 错误信封**，而这里只判 `res.ok`
//       就把 `{"code":2001,...}` 存成 report_xxx.csv —— 用户看到"报告打不开"，真因是扫描没了
//   后端已改成 404（见 server/tests/api.exportNotFound.test.js），这里钉前端这一侧：
//   **任何"没带文件名头"的响应都不许落到盘上**。少一条断言，这个洞就会以另一种形态回来。
// ============================================================================
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook } from '@testing-library/react';
import { useScan } from '../hooks/useScan';
import { getApiToken } from '../shared/apiClient';
import { tauriBridge } from '../shared/tauriBridge';

vi.mock('../shared/apiClient', () => ({
  API_BASE: 'http://test/api',
  apiClient: { get: vi.fn(), post: vi.fn() },
  ApiError: class ApiError extends Error {},
  getApiToken: vi.fn(() => 'tok123'),
}));
vi.mock('../shared/tauriBridge', () => ({
  tauriBridge: { saveFile: vi.fn().mockResolvedValue(undefined), isTauri: false },
}));

const CSV = 'url,param,technique\nhttp://t/?id=1,id,union\n';
const fetchMock = vi.fn();

const resp = (init: { status?: number; headers?: Record<string, string>; body?: string }) => ({
  ok: (init.status ?? 200) >= 200 && (init.status ?? 200) < 300,
  status: init.status ?? 200,
  headers: new Headers(init.headers || {}),
  text: async () => init.body ?? '',
}) as unknown as Response;

describe('useScan.exportReport', () => {
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    vi.mocked(tauriBridge.saveFile).mockClear();
  });
  afterEach(() => vi.unstubAllGlobals());

  it('带 x-api-token 请求，并把响应体按格式存盘', async () => {
    fetchMock.mockResolvedValue(
      resp({ headers: { 'content-disposition': 'attachment; filename="report_s1.csv"', 'content-type': 'text/csv' }, body: CSV })
    );
    const { result } = renderHook(() => useScan());
    await result.current.exportReport('s1', 'csv');

    const [url, init] = fetchMock.mock.calls[0];
    expect(String(url)).toBe('http://test/api/scan/s1/report/export?format=csv');
    expect((init as RequestInit).headers).toMatchObject({ 'x-api-token': 'tok123' });
    expect(vi.mocked(getApiToken)).toHaveBeenCalled();
    expect(tauriBridge.saveFile).toHaveBeenCalledWith('report_s1.csv', CSV, expect.any(String));
  });

  it('401 时抛出，不写盘', async () => {
    fetchMock.mockResolvedValue(resp({ status: 401 }));
    const { result } = renderHook(() => useScan());
    await expect(result.current.exportReport('s1', 'csv')).rejects.toThrow(/401/);
    expect(tauriBridge.saveFile).not.toHaveBeenCalled();
  });

  it('200 但不带文件名头 = 错误信封：抛错并带上服务端原因，绝不存盘', async () => {
    fetchMock.mockResolvedValue(
      resp({ status: 200, headers: { 'content-type': 'application/json' }, body: '{"code":2001,"message":"扫描不存在或已结束"}' })
    );
    const { result } = renderHook(() => useScan());
    await expect(result.current.exportReport('gone', 'csv')).rejects.toThrow(/扫描不存在或已结束/);
    expect(tauriBridge.saveFile).not.toHaveBeenCalled();
  });

  it('未设 token 时不发空头（本机默认形态不被污染）', async () => {
    vi.mocked(getApiToken).mockReturnValueOnce('');
    fetchMock.mockResolvedValue(
      resp({ headers: { 'content-disposition': 'attachment; filename="report_s1.json"' }, body: '{}' })
    );
    const { result } = renderHook(() => useScan());
    await result.current.exportReport('s1', 'json');
    const [, init] = fetchMock.mock.calls[0];
    // 断言的是不变式"不许发出空的鉴权头"（服务端严格比对时会把 '' 当成错误凭据），
    // 不是 init.headers 的偶然形状（无 token 时它是 {}，写死 undefined 会测到实现细节）
    const headers = ((init as RequestInit).headers || {}) as Record<string, string>;
    expect(headers['x-api-token']).toBeUndefined();
  });
});
