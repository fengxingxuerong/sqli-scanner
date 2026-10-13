// useServerHistory Hook 直接用例（D60-8.1）：
//   ① 成功：apiClient.scans resolve → rows 填充、loading=false、error=''
//   ② 失败：apiClient.scans reject(Error) → rows=[]、loading=false、error=message
//   ③ 失败（非 Error）：reject(string) → error=该字符串
//   ④ 卸载后不 setState：resolve 前卸载 → state 保持 loading=true
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { useServerHistory } from '../hooks/useServerHistory';
import { apiClient } from '../shared/apiClient';

vi.mock('../shared/apiClient', () => ({
  apiClient: { scans: vi.fn() },
}));

const mockedScans = vi.mocked(apiClient.scans);

describe('useServerHistory', () => {
  beforeEach(() => { vi.resetAllMocks(); });
  afterEach(() => { vi.restoreAllMocks(); });

  it('① 成功：scans resolve → rows 填充、loading=false、error=""', async () => {
    mockedScans.mockResolvedValue({
      total: 2,
      ledgerRoot: '/tmp/ledger',
      scans: [
        {
          scanId: 's1', target: 'http://t/', method: 'GET',
          startedAt: '2026-01-01', finishedAt: '2026-01-01',
          points: 3, vulns: 0, riskLevel: null, dbms: null, verdict: null,
          status: 'completed', source: 'ledger',
        },
        {
          scanId: 's2', target: 'http://t2/', method: 'GET',
          startedAt: '2026-01-02', finishedAt: null,
          points: 5, vulns: 1, riskLevel: 'High', dbms: 'MySQL', verdict: 'vulnerable',
          status: 'running', source: 'live',
        },
      ],
    });

    const { result } = renderHook(() => useServerHistory(50));

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.rows).toHaveLength(2);
    expect(result.current.rows[0].scanId).toBe('s1');
    expect(result.current.error).toBe('');
  });

  it('② 失败：scans reject(Error) → rows=[]、loading=false、error=message', async () => {
    mockedScans.mockRejectedValue(new Error('网络断了'));

    const { result } = renderHook(() => useServerHistory());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.rows).toHaveLength(0);
    expect(result.current.error).toBe('网络断了');
  });

  it('③ 失败（非 Error）：reject(string) → error=该字符串', async () => {
    mockedScans.mockRejectedValue('服务端 503');

    const { result } = renderHook(() => useServerHistory());

    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.rows).toHaveLength(0);
    expect(result.current.error).toBe('服务端 503');
  });

  it('④ 卸载后不 setState：resolve 前卸载 → state 保持 loading=true', async () => {
    let resolveFn: (v: any) => void = () => {};
    mockedScans.mockReturnValue(new Promise((r) => { resolveFn = r; }));

    const { result, unmount } = renderHook(() => useServerHistory());

    unmount();
    resolveFn({ scans: [{ scanId: 'late', status: 'completed', target: '', createdAt: '' }] });

    expect(result.current.loading).toBe(true);
    expect(result.current.rows).toHaveLength(0);
  });
});