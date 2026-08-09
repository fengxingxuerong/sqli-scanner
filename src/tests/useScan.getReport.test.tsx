import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import { useScan } from '../hooks/useScan';
import { useScanStore } from '../store/scanStore';

// 仅桩 apiClient：聚焦 getReport 的引擎分支 URL 选择
vi.mock('../shared/apiClient', () => ({
  apiClient: { get: vi.fn(), post: vi.fn(), tampers: vi.fn() },
  API_BASE: 'http://test',
}));
import { apiClient } from '../shared/apiClient';

const fakeReport = { scanId: 's1' } as any;

// 在 React 内捕获 getReport（zustand hook 不能在组件外直接调用）
let captured: ((id: string) => Promise<unknown>) | null = null;
function Probe() {
  const { getReport } = useScan();
  captured = getReport;
  return null;
}

beforeEach(() => {
  vi.clearAllMocks();
  captured = null;
  useScanStore.getState().reset();
});

describe('useScan.getReport 引擎分支', () => {
  it('builtin → GET /scan/:id/report', async () => {
    useScanStore.setState({ engine: 'builtin' });
    (apiClient.get as ReturnType<typeof vi.fn>).mockResolvedValue(fakeReport);
    render(<Probe />);
    const r = await captured!('s1');
    expect(apiClient.get).toHaveBeenCalledWith('/scan/s1/report');
    expect(r).toBe(fakeReport);
  });

  it('sqlmap → GET /sqlmap/:id/report', async () => {
    useScanStore.setState({ engine: 'sqlmap' });
    (apiClient.get as ReturnType<typeof vi.fn>).mockResolvedValue(fakeReport);
    render(<Probe />);
    const r = await captured!('s1');
    expect(apiClient.get).toHaveBeenCalledWith('/sqlmap/s1/report');
    expect(r).toBe(fakeReport);
  });

  it('请求失败 → 返回 null 且不抛出', async () => {
    useScanStore.setState({ engine: 'builtin' });
    (apiClient.get as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('net'));
    render(<Probe />);
    const r = await captured!('s1');
    expect(r).toBeNull();
  });
});
