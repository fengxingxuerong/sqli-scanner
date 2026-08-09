import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import ProgressView from '../components/ProgressView';
import { useScanStore } from '../store/scanStore';
import type { ScanEvent } from '../shared/types';

// 桩 useScan，聚焦任务卡的停止控制（不触发真实网络）
const stopScanMock = vi.fn();
vi.mock('../hooks/useScan', () => ({ useScan: () => ({ stopScan: stopScanMock }) }));

describe('ProgressView 扫描任务卡 + 停止控制', () => {
  beforeEach(() => {
    stopScanMock.mockClear();
    useScanStore.getState().reset();
  });

  it('running + 有 scanId/目标/引擎/并发 → 渲染任务卡且停止按钮可用，点击调用 stopScan(scanId)', () => {
    useScanStore.setState({
      status: 'running',
      scanId: 's1',
      targetUrl: 'http://target.t/',
      engine: 'builtin',
      scanConcurrency: 5,
      events: [{ type: 'point_discovered', ts: '1', payload: null } as ScanEvent],
    });
    render(<ProgressView />);
    expect(screen.getByText('扫描任务')).toBeTruthy();
    expect(screen.getByText('目标地址：')).toBeTruthy();
    expect(screen.getByText('http://target.t/')).toBeTruthy();
    expect(screen.getByText('引擎：自带引擎')).toBeTruthy();
    expect(screen.getByText('并发：5')).toBeTruthy();
    const stopBtn = screen.getByRole('button', { name: '停止扫描' }) as HTMLButtonElement;
    expect(stopBtn.disabled).toBe(false);
    fireEvent.click(stopBtn);
    expect(stopScanMock).toHaveBeenCalledTimes(1);
    expect(stopScanMock).toHaveBeenCalledWith('s1');
  });

  it('sqlmap 引擎 → 任务卡显示「sqlmap 高级」', () => {
    useScanStore.setState({ status: 'running', scanId: 's2', targetUrl: 'http://x/', engine: 'sqlmap', scanConcurrency: 2 });
    render(<ProgressView />);
    expect(screen.getByText('引擎：sqlmap 高级')).toBeTruthy();
  });

  it('非 running（completed）或无 scanId → 停止按钮禁用', () => {
    useScanStore.setState({ status: 'completed', scanId: null, targetUrl: null, engine: 'builtin', scanConcurrency: 1 });
    render(<ProgressView />);
    const stopBtn = screen.getByRole('button', { name: '停止扫描' }) as HTMLButtonElement;
    expect(stopBtn.disabled).toBe(true);
    expect(stopScanMock).not.toHaveBeenCalled();
  });
});
