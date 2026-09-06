import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import ProgressView from '../components/ProgressView';
import { useScanStore } from '../store/scanStore';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('ProgressView 组件', () => {
  it('无事件时显示占位提示', () => {
    useScanStore.getState().reset();
    render(<ProgressView />);
    expect(screen.getByText('暂无事件，开始扫描后这里会实时显示进度')).toBeTruthy();
  });

  it('渲染从 store 读取的事件流', () => {
    useScanStore.getState().reset();
    useScanStore.getState().addEvent({ type: 'detect', ts: '12:00', payload: 'vuln found' });
    render(<ProgressView />);
    expect(screen.getByText(/vuln found/)).toBeTruthy();
  });

  it('scan_started 事件：渲染事件类型标签与序列化载荷', () => {
    useScanStore.getState().reset();
    useScanStore.getState().addEvent({
      type: 'scan_started', scanId: 's1', ts: '2026-01-01T00:00:00Z',
      payload: { target: 'http://example.com/item.php?id=1' },
    });
    render(<ProgressView />);
    expect(screen.getByText('scan_started')).toBeTruthy();
    expect(screen.getByText(/target/)).toBeTruthy();
    expect(screen.getByText(/example\.com/)).toBeTruthy();
    expect(screen.getByText('1 条事件')).toBeTruthy();
  });

  it('进度计算：point_discovered 累计 total，point_testing/detection_found 累计 processed', () => {
    useScanStore.getState().reset();
    useScanStore.getState().addEvent({ type: 'point_discovered', scanId: 's1', ts: 't1', payload: { points: [{}, {}, {}, {}] } });
    useScanStore.getState().addEvent({ type: 'point_testing', scanId: 's1', ts: 't2', payload: { pointId: 'p1' } });
    useScanStore.getState().addEvent({ type: 'point_testing', scanId: 's1', ts: 't3', payload: { pointId: 'p2' } });
    useScanStore.getState().addEvent({ type: 'detection_found', scanId: 's1', ts: 't4', payload: { pointId: 'p3' } });
    useScanStore.getState().setStatus('running');
    render(<ProgressView />);
    // total=4, processed=3 → 75%
    expect(screen.getByText('已处理 3/4 个注入点（75%）')).toBeTruthy();
  });

  it('复制日志按钮：把事件格式化为 [type] ts payload 写入剪贴板', async () => {
    useScanStore.getState().reset();
    useScanStore.getState().addEvent({ type: 'scan_started', scanId: 's1', ts: '2026-01-01T00:00:00Z', payload: { target: 'http://x' } });
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });

    render(<ProgressView />);
    fireEvent.click(screen.getByRole('button', { name: '复制日志' }));

    await vi.waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    const text = writeText.mock.calls[0][0] as string;
    expect(text).toBe('[scan_started] 2026-01-01T00:00:00Z {"target":"http://x"}');
  });

  it('展示当前状态标签', () => {
    useScanStore.getState().reset();
    useScanStore.getState().setStatus('running');
    render(<ProgressView />);
    expect(screen.getByText('扫描中')).toBeTruthy();
    useScanStore.getState().reset();
  });
});