// S8 事件流日志复制 / 下载：
//  - 复制日志：把所有事件格式化为 [type] ts payload 写入剪贴板
//  - 下载日志：生成 .log 文本经 tauriBridge.saveFile 落盘（Web 版降级 blob 下载）
//  - 无事件时两按钮禁用
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import ProgressView from '../components/ProgressView';
import { useScanStore } from '../store/scanStore';

// mock tauriBridge：断言下载日志的落盘调用（文件名 / 内容 / MIME）
vi.mock('../shared/tauriBridge', () => ({
  tauriBridge: { saveFile: vi.fn().mockResolvedValue(undefined), isTauri: false },
}));
import { tauriBridge } from '../shared/tauriBridge';

const EVENTS = [
  { type: 'point_testing', scanId: 's1', ts: '2026-01-01T00:00:00Z', payload: { pointId: 'p1' } },
  { type: 'sqlmap_log', scanId: 's1', ts: '2026-01-01T00:00:01Z', payload: { level: 'info', text: 'target url: http://x' } },
  { type: 'detection_found', scanId: 's1', ts: '2026-01-01T00:00:02Z', payload: 'plain payload' },
];

beforeEach(() => {
  vi.mocked(tauriBridge.saveFile).mockClear();
  useScanStore.getState().reset();
  useScanStore.setState({ scanId: 's1' });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('S8 ProgressView 日志复制/下载', () => {
  it('无事件时「复制日志 / 下载日志」均禁用', () => {
    render(<ProgressView />);
    const copyBtn = screen.getByRole('button', { name: '复制日志' }) as HTMLButtonElement;
    const dlBtn = screen.getByRole('button', { name: '下载日志' }) as HTMLButtonElement;
    expect(copyBtn.disabled).toBe(true);
    expect(dlBtn.disabled).toBe(true);
  });

  it('复制日志：把所有事件格式化为 [type] ts payload 写入剪贴板', async () => {
    for (const e of EVENTS) useScanStore.getState().addEvent(e as any);
    const writeText = vi.fn().mockResolvedValue(undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });

    render(<ProgressView />);
    fireEvent.click(screen.getByRole('button', { name: '复制日志' }));

    await vi.waitFor(() => expect(writeText).toHaveBeenCalledTimes(1));
    const text = writeText.mock.calls[0][0] as string;
    const lines = text.split('\n');
    expect(lines).toHaveLength(3);
    // 逐行断言 [type] ts payload 格式
    expect(lines[0]).toBe('[point_testing] 2026-01-01T00:00:00Z {"pointId":"p1"}');
    expect(lines[1]).toContain('[sqlmap_log] 2026-01-01T00:00:01Z');
    expect(lines[1]).toContain('"text":"target url: http://x"');
    expect(lines[2]).toBe('[detection_found] 2026-01-01T00:00:02Z plain payload');
  });

  it('下载日志：生成 .log 文本文件经 saveFile 落盘', async () => {
    for (const e of EVENTS) useScanStore.getState().addEvent(e as any);

    render(<ProgressView />);
    fireEvent.click(screen.getByRole('button', { name: '下载日志' }));

    await vi.waitFor(() => expect(tauriBridge.saveFile).toHaveBeenCalledTimes(1));
    const [name, content, mime] = vi.mocked(tauriBridge.saveFile).mock.calls[0];
    expect(name).toBe('scan_logs_s1.log');
    expect(mime).toBe('text/plain; charset=utf-8');
    const text = String(content);
    expect(text.split('\n')).toHaveLength(3);
    expect(text).toContain('[point_testing]');
    expect(text).toContain('[sqlmap_log]');
    expect(text).toContain('plain payload');
  });
});
