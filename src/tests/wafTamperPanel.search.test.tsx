// WafTamperPanel 清单搜索 QA：按名称/说明过滤、命中计数、清空恢复。
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react';
import { useState } from 'react';
import type { TamperConfig } from '../shared/types';
import WafTamperPanel from '../components/WafTamperPanel';

vi.mock('../shared/apiClient', () => ({
  apiClient: {
    tampers: vi.fn().mockResolvedValue([
      { name: 'space2comment', description: '空格转内联注释' },
      { name: 'randomcase', description: '随机大小写' },
      { name: 'charencode', description: 'URL 编码' },
      { name: 'modsecurityversioned', description: 'ModSecurity 版本注释包裹' },
    ]),
  },
}));

const DEFAULT: TamperConfig = { enabled: false, plugins: [], intensity: 'medium' };

function Harness({ initial = DEFAULT }: { initial?: TamperConfig }) {
  const [value, setValue] = useState<TamperConfig>(initial);
  return <WafTamperPanel value={value} onChange={setValue} />;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('WafTamperPanel 清单搜索', () => {
  it('加载完成后默认显示总数（未过滤）', async () => {
    render(<Harness />);
    await screen.findByText(/4 项，来自后端 TamperRegistry/);
    // 4 个 tamper 复选项
    expect(within(screen.getByTestId('tamper-list')).getAllByRole('checkbox').length).toBe(4);
  });

  it('输入「random」→ 仅命中 randomcase，计数「命中 1 / 共 4 项（已过滤）」', async () => {
    render(<Harness />);
    const input = await screen.findByPlaceholderText('搜索名称 / 说明');
    fireEvent.change(input, { target: { value: 'random' } });
    await waitFor(() => expect(within(screen.getByTestId('tamper-list')).getAllByRole('checkbox').length).toBe(1));
    expect(screen.getByText(/命中 1 \/ 共 4 项（已过滤）/)).toBeTruthy();
    // 仅 randomcase（其说明含「随机大小写」也匹配 random）
    expect(within(screen.getByTestId('tamper-list')).getByRole('checkbox', { name: /randomcase/ })).toBeTruthy();
    expect(within(screen.getByTestId('tamper-list')).queryByRole('checkbox', { name: /space2comment/ })).toBeNull();
  });

  it('输入「注释」→ 按说明命中 space2comment 与 modsecurityversioned', async () => {
    render(<Harness />);
    const input = await screen.findByPlaceholderText('搜索名称 / 说明');
    fireEvent.change(input, { target: { value: '注释' } });
    await waitFor(() => expect(within(screen.getByTestId('tamper-list')).getAllByRole('checkbox').length).toBe(2));
    expect(screen.getByText(/命中 2 \/ 共 4 项（已过滤）/)).toBeTruthy();
  });

  it('清空搜索 → 恢复全部 4 项', async () => {
    render(<Harness />);
    const input = await screen.findByPlaceholderText('搜索名称 / 说明');
    fireEvent.change(input, { target: { value: 'random' } });
    await waitFor(() => expect(within(screen.getByTestId('tamper-list')).getAllByRole('checkbox').length).toBe(1));
    fireEvent.change(input, { target: { value: '' } });
    await waitFor(() => expect(within(screen.getByTestId('tamper-list')).getAllByRole('checkbox').length).toBe(4));
    expect(screen.getByText(/4 项，来自后端 TamperRegistry/)).toBeTruthy();
  });

  it('搜索后出现「清除搜索」按钮，点击 → 清空并恢复全部 4 项', async () => {
    render(<Harness />);
    const input = await screen.findByPlaceholderText('搜索名称 / 说明');
    fireEvent.change(input, { target: { value: 'random' } });
    await waitFor(() => expect(within(screen.getByTestId('tamper-list')).getAllByRole('checkbox').length).toBe(1));
    expect(screen.getByRole('button', { name: '清除搜索' })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: '清除搜索' }));
    await waitFor(() => expect(within(screen.getByTestId('tamper-list')).getAllByRole('checkbox').length).toBe(4));
    expect(screen.getByText(/4 项，来自后端 TamperRegistry/)).toBeTruthy();
    expect((screen.getByPlaceholderText('搜索名称 / 说明') as HTMLInputElement).value).toBe('');
  });

  it('搜索后聚焦输入框按 Esc → 清空并恢复全部 4 项', async () => {
    render(<Harness />);
    const input = await screen.findByPlaceholderText('搜索名称 / 说明');
    fireEvent.change(input, { target: { value: 'random' } });
    await waitFor(() => expect(within(screen.getByTestId('tamper-list')).getAllByRole('checkbox').length).toBe(1));
    fireEvent.keyDown(input, { key: 'Escape' });
    await waitFor(() => expect(within(screen.getByTestId('tamper-list')).getAllByRole('checkbox').length).toBe(4));
    expect((screen.getByPlaceholderText('搜索名称 / 说明') as HTMLInputElement).value).toBe('');
  });

  it('按「/」快捷键聚焦搜索框', async () => {
    render(<Harness />);
    const input = await screen.findByPlaceholderText('搜索名称 / 说明');
    expect(document.activeElement).not.toBe(input);
    fireEvent.keyDown(document, { key: '/' });
    expect(document.activeElement).toBe(input);
  });
});
