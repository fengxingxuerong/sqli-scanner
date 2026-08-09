import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ScanPage from '../pages/ScanPage';
import { useScanStore } from '../store/scanStore';

// 桩掉网络/异步副作用，聚焦 submitting 骨架屏逻辑
vi.mock('../hooks/useScan', () => ({
  useScan: () => ({ startScan: vi.fn(() => new Promise(() => {})), stopScan: vi.fn() }),
}));
vi.mock('../hooks/useEvents', () => ({ useEvents: () => {} }));
vi.mock('../shared/tauriBridge', () => ({
  tauriBridge: { startEngine: vi.fn(() => Promise.resolve()) },
}));
// 桩 WafTamperPanel 的 tamper 拉取，避免 jsdom XHR 噪声导致退出码非零
vi.mock('../shared/apiClient', () => ({
  apiClient: { tampers: vi.fn().mockResolvedValue([]) },
}));

beforeEach(() => useScanStore.getState().reset());

describe('ScanPage 提交中骨架屏', () => {
  it('初始（无提交）不显示骨架屏，开始扫描按钮可用', () => {
    render(
      <MemoryRouter>
        <ScanPage />
      </MemoryRouter>,
    );
    expect(document.querySelector('.MuiSkeleton-root')).toBeNull();
    expect((screen.getByRole('button', { name: /开始扫描/ }) as HTMLButtonElement).disabled).toBe(false);
  });

  it('点击开始扫描（startScan 挂起）显示骨架屏且按钮禁用', async () => {
    render(
      <MemoryRouter>
        <ScanPage />
      </MemoryRouter>,
    );
    const urlInput = screen.getByLabelText('目标 URL') as HTMLInputElement;
    fireEvent.change(urlInput, { target: { value: 'http://t/' } });
    // 切到 sqlmap 引擎：默认 dump/osShell/fileRead 均为关闭，不触发任何二次确认，直接 doStart
    fireEvent.click(screen.getByText('sqlmap 高级模式'));
    fireEvent.click(screen.getByRole('button', { name: /开始扫描/ }));
    // submitting 置位后骨架屏出现；startScan 始终挂起，骨架保持
    await waitFor(() => expect(document.querySelector('.MuiSkeleton-root')).toBeTruthy());
    const btn = screen.getByRole('button', { name: /启动中|开始扫描/ }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
  });
});

// 完成态报告入口：原仅 builtin 显示，现改为「有报告即显示」，覆盖 sqlmap（修复 sqlmap 扫完无入口的问题）
describe('ScanPage 扫描完成态报告入口（双引擎）', () => {
  const mkReport = (scanId: string, riskLevel: string, vulnCount: number) =>
    ({ scanId, riskLevel, vulns: Array.from({ length: vulnCount }, (_, i) => ({ id: `v${i}` })) } as any);

  it('sqlmap 完成且有报告 → 渲染「查看报告 →」与完成提示', () => {
    useScanStore.setState({ engine: 'sqlmap', status: 'completed', scanId: 's1', report: mkReport('s1', 'High', 2) });
    render(
      <MemoryRouter>
        <ScanPage />
      </MemoryRouter>,
    );
    expect(screen.getByRole('button', { name: /查看报告/ })).toBeTruthy();
    expect(screen.getByText(/扫描完成，风险等级/)).toBeTruthy();
  });

  it('builtin 完成且有报告 → 仍渲染「查看报告 →」（回归）', () => {
    useScanStore.setState({ engine: 'builtin', status: 'completed', scanId: 'b1', report: mkReport('b1', 'Low', 0) });
    render(
      <MemoryRouter>
        <ScanPage />
      </MemoryRouter>,
    );
    expect(screen.getByRole('button', { name: /查看报告/ })).toBeTruthy();
  });

  it('无报告（未完成 / 数据缺失）→ 不渲染「查看报告 →」', () => {
    useScanStore.setState({ engine: 'sqlmap', status: 'running', scanId: 's2', report: null });
    render(
      <MemoryRouter>
        <ScanPage />
      </MemoryRouter>,
    );
    expect(screen.queryByRole('button', { name: /查看报告/ })).toBeNull();
  });
});
