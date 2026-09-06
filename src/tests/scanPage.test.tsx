// ScanPage 扫描页补测（原覆盖 63.9%）：
//   ① 组装渲染 ScanWizard；无 scanId 时不渲染进度卡片
//   ② 运行中：进度卡片 + 状态 Chip + 百分比文案（H2 聚合值消费）
//   ③ 空 URL 点开始 → 「请填写目标 URL」错误护栏
//   ④ 已完成（有 report）：ScanResult 展示查看报告入口
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import ScanPage from '../pages/ScanPage';
import { useScanStore } from '../store/scanStore';
import { sqlmapClient } from '../shared/apiClient';

const { startScanMock, stopScanMock, pauseScanMock, resumeScanMock } = vi.hoisted(() => ({
  startScanMock: vi.fn(),
  stopScanMock: vi.fn(),
  pauseScanMock: vi.fn(),
  resumeScanMock: vi.fn(),
}));

vi.mock('../hooks/useScan', () => ({
  useScan: () => ({
    startScan: startScanMock,
    stopScan: stopScanMock,
    pauseScan: pauseScanMock,
    resumeScan: resumeScanMock,
  }),
}));

// useEvents 内部依赖 EventSource，扫描页级测试统一 mock 掉
vi.mock('../hooks/useEvents', () => ({ useEvents: vi.fn() }));

vi.mock('../shared/apiClient', () => ({
  API_BASE: 'http://test/api',
  ApiError: class extends Error {},
  apiClient: { get: vi.fn(), post: vi.fn(), tampers: vi.fn().mockResolvedValue([]) },
  exploitClient: { capabilities: vi.fn() },
  sqlmapClient: { status: vi.fn() },
}));

vi.mock('../shared/tauriBridge', () => ({
  tauriBridge: { startEngine: vi.fn(), stopEngine: vi.fn(), saveFile: vi.fn() },
}));

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/scan']}>
      <Routes>
        <Route path="/scan" element={<ScanPage />} />
        <Route path="/report/:id" element={<div>REPORT_PROBE</div>} />
      </Routes>
    </MemoryRouter>
  );
}

function resetStore(partial: Record<string, unknown> = {}) {
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
    ...partial,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  // 切 sqlmap 引擎时 ScanWizard 会做预检（status），避免 undefined.then 崩溃
  vi.mocked(sqlmapClient.status).mockResolvedValue({ available: true } as any);
  resetStore();
});

describe('ScanPage · 组装与进度', () => {
  it('渲染扫描向导；无 scanId 时不渲染进度卡片', () => {
    renderPage();
    expect(screen.getByText('SQL 注入检测')).toBeTruthy();
    expect(screen.queryByText('扫描进度')).toBeNull();
  });

  it('运行中：进度卡片 + 状态 Chip + 已处理百分比（H2 聚合值）', () => {
    resetStore({
      scanId: 's1',
      scanEngine: 'builtin',
      status: 'running',
      progressTotal: 4,
      processedPointIds: { p1: true, p2: true },
      processedCount: 2, // 与 processedPointIds 同步的增量计数（ScanPage 现订阅数字）
    });
    renderPage();
    // ProgressView 内也有「扫描进度」标题，断言至少渲染一处
    expect(screen.getAllByText('扫描进度').length).toBeGreaterThan(0);
    expect(screen.getAllByText('扫描中').length).toBeGreaterThan(0);
    expect(screen.getAllByText('已处理 2/4 个注入点（50%）').length).toBeGreaterThan(0);
  });

  it('空 URL 点开始：展示「请填写目标 URL」且不发起扫描', () => {
    renderPage();
    fireEvent.click(screen.getByRole('button', { name: '开始扫描' }));
    expect(screen.getByText('请填写目标 URL')).toBeTruthy();
    expect(startScanMock).not.toHaveBeenCalled();
  });

  it('有报告且扫描完成：ScanResult 提供查看报告入口', async () => {
    resetStore({
      scanId: 's1',
      scanEngine: 'builtin',
      status: 'completed',
      report: {
        scanId: 's1', engine: 'builtin', riskLevel: 'High',
        target: { baseUrl: 'http://t/' }, vulns: [], points: [], summary: {},
      } as any,
    });
    renderPage();
    await waitFor(() => expect(screen.getByText(/查看报告/)).toBeTruthy());
  });
});

describe('ScanPage · 拖库二次确认（builtin）', () => {
  it('默认开启拖库：点开始 → ConfirmExtract；取消不发起，确认后带 enableExtract 发起', async () => {
    startScanMock.mockResolvedValueOnce('s1');
    renderPage();
    // 填 URL（无需展开高级设置，enableExtract 默认 true）
    fireEvent.change(screen.getAllByPlaceholderText('http://example.com/item.php?id=1')[0], {
      target: { value: 'http://t/item.php?id=1' },
    });

    // 点开始 → 拖库二次确认对话框，未发起请求
    fireEvent.click(screen.getByRole('button', { name: '开始扫描' }));
    expect(screen.getByText('确认执行数据提取（拖库）？')).toBeTruthy();
    expect(startScanMock).not.toHaveBeenCalled();

    // 取消 → 对话框关闭，仍不发起
    fireEvent.click(screen.getByText('取消'));
    await waitFor(() => expect(screen.queryByText('确认执行数据提取（拖库）？')).toBeNull());
    expect(startScanMock).not.toHaveBeenCalled();

    // 再次开始 → 确认 → 发起
    fireEvent.click(screen.getByRole('button', { name: '开始扫描' }));
    fireEvent.click(screen.getByText('我已知晓，继续'));
    await waitFor(() => expect(startScanMock).toHaveBeenCalledTimes(1));
    const args = startScanMock.mock.calls[0][0];
    expect(args.url).toBe('http://t/item.php?id=1');
    expect(args.engine).toBe('builtin');
    expect(args.config.enableExtract).toBe(true);
  });

  it('显式关闭 enableExtract：直接发起，无二次确认对话框', async () => {
    startScanMock.mockResolvedValueOnce('s1');
    renderPage();
    // 展开两层高级设置并切换 enableExtract(false)
    fireEvent.click(screen.getAllByText('高级设置')[0]);
    fireEvent.click(screen.getAllByText('高级设置')[1]);
    fireEvent.click(screen.getByLabelText('启用数据提取（拖库）'));
    fireEvent.change(screen.getAllByPlaceholderText('http://example.com/item.php?id=1')[0], {
      target: { value: 'http://t/item.php?id=1' },
    });

    fireEvent.click(screen.getByRole('button', { name: '开始扫描' }));
    await waitFor(() => expect(startScanMock).toHaveBeenCalledTimes(1));
    expect(screen.queryByText('确认执行数据提取（拖库）？')).toBeNull();
    expect(startScanMock.mock.calls[0][0].config.enableExtract).toBe(false);
  });
});

describe('ScanPage · sqlmap 破坏性二次确认', () => {
  it('切 sqlmap 引擎勾选拖库 → ConfirmSqlmap；确认后携带 engine=sqlmap + dump 发起', async () => {
    startScanMock.mockResolvedValueOnce('m1');
    renderPage();
    fireEvent.click(screen.getAllByText('高级设置')[0]);
    fireEvent.click(screen.getByText('sqlmap 高级模式'));
    await waitFor(() => expect(screen.getByText('拖库 --dump')).toBeTruthy());
    fireEvent.click(screen.getByText('拖库 --dump'));
    fireEvent.change(screen.getAllByPlaceholderText('http://example.com/item.php?id=1')[0], {
      target: { value: 'http://t/item.php?id=1' },
    });

    fireEvent.click(screen.getByRole('button', { name: '开始扫描' }));
    expect(screen.getByText('确认执行 sqlmap 破坏性操作？')).toBeTruthy();
    expect(startScanMock).not.toHaveBeenCalled();

    fireEvent.click(screen.getByText('我已知晓，继续'));
    await waitFor(() => expect(startScanMock).toHaveBeenCalledTimes(1));
    const args = startScanMock.mock.calls[0][0];
    expect(args.engine).toBe('sqlmap');
    expect(args.sqlmapConfig.dump).toBe(true);
  });

  it('sqlmap 引擎 + 未勾选破坏性操作：直接发起，无二次确认对话框', async () => {
    startScanMock.mockResolvedValueOnce('m1');
    renderPage();
    fireEvent.click(screen.getAllByText('高级设置')[0]);
    fireEvent.click(screen.getByText('sqlmap 高级模式'));
    fireEvent.change(screen.getAllByPlaceholderText('http://example.com/item.php?id=1')[0], {
      target: { value: 'http://t/item.php?id=1' },
    });
    fireEvent.click(screen.getByRole('button', { name: '开始扫描' }));
    await waitFor(() => expect(startScanMock).toHaveBeenCalledTimes(1));
    expect(screen.queryByText('确认执行 sqlmap 破坏性操作？')).toBeNull();
    expect(startScanMock.mock.calls[0][0].sqlmapConfig.dump).toBe(false);
  });
});
