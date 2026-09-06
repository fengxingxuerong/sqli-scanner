// ReportExport 导出组件补测（原覆盖 69%）：
//   ① 无 scanId：导出按钮禁用 + 无拖库数据提示
//   ② 有 scanId：整份报告导出路由 + 拖库 CSV 走 tauriBridge.saveFile
//   ③ 导出失败：P1-6 用户可见错误 Alert
//   ④ AI 报告：成功渲染内容与模型 / success=false 与异常 → aiFailed
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import ReportExport from '../components/ReportExport';
import { useScanStore } from '../store/scanStore';
import { tauriBridge } from '../shared/tauriBridge';
import { apiClient } from '../shared/apiClient';

const { exportReportMock } = vi.hoisted(() => ({ exportReportMock: vi.fn() }));

vi.mock('../hooks/useScan', () => ({
  useScan: () => ({ exportReport: exportReportMock }),
}));

vi.mock('../shared/tauriBridge', () => ({
  tauriBridge: { saveFile: vi.fn() },
}));

vi.mock('../shared/apiClient', () => ({
  API_BASE: 'http://test/api',
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
    report: { ai: vi.fn() },
  },
}));

beforeEach(() => {
  vi.clearAllMocks();
  useScanStore.setState({ scanId: null, report: null, events: [] });
  // 静音 console.error（P1-6 失败路径会打日志）
  vi.spyOn(console, 'error').mockImplementation(() => undefined);
});

describe('ReportExport · 无 scanId', () => {
  it('整份导出与 db-json 按钮禁用；无拖库数据时拖库导出禁用并提示', () => {
    render(<ReportExport />);
    for (const label of ['JSON', 'HTML', 'CSV', 'Markdown']) {
      expect((screen.getByRole('button', { name: label }) as HTMLButtonElement).disabled).toBe(true);
    }
    expect((screen.getByRole('button', { name: '拖库 CSV' }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('本次扫描未提取到拖库数据，不可导出')).toBeTruthy();
  });
});

describe('ReportExport · 有 scanId', () => {
  beforeEach(() => {
    useScanStore.setState({ scanId: 's1' });
  });

  it('点击 JSON 走 exportReport(scanId, json)', () => {
    exportReportMock.mockResolvedValueOnce(undefined);
    render(<ReportExport />);
    fireEvent.click(screen.getByRole('button', { name: 'JSON' }));
    expect(exportReportMock).toHaveBeenCalledWith('s1', 'json');
  });

  it('导出失败渲染用户可见错误（P1-6）', async () => {
    exportReportMock.mockRejectedValueOnce(new Error('HTTP 500'));
    render(<ReportExport />);
    fireEvent.click(screen.getByRole('button', { name: 'CSV' }));
    await waitFor(() => expect(screen.getByText('导出报告失败：HTTP 500')).toBeTruthy());
  });

  it('有拖库数据：拖库 CSV 纯客户端生成并经 tauriBridge.saveFile 落盘', () => {
    useScanStore.setState({
      report: {
        scanId: 's1',
        data: { databases: [{ name: 'db1' }], tables: { db1: ['users'] }, rows: { 'db1.users': [['a']] } },
      } as any,
    });
    vi.mocked(tauriBridge.saveFile).mockResolvedValueOnce(undefined);
    render(<ReportExport />);
    expect(screen.queryByText('本次扫描未提取到拖库数据，不可导出')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: '拖库 CSV' }));
    expect(tauriBridge.saveFile).toHaveBeenCalledWith(
      'dump_s1.dump.csv',
      expect.stringContaining('db1'),
      'text/csv; charset=utf-8'
    );
  });
});

describe('ReportExport · AI 报告', () => {
  beforeEach(() => {
    useScanStore.setState({ scanId: 's1' });
  });

  it('生成成功：渲染内容与模型标签', async () => {
    vi.mocked(apiClient.report.ai).mockResolvedValueOnce({
      success: true, model: 'gpt-test', content: 'AI 分析结论',
    } as any);
    render(<ReportExport />);
    fireEvent.click(screen.getByRole('button', { name: 'AI 分析' }));
    await waitFor(() => expect(screen.getByText('AI 分析结论')).toBeTruthy());
    expect(screen.getByText('AI 模型: gpt-test')).toBeTruthy();
  });

  it('success=false 与请求异常均展示 aiFailed / 原始错误', async () => {
    vi.mocked(apiClient.report.ai).mockResolvedValueOnce({ success: false } as any);
    render(<ReportExport />);
    fireEvent.click(screen.getByRole('button', { name: 'AI 分析' }));
    await waitFor(() => expect(screen.getByText('AI 报告生成失败')).toBeTruthy());

    vi.mocked(apiClient.report.ai).mockRejectedValueOnce(new Error('quota exceeded'));
    fireEvent.click(screen.getByRole('button', { name: 'AI 分析' }));
    await waitFor(() => expect(screen.getByText('quota exceeded')).toBeTruthy());
  });
});
