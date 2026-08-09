import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ReportPage from '../pages/ReportPage';
import { useScanStore } from '../store/scanStore';
import type { ReportModel, SafeProbeAlert } from '../shared/types';

// ReportPage 通过 useScan().getReport 拉报告；测试里注入 store.report 即可，
// 因此把 getReport mock 成 noop，避免 useEffect 副作用。
vi.mock('../hooks/useScan', () => ({
  useScan: () => ({ getReport: vi.fn() }),
}));

// 拓扑图导出依赖 canvas/SVG 序列化，jsdom 不支持，统一 mock 为返回假 dataUrl
vi.mock('html-to-image', () => ({
  toPng: vi.fn().mockResolvedValue('data:image/png;base64,iVBORw0KGgo='),
  toSvg: vi.fn().mockResolvedValue('data:image/svg+xml;base64,PHN2Zz4='),
}));

// 部分字段用 any 中转，避免测试里造完整 ReportModel 的样板噪声
function baseReport(over: Partial<ReportModel> = {}): ReportModel {
  const r: any = {
    scanId: 's1',
    target: { baseUrl: 'http://t/' },
    startedAt: '',
    finishedAt: '',
    dbms: null,
    points: [],
    vulns: [],
    data: null,
    riskLevel: 'Low',
    summary: {},
    ...over,
  };
  return r as ReportModel;
}

const alert1: SafeProbeAlert = {
  url: 'http://safe1/',
  reason: '安全 URL 状态码偏离：基线 200 → 实际 403',
  baselineStatus: 200,
  baselineLen: 100,
  actualStatus: 403,
  actualLen: 12,
  ts: '2026-08-05T00:00:00Z',
};
const alert2: SafeProbeAlert = {
  url: 'http://safe2/',
  reason: '安全 URL 响应体长度偏离基线：120 → 500',
  baselineStatus: 200,
  baselineLen: 120,
  actualStatus: 200,
  actualLen: 500,
  ts: '2026-08-05T00:01:00Z',
};

beforeEach(() => useScanStore.getState().reset());

describe('ReportPage 安全间隔探测告警（可折叠 Accordion）', () => {
  it('无报告时显示骨架屏占位（非纯文字）', () => {
    useScanStore.setState({ report: null });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    // 骨架屏：标题 + 卡片 + 图区多个占位块
    expect(document.querySelector('.MuiSkeleton-root')).toBeTruthy();
    expect(screen.queryByText(/加载中或报告不存在/)).toBeNull();
  });

  it('无 safeProbeAlerts 时不渲染告警区块', () => {
    useScanStore.setState({ report: baseReport({ summary: {} }) });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    expect(screen.queryByText(/安全间隔探测告警/)).toBeNull();
  });

  it('有告警时折叠态显示标题与条数 Chip（不展开也能看到概要）', () => {
    useScanStore.setState({
      report: baseReport({ summary: { safeProbeAlerts: [alert1, alert2] } }),
    });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    expect(screen.getByText('安全间隔探测告警')).toBeTruthy();
    expect(screen.getByText('2 条')).toBeTruthy();
  });

  it('点击展开后显示每条明细（URL/原因/基线→实际）与失真提示', () => {
    useScanStore.setState({
      report: baseReport({ summary: { safeProbeAlerts: [alert1, alert2] } }),
    });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByText('安全间隔探测告警'));
    expect(screen.getByText('http://safe1/')).toBeTruthy();
    expect(screen.getByText('http://safe2/')).toBeTruthy();
    expect(screen.getByText(/基线 200（100B）→ 实际 403（12B）/)).toBeTruthy();
    expect(screen.getByText(/基线 200（120B）→ 实际 200（500B）/)).toBeTruthy();
    expect(screen.getByText(/当前批次检测结果可能失真/)).toBeTruthy();
  });

  it('单条告警也正常渲染条数 Chip', () => {
    useScanStore.setState({
      report: baseReport({ summary: { safeProbeAlerts: [alert1] } }),
    });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    expect(screen.getByText('安全间隔探测告警')).toBeTruthy();
    expect(screen.getByText('1 条')).toBeTruthy();
  });

  it('报告存在时显示「打印报告」按钮（与导出 HTML 打印能力对齐）', () => {
    useScanStore.setState({ report: baseReport({ summary: {} }) });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    const btn = screen.getByText('打印报告');
    expect(btn).toBeTruthy();
    // 点击触发 window.print（jsdom 下为 noop，断言不抛即可）
    expect(() => fireEvent.click(btn)).not.toThrow();
  });

  it('报告存在时渲染目录锚点侧栏（与导出 HTML TOC 对齐）', () => {
    useScanStore.setState({ report: baseReport({ summary: {} }) });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    // TOC 标题与四个锚点链接
    expect(screen.getByText('目录')).toBeTruthy();
    const anchors = Array.from(document.querySelectorAll('a[href^="#sec-"]'));
    expect(anchors.length).toBe(4);
    // 锚点目标：四个区块 Paper 的 id 均存在
    expect(document.getElementById('sec-vulns')).toBeTruthy();
    expect(document.getElementById('sec-detail')).toBeTruthy();
    expect(document.getElementById('sec-data')).toBeTruthy();
    expect(document.getElementById('sec-export')).toBeTruthy();
  });

  it('summary.secondOrderDiscovery 存在 → 展示候选数与确认的触发页列表', () => {
    useScanStore.setState({
      report: baseReport({
        summary: {
          secondOrderDiscovery: { candidates: ['http://t/a', 'http://t/b'], confirmed: ['http://t/a'] },
        },
      }),
    });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    expect(screen.getByText('二阶自动发现')).toBeTruthy();
    expect(screen.getByText(/从 2 个候选链接中确认 1 个/)).toBeTruthy();
    // 图渲染确认触发页节点（URL 在节点中至少出现 1 次；React Flow 无障碍描述可能重复，故用 getAllByText）
    expect(screen.getAllByText('http://t/a').length).toBeGreaterThanOrEqual(1);
    // 图同时渲染候选触发页节点（候选不再隐藏，旧 ul 列表只列确认已改为图展示两者）
    expect(screen.getAllByText('http://t/b').length).toBeGreaterThanOrEqual(1);
  });

  it('report.points 含存储点 → 展示存储点计数与类型分布', () => {
    const points: any[] = [
      { id: 'p1', location: 'body', param: 'username', originalValue: '1', confirmed: false, technique: null, dbms: null, isStorePoint: true, storeKind: 'registration' },
      { id: 'p2', location: 'body', param: 'comment', originalValue: '', confirmed: false, technique: null, dbms: null, isStorePoint: true, storeKind: 'comment' },
      { id: 'p3', location: 'url', param: 'q', originalValue: '1', confirmed: false, technique: null, dbms: null },
    ];
    useScanStore.setState({ report: baseReport({ points }) });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    expect(screen.getByText('二阶自动发现')).toBeTruthy();
    expect(screen.getByText(/已识别存储点 2 个/)).toBeTruthy();
    expect(screen.getByText(/registration:1/)).toBeTruthy();
    expect(screen.getByText(/comment:1/)).toBeTruthy();
  });

  it('无 discovery 且无存储点 → 不渲染二阶自动发现区块', () => {
    useScanStore.setState({ report: baseReport({ summary: {}, points: [] }) });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    expect(screen.queryByText('二阶自动发现')).toBeNull();
  });
});

describe('ReportPage 顶部拓扑图导出入口', () => {
  const points: any[] = [
    { id: 'p1', location: 'url', param: 'id', originalValue: '1', confirmed: false, technique: null, dbms: null, isStorePoint: false },
  ];

  it('有注入点、无二阶数据：注入拓扑图按钮可用、二阶按钮禁用', () => {
    useScanStore.setState({ report: baseReport({ points, summary: {} }) });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    expect((screen.getByRole('button', { name: /导出注入拓扑图/ }) as HTMLButtonElement).disabled).toBe(false);
    expect((screen.getByRole('button', { name: /导出二阶链路/ }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('点击「导出注入拓扑图」触发子组件 exportImage → toPng', async () => {
    useScanStore.setState({ report: baseReport({ points, summary: {} }) });
    const { toPng } = await import('html-to-image');
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole('button', { name: /导出注入拓扑图/ }));
    await new Promise((r) => setTimeout(r, 0));
    expect(toPng).toHaveBeenCalledTimes(1);
  });

  it('无注入点时「导出注入拓扑图」按钮禁用', () => {
    useScanStore.setState({ report: baseReport({ points: [], summary: {} }) });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    expect((screen.getByRole('button', { name: /导出注入拓扑图/ }) as HTMLButtonElement).disabled).toBe(true);
  });
});
