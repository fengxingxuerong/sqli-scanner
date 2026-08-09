import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { useScanStore } from '../store/scanStore';
import ScanPage from '../pages/ScanPage';
import ReportPage from '../pages/ReportPage';

// ScanPage → ScanConfigPanel → WafTamperPanel 挂载即请求 /api/tampers，统一 mock
vi.mock('../shared/apiClient', () => ({
  apiClient: {
    tampers: vi.fn().mockResolvedValue([
      { name: 'space2comment', description: '空格转内联注释' },
      { name: 'randomcase', description: '随机大小写' },
      { name: 'charencode', description: 'URL 编码' },
    ]),
  },
}));

beforeEach(() => {
  useScanStore.getState().reset();
  vi.clearAllMocks();
});

describe('F-20 WAF 建议 QA（端到端）', () => {
  it('waf_detected → 扫描页出现建议条，一键应用只写 plugins（enabled 仍 false）', async () => {
    render(
      <MemoryRouter>
        <ScanPage />
      </MemoryRouter>
    );

    // 模拟后端经 SSE 推送 waf_detected 事件（useEvents 会写入 store.wafSuggestion）
    useScanStore.getState().setWafSuggestion({
      vendors: [{ vendor: 'Cloudflare', confidence: 0.85, evidence: 'header: cf-ray' }],
      suggestions: [
        { vendor: 'Cloudflare', plugins: ['space2comment', 'randomcase', 'charencode'] },
      ],
    });

    // 建议条出现，且含检测到的 WAF 名
    const banner = await screen.findByText(/识别到 WAF/);
    expect(banner.textContent).toContain('Cloudflare');

    // 点击「一键应用推荐」→ 只写入 plugins，enabled 仍由用户开启
    fireEvent.click(screen.getByText('一键应用推荐'));

    // WafTamperPanel 出现对应有序 chips
    await screen.findByText('1. space2comment');
    await screen.findByText('3. charencode');

    // 总开关仍关闭（仅推荐不自动套用）
    const sw = screen.getByLabelText(/启用 tamper 变换/) as HTMLInputElement;
    expect(sw.checked).toBe(false);
  });

  it('报告页：tamper 启用时摘要渲染组合', async () => {
    useScanStore.getState().setReport({
      scanId: 's1',
      target: { id: 't1', baseUrl: 'http://x', method: 'GET', bodyParams: {}, cookieParams: {}, headerParams: {}, config: {} },
      startedAt: '',
      finishedAt: '',
      dbms: null,
      points: [],
      vulns: [],
      data: null,
      riskLevel: 'Low',
      summary: {
        wafEvasion: {
          tamper: { enabled: true, plugins: ['space2comment', 'randomcase'], intensity: 'medium' },
        },
      },
    } as any);

    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>
    );

    const alert = await screen.findByText(/tamper 组合/);
    expect(alert.textContent).toContain('space2comment → randomcase');
  });

  it('报告页：tamper 关闭时不渲染组合', () => {
    useScanStore.getState().setReport({
      scanId: 's1',
      target: { id: 't1', baseUrl: 'http://x', method: 'GET', bodyParams: {}, cookieParams: {}, headerParams: {}, config: {} },
      startedAt: '',
      finishedAt: '',
      dbms: null,
      points: [],
      vulns: [],
      data: null,
      riskLevel: 'Low',
      summary: {},
    } as any);

    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>
    );

    expect(screen.queryByText(/tamper 组合/)).toBeNull();
  });

  it('second_order_discovery → 扫描页出现实时发现横幅（候选数/确认触发页列表）与实时全局拓扑图', () => {
    // 模拟后端经 SSE 推送：point_discovered（全量注入点）+ scan_started（目标 URL）+ second_order_discovery
    useScanStore.getState().setTargetUrl('http://t');
    useScanStore.getState().setDiscoveredPoints([
      { id: '1', location: 'body', param: 'username', originalValue: '1', confirmed: false, technique: null, dbms: null, isStorePoint: true, storeKind: 'registration' },
      { id: '2', location: 'url', param: 'id', originalValue: '1', confirmed: false, technique: null, dbms: null },
    ]);
    useScanStore.getState().setSecondOrderDiscovery({
      candidates: ['http://t/a', 'http://t/b'],
      confirmed: ['http://t/a'],
      storePoints: [{ param: 'username', storeKind: 'registration' }],
    });

    render(
      <MemoryRouter>
        <ScanPage />
      </MemoryRouter>
    );

    // 横幅：用 within 限定，避免与图中节点文本（同样含 URL）冲突
    const banner = screen.getByText(/二阶自动发现/).closest('.MuiAlert-root') as HTMLElement;
    expect(banner.textContent).toContain('从 2 个候选链接中确认 1 个');
    // 仅确认页被列出（横幅内）
    const withinBanner = within(banner);
    expect(withinBanner.getByText('http://t/a')).toBeTruthy();
    expect(withinBanner.queryByText('http://t/b')).toBeNull();

    // 实时全局拓扑图：图例含「存储点」；已确认触发页节点「二阶确认触发页」；节点渲染 URL（与横幅共存）
    expect(screen.getByText('存储点')).toBeTruthy();
    expect(screen.getByText('二阶确认触发页')).toBeTruthy();
    expect(screen.getAllByText('http://t/a').length).toBeGreaterThan(0);
  });

  it('无 second_order_discovery 时不渲染实时发现横幅', () => {
    useScanStore.getState().setSecondOrderDiscovery(null);
    render(
      <MemoryRouter>
        <ScanPage />
      </MemoryRouter>
    );
    expect(screen.queryByText(/二阶自动发现/)).toBeNull();
  });
});
