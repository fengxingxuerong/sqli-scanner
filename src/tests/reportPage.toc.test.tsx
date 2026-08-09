import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, act } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import ReportPage from '../pages/ReportPage';
import { useScanStore } from '../store/scanStore';
import type { ReportModel } from '../shared/types';

// 复用报告页既有 mock 约定：getReport 为 noop，拓扑导出依赖的 html-to-image 桩成假 dataUrl
vi.mock('../hooks/useScan', () => ({ useScan: () => ({ getReport: vi.fn() }) }));
vi.mock('html-to-image', () => ({
  toPng: vi.fn().mockResolvedValue('data:image/png;base64,iVBORw0KGgo='),
  toSvg: vi.fn().mockResolvedValue('data:image/svg+xml;base64,PHN2Zz4='),
}));

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

// 记录挂载的 IntersectionObserver 实例，便于测试触发回调
class MockIntersectionObserver {
  static lastInstance: MockIntersectionObserver | null = null;
  cb: IntersectionObserverCallback;
  observed: Element[] = [];
  constructor(cb: IntersectionObserverCallback) {
    this.cb = cb;
    MockIntersectionObserver.lastInstance = this;
  }
  observe(el: Element) {
    this.observed.push(el);
  }
  unobserve() {}
  disconnect() {}
  // 测试辅助：模拟某区块进入视口
  trigger(id: string) {
    const el = this.observed.find((e) => e.id === id);
    if (!el) return;
    this.cb(
      [{ isIntersecting: true, target: el, boundingClientRect: { top: 0 } } as unknown as IntersectionObserverEntry],
      this as unknown as IntersectionObserver,
    );
  }
}

beforeEach(() => {
  useScanStore.getState().reset();
  MockIntersectionObserver.lastInstance = null;
  // 默认 jsdom 无 IntersectionObserver；各用例按需注入
  delete (globalThis as any).IntersectionObserver;
});

describe('ReportPage 目录 scrollspy', () => {
  it('无 IntersectionObserver（jsdom）下渲染 4 个锚点且不崩溃，默认高亮首项', () => {
    useScanStore.setState({ report: baseReport({ vulns: [], data: null }) });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    const anchors = Array.from(document.querySelectorAll('a[href^="#sec-"]'));
    expect(anchors.length).toBe(4);
    // 默认 activeSec = sec-vulns → 该按钮为 contained
    const first = document.querySelector('a[href="#sec-vulns"]') as HTMLElement;
    expect(first.className).toContain('MuiButton-contained');
  });

  it('注入 IntersectionObserver 后，区块进入视口切换高亮', async () => {
    (globalThis as any).IntersectionObserver = MockIntersectionObserver as any;
    useScanStore.setState({ report: baseReport({ vulns: [], data: null }) });
    render(
      <MemoryRouter>
        <ReportPage />
      </MemoryRouter>,
    );
    const obs = MockIntersectionObserver.lastInstance!;
    expect(obs).toBeTruthy();
    expect(obs.observed.length).toBe(4);
    // 初始高亮首项
    expect((document.querySelector('a[href="#sec-vulns"]') as HTMLElement).className).toContain(
      'MuiButton-contained',
    );
    // 触发 sec-data 进入视口 → 高亮切到「拖库数据」
    await act(async () => {
      obs.trigger('sec-data');
    });
    expect((document.querySelector('a[href="#sec-data"]') as HTMLElement).className).toContain(
      'MuiButton-contained',
    );
    expect((document.querySelector('a[href="#sec-vulns"]') as HTMLElement).className).not.toContain(
      'MuiButton-contained',
    );
  });
});
