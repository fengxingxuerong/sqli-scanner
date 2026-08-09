import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createRef } from 'react';
import { render, screen, fireEvent, within } from '@testing-library/react';
import InjectionTopologyGraph, { buildTopologyData, layoutTopology, type GraphHandle } from '../components/InjectionTopologyGraph';
import type { InjectionPoint, InjectionLocation } from '../shared/types';

// html-to-image 依赖 canvas/SVG 序列化，jsdom 不支持，统一 mock 为返回假 dataUrl
vi.mock('html-to-image', () => ({
  toPng: vi.fn().mockResolvedValue('data:image/png;base64,iVBORw0KGgo='),
  toSvg: vi.fn().mockResolvedValue('data:image/svg+xml;base64,PHN2Zz4='),
}));

// 构造注入点（最小字段，后端 createInjectionPoint 的同构前端形状）
function makePoint(
  id: string,
  param: string,
  location: InjectionLocation,
  isStore = false,
  storeKind: string | null = null,
): InjectionPoint {
  return {
    id,
    location,
    param,
    originalValue: '1',
    confirmed: false,
    technique: null,
    dbms: null,
    isStorePoint: isStore,
    storeKind,
  } as InjectionPoint;
}

describe('buildTopologyData（全局注入拓扑数据转换）', () => {
  it('空 points 返回空图', () => {
    const { nodes, edges } = buildTopologyData([], 'http://t');
    expect(nodes.length).toBe(0);
    expect(edges.length).toBe(0);
  });

  it('节点数 = 1 目标 + 非空 location 数 + 注入点数（+ 确认触发页数）', () => {
    const pts = [
      makePoint('1', 'a', 'body'),
      makePoint('2', 'b', 'body', true, 'registration'),
      makePoint('3', 'c', 'url'),
      makePoint('4', 'd', 'cookie'),
    ];
    const { nodes } = buildTopologyData(pts, 'http://t', { confirmed: ['http://t/trig1'] });
    // 目标1 + location(body/url/cookie 共 3 类) + 4 注入点 + 1 触发页 = 9
    expect(nodes.length).toBe(9);
    expect(nodes.filter((n) => n.type === 'target').length).toBe(1);
    expect(nodes.filter((n) => n.type === 'location').length).toBe(3);
    expect(nodes.filter((n) => n.type === 'param').length).toBe(4);
    expect(nodes.filter((n) => n.type === 'trigger').length).toBe(1);
  });

  it('边：目标→位置→参数 三层 + 存储点→确认触发页', () => {
    const pts = [makePoint('1', 'a', 'body', true, 'registration'), makePoint('2', 'b', 'url')];
    const { edges } = buildTopologyData(pts, 'http://t', { confirmed: ['http://t/x'] });
    // target→loc-body + target→loc-url = 2
    // loc-body→p-1 + loc-url→p-2 = 2
    // p-1(store)→trig-0 = 1
    expect(edges.length).toBe(5);
    expect(edges.some((e) => e.source === 'target' && e.target === 'loc-body')).toBe(true);
    expect(edges.some((e) => e.source === 'loc-body' && e.target === 'p-1')).toBe(true);
    expect(edges.some((e) => e.source === 'p-1' && e.target === 'trig-0')).toBe(true);
  });

  it('无二阶时退化为目标→位置→参数（无触发页节点、无 store 出边）', () => {
    const pts = [makePoint('1', 'a', 'body', true, 'registration'), makePoint('2', 'b', 'url')];
    const { nodes, edges } = buildTopologyData(pts, 'http://t');
    expect(nodes.filter((n) => n.type === 'trigger').length).toBe(0);
    // target→loc-body + target→loc-url + loc-body→p-1 + loc-url→p-2 = 4
    expect(edges.length).toBe(4);
  });

  it('空 location 类别不生成位置节点', () => {
    const pts = [makePoint('1', 'a', 'body')];
    const { nodes } = buildTopologyData(pts, 'http://t');
    expect(nodes.some((n) => n.id === 'loc-cookie')).toBe(false);
    expect(nodes.some((n) => n.id === 'loc-header')).toBe(false);
    expect(nodes.some((n) => n.id === 'loc-body')).toBe(true);
  });

  it('highlightPointIds 命中参数节点 → data.vulnerable=true，未命中为 false（不影响节点数）', () => {
    const pts = [makePoint('1', 'a', 'body'), makePoint('2', 'b', 'url')];
    const { nodes } = buildTopologyData(pts, 'http://t', undefined, ['1']);
    const p1 = nodes.find((n) => n.id === 'p-1')!;
    const p2 = nodes.find((n) => n.id === 'p-2')!;
    expect((p1.data as { vulnerable: boolean }).vulnerable).toBe(true);
    expect((p2.data as { vulnerable: boolean }).vulnerable).toBe(false);
  });
});

describe('layoutTopology（dagre 自动布局）', () => {
  it('返回与原节点数相同且坐标为有限数', () => {
    const pts = [makePoint('1', 'a', 'body', true, 'registration'), makePoint('2', 'b', 'url')];
    const data = buildTopologyData(pts, 'http://t', { confirmed: ['http://t/x'] });
    const laid = layoutTopology(data.nodes, data.edges);
    expect(laid.length).toBe(data.nodes.length);
    laid.forEach((n) => {
      expect(Number.isFinite(n.position.x)).toBe(true);
      expect(Number.isFinite(n.position.y)).toBe(true);
    });
  });

  it('LR 布局下目标列在最左（x 最小）', () => {
    const pts = [makePoint('1', 'a', 'body', true, 'registration'), makePoint('2', 'b', 'url')];
    const data = buildTopologyData(pts, 'http://t', { confirmed: ['http://t/x'] });
    const laid = layoutTopology(data.nodes, data.edges);
    const target = laid.find((n) => n.id === 'target')!;
    const others = laid.filter((n) => n.id !== 'target');
    others.forEach((o) => expect(target.position.x).toBeLessThan(o.position.x));
  });
});

describe('InjectionTopologyGraph 交互（点击节点看详情 Drawer）', () => {
  const baseProps = {
    points: [makePoint('1', 'username', 'body', true, 'registration'), makePoint('2', 'id', 'url')],
    baseUrl: 'http://t',
    secondOrder: {
      confirmed: ['http://t/trig'],
      storePoints: [{ param: 'username', storeKind: 'registration' }],
    },
  };

  it('点击存储点参数节点 → 抽屉显示「存储点详情」+ 参数名 + 分类', () => {
    render(<InjectionTopologyGraph {...baseProps} />);
    const node = screen.getByText('username').closest('.react-flow__node') as HTMLElement;
    expect(node).toBeTruthy();
    fireEvent.click(node);
    // 抽屉标题「存储点详情」全局唯一，据此锚定抽屉后在其内部断言，避免与节点文案重复匹配
    const drawer = screen.getByText('存储点详情').closest('.MuiDrawer-root') as HTMLElement;
    expect(within(drawer).getByText('username')).toBeTruthy();
    expect(within(drawer).getByText(/分类: registration/)).toBeTruthy();
  });

  it('点击触发页节点 → 抽屉显示「触发页详情」+ URL', () => {
    render(<InjectionTopologyGraph {...baseProps} />);
    const node = screen.getByText('http://t/trig').closest('.react-flow__node') as HTMLElement;
    expect(node).toBeTruthy();
    fireEvent.click(node);
    const drawer = screen.getByText('触发页详情').closest('.MuiDrawer-root') as HTMLElement;
    expect(within(drawer).getByText('http://t/trig')).toBeTruthy();
  });

  it('点击目标节点 → 抽屉显示「扫描目标」+ baseUrl', () => {
    render(<InjectionTopologyGraph {...baseProps} />);
    const node = screen.getByText('http://t').closest('.react-flow__node') as HTMLElement;
    expect(node).toBeTruthy();
    fireEvent.click(node);
    // 「扫描目标」同时出现于目标节点与抽屉标题，改用仅抽屉内出现的「目标 URL」标签锚定抽屉
    const drawer = screen.getByText('目标 URL').closest('.MuiDrawer-root') as HTMLElement;
    expect(within(drawer).getByText('扫描目标')).toBeTruthy();
    expect(within(drawer).getByText('http://t')).toBeTruthy();
  });
});

describe('InjectionTopologyGraph 导出 PNG', () => {
  const baseProps = {
    points: [makePoint('1', 'username', 'body', true, 'registration')],
    baseUrl: 'http://t',
    secondOrder: {
      confirmed: ['http://t/trig'],
      storePoints: [{ param: 'username', storeKind: 'registration' }],
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.unstubAllGlobals();
  });

  it('点击「导出 PNG」按钮触发 html-to-image 的 toPng', async () => {
    const { toPng } = await import('html-to-image');
    render(<InjectionTopologyGraph {...baseProps} />);
    const btn = screen.getByRole('button', { name: /导出 PNG/ });
    fireEvent.click(btn);
    // toPng 异步执行，等待微任务完成后断言
    await new Promise((r) => setTimeout(r, 0));
    expect(toPng).toHaveBeenCalledTimes(1);
    expect((toPng as unknown as ReturnType<typeof vi.fn>).mock.calls[0][1]).toMatchObject({
      backgroundColor: '#ffffff',
      width: expect.any(Number),
      height: expect.any(Number),
    });
  });

  it('点击「导出 SVG」按钮触发 html-to-image 的 toSvg 且不影响 PNG 计数', async () => {
    const { toPng, toSvg } = await import('html-to-image');
    render(<InjectionTopologyGraph {...baseProps} />);
    const btn = screen.getByRole('button', { name: /导出 SVG/ });
    fireEvent.click(btn);
    await new Promise((r) => setTimeout(r, 0));
    expect(toSvg).toHaveBeenCalledTimes(1);
    const opts = (toSvg as unknown as ReturnType<typeof vi.fn>).mock.calls[0][1];
    expect(opts).toMatchObject({
      backgroundColor: '#ffffff',
      width: expect.any(Number),
      height: expect.any(Number),
    });
    // PNG 未被本次点击调用
    expect(toPng).toHaveBeenCalledTimes(0);
  });

  it('点击「复制图片」将 PNG 写入剪贴板', async () => {
    const { toPng } = await import('html-to-image');
    const clipboardWrite = vi.fn().mockResolvedValue(undefined);
    (navigator as unknown as { clipboard: { write: typeof clipboardWrite } }).clipboard = {
      write: clipboardWrite,
    };
    vi.stubGlobal(
      'ClipboardItem',
      class {
        items: Record<string, Blob>;
        constructor(items: Record<string, Blob>) {
          this.items = items;
        }
      },
    );
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ blob: () => Promise.resolve(new Blob(['x'], { type: 'image/png' })) });
    vi.stubGlobal('fetch', fetchMock);

    render(<InjectionTopologyGraph {...baseProps} />);
    fireEvent.click(screen.getByRole('button', { name: /复制图片/ }));
    await new Promise((r) => setTimeout(r, 20));

    expect(toPng).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(clipboardWrite).toHaveBeenCalledTimes(1);
    const written = clipboardWrite.mock.calls[0][0] as unknown as Array<{ items: Record<string, Blob> }>;
    expect(written[0].items['image/png']).toBeInstanceOf(Blob);
  });

  it('导出按钮区带 rp-no-print（不随报告页 PDF/打印导出）', () => {
    render(<InjectionTopologyGraph {...baseProps} />);
    const btn = screen.getByRole('button', { name: /导出 PNG/ });
    expect(btn.closest('.rp-no-print')).toBeTruthy();
  });

  it('导出走组件容器 ref 而非 document.querySelector（多实例隔离，避免取错首个 viewport）', async () => {
    const docQ = vi.spyOn(document, 'querySelector');
    const { toPng } = await import('html-to-image');
    render(<InjectionTopologyGraph {...baseProps} />);
    fireEvent.click(screen.getByRole('button', { name: /导出 PNG/ }));
    await new Promise((r) => setTimeout(r, 0));
    expect(toPng).toHaveBeenCalledTimes(1);
    expect(docQ).not.toHaveBeenCalledWith('.react-flow__viewport');
    docQ.mockRestore();
  });

  it('forwardRef exportImage("png") 触发 toPng（报告页便捷入口走此通道）', async () => {
    const { toPng } = await import('html-to-image');
    const ref = createRef<GraphHandle>();
    render(<InjectionTopologyGraph ref={ref} {...baseProps} />);
    await ref.current!.exportImage('png');
    expect(toPng).toHaveBeenCalledTimes(1);
  });
});
