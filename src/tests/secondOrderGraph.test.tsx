import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createRef } from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import SecondOrderGraph, { buildGraphData, layoutGraph, type GraphHandle } from '../components/SecondOrderGraph';

// html-to-image 依赖 canvas/SVG 序列化，jsdom 不支持，统一 mock 为返回假 dataUrl
vi.mock('html-to-image', () => ({
  toPng: vi.fn().mockResolvedValue('data:image/png;base64,iVBORw0KGgo='),
  toSvg: vi.fn().mockResolvedValue('data:image/svg+xml;base64,PHN2Zz4='),
}));

describe('buildGraphData（二阶链路图数据转换）', () => {
  it('存储点节点数 = storePoints.length，触发页节点数 = candidates.length', () => {
    const { nodes } = buildGraphData(
      ['http://t/a', 'http://t/b'],
      ['http://t/a'],
      [{ param: 'username', storeKind: 'registration' }],
    );
    const stores = nodes.filter((n) => n.type === 'store');
    const trigs = nodes.filter((n) => n.type === 'trigger');
    expect(stores.length).toBe(1);
    expect(trigs.length).toBe(2);
  });

  it('边仅从存储点连到「确认」触发页，候选未确认无入边', () => {
    const { edges } = buildGraphData(
      ['http://t/a', 'http://t/b'],
      ['http://t/a'], // 仅 a 确认
      [{ param: 'username', storeKind: 'registration' }],
    );
    // 仅 store-0 -> trig-0（a 确认），b 候选未确认不连线
    expect(edges.length).toBe(1);
    expect(edges[0].source).toBe('store-0');
    expect(edges[0].target).toBe('trig-0');
    expect(edges[0].animated).toBe(true);
  });

  it('confirmed 标记写入触发页节点 data.confirmed', () => {
    const { nodes } = buildGraphData(
      ['http://t/a', 'http://t/b'],
      ['http://t/a'],
      [],
    );
    const a = nodes.find((n) => n.id === 'trig-0')!;
    const b = nodes.find((n) => n.id === 'trig-1')!;
    expect((a.data as { confirmed: boolean }).confirmed).toBe(true);
    expect((b.data as { confirmed: boolean }).confirmed).toBe(false);
  });

  it('无存储点也无触发页时返回空图', () => {
    const { nodes, edges } = buildGraphData([], [], []);
    expect(nodes.length).toBe(0);
    expect(edges.length).toBe(0);
  });

  it('有候选触发页但无存储点时仍渲染触发页节点（无边）', () => {
    const { nodes, edges } = buildGraphData(['http://t/a'], [], []);
    expect(nodes.length).toBe(1);
    expect(edges.length).toBe(0);
    expect(nodes[0].type).toBe('trigger');
  });
});

describe('layoutGraph（dagre 自动布局）', () => {
  it('返回与原节点数相同的节点，且坐标为有限数', () => {
    const { nodes, edges } = buildGraphData(
      ['http://t/a', 'http://t/b'],
      ['http://t/a'],
      [{ param: 'username', storeKind: 'registration' }],
    );
    const laid = layoutGraph(nodes, edges);
    expect(laid.length).toBe(nodes.length);
    laid.forEach((n) => {
      expect(Number.isFinite(n.position.x)).toBe(true);
      expect(Number.isFinite(n.position.y)).toBe(true);
    });
  });

  it('LR 布局下存储点列在确认触发页左侧', () => {
    const { nodes, edges } = buildGraphData(
      ['http://t/a', 'http://t/b'],
      ['http://t/a', 'http://t/b'],
      [{ param: 'username', storeKind: 'registration' }],
    );
    const laid = layoutGraph(nodes, edges);
    const store = laid.filter((n) => n.type === 'store');
    const trig = laid.filter((n) => n.type === 'trigger');
    store.forEach((s) => {
      trig.forEach((t) => {
        expect(s.position.x).toBeLessThan(t.position.x);
      });
    });
  });

  it('多个确认触发页经 dagre 分层后纵向错开（y 不重叠）', () => {
    const { nodes, edges } = buildGraphData(
      ['http://t/a', 'http://t/b', 'http://t/c'],
      ['http://t/a', 'http://t/b', 'http://t/c'],
      [{ param: 'username', storeKind: 'registration' }],
    );
    const laid = layoutGraph(nodes, edges);
    const trigYs = laid.filter((n) => n.type === 'trigger').map((n) => n.position.y);
    const distinctY = new Set(trigYs).size;
    expect(distinctY).toBeGreaterThan(1);
  });
});

describe('SecondOrderGraph 交互（点击节点看详情 Drawer）', () => {
  const baseProps = {
    candidates: ['http://t/confirm', 'http://t/candidate'],
    confirmed: ['http://t/confirm'],
    storePoints: [{ param: 'username', storeKind: 'registration' }],
  };

  it('点击确认触发页节点 → 右侧抽屉显示「触发页详情」与确认状态', () => {
    render(<SecondOrderGraph {...baseProps} />);
    const node = screen.getByText('http://t/confirm').closest('.react-flow__node') as HTMLElement;
    expect(node).toBeTruthy();
    fireEvent.click(node);
    expect(screen.getByText('触发页详情')).toBeTruthy();
    expect(screen.getByText('已确认回显')).toBeTruthy();
  });

  it('点击存储点节点 → 抽屉显示参数名与类型', () => {
    render(<SecondOrderGraph {...baseProps} />);
    const node = screen.getByText('username').closest('.react-flow__node') as HTMLElement;
    expect(node).toBeTruthy();
    fireEvent.click(node);
    expect(screen.getByText('存储点详情')).toBeTruthy();
    expect(screen.getByText(/类型: registration/)).toBeTruthy();
  });

  it('点击后关闭按钮可关闭抽屉', () => {
    render(<SecondOrderGraph {...baseProps} />);
    const node = screen.getByText('http://t/confirm').closest('.react-flow__node') as HTMLElement;
    fireEvent.click(node);
    expect(screen.getByText('触发页详情')).toBeTruthy();
    fireEvent.click(screen.getByLabelText('关闭'));
    expect(screen.queryByText('触发页详情')).toBeNull();
  });
});

describe('SecondOrderGraph 导出 PNG', () => {
  const baseProps = {
    candidates: ['http://t/confirm', 'http://t/candidate'],
    confirmed: ['http://t/confirm'],
    storePoints: [{ param: 'username', storeKind: 'registration' }],
  };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.unstubAllGlobals();
  });

  it('点击「导出 PNG」按钮触发 html-to-image 的 toPng', async () => {
    const { toPng } = await import('html-to-image');
    render(<SecondOrderGraph {...baseProps} />);
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
    render(<SecondOrderGraph {...baseProps} />);
    const btn = screen.getByRole('button', { name: /导出 SVG/ });
    fireEvent.click(btn);
    await new Promise((r) => setTimeout(r, 0));
    expect(toSvg).toHaveBeenCalledTimes(1);
    expect((toSvg as unknown as ReturnType<typeof vi.fn>).mock.calls[0][1]).toMatchObject({
      backgroundColor: '#ffffff',
      width: expect.any(Number),
      height: expect.any(Number),
    });
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

    render(<SecondOrderGraph {...baseProps} />);
    fireEvent.click(screen.getByRole('button', { name: /复制图片/ }));
    await new Promise((r) => setTimeout(r, 20));

    expect(toPng).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(clipboardWrite).toHaveBeenCalledTimes(1);
    const written = clipboardWrite.mock.calls[0][0] as unknown as Array<{ items: Record<string, Blob> }>;
    expect(written[0].items['image/png']).toBeInstanceOf(Blob);
  });

  it('导出按钮区带 rp-no-print（不随报告页 PDF/打印导出）', () => {
    render(<SecondOrderGraph {...baseProps} />);
    const btn = screen.getByRole('button', { name: /导出 PNG/ });
    expect(btn.closest('.rp-no-print')).toBeTruthy();
  });

  it('导出走组件容器 ref 而非 document.querySelector（多实例隔离，避免取错首个 viewport）', async () => {
    const docQ = vi.spyOn(document, 'querySelector');
    const { toPng } = await import('html-to-image');
    render(<SecondOrderGraph {...baseProps} />);
    fireEvent.click(screen.getByRole('button', { name: /导出 PNG/ }));
    await new Promise((r) => setTimeout(r, 0));
    expect(toPng).toHaveBeenCalledTimes(1);
    expect(docQ).not.toHaveBeenCalledWith('.react-flow__viewport');
    docQ.mockRestore();
  });

  it('forwardRef exportImage("png") 触发 toPng（报告页便捷入口走此通道）', async () => {
    const { toPng } = await import('html-to-image');
    const ref = createRef<GraphHandle>();
    render(<SecondOrderGraph ref={ref} {...baseProps} />);
    await ref.current!.exportImage('png');
    expect(toPng).toHaveBeenCalledTimes(1);
  });
});
