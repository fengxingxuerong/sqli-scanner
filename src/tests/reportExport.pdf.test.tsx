import { describe, it, expect, vi, beforeEach } from 'vitest';

// html-to-image 与 jspdf 在 jsdom 下依赖 canvas/真实字体，统一 mock：
// - toPng：返回假 PNG dataUrl（filter 在调用参数里，测试直接从 mock.calls 读取）
// - jsPDF：记录 addPage/addImage/save 调用，模拟 A4 页尺寸
// 用 vi.hoisted 声明 mock，确保 vi.mock 工厂闭包可安全引用（避免 hoist 限制导致 toPng 行为异常/超时）
const { toPngMock } = vi.hoisted(() => ({ toPngMock: vi.fn() }));
vi.mock('html-to-image', () => ({
  toPng: (node: HTMLElement, opts: any) => toPngMock(node, opts),
}));

const addPageMock = vi.fn();
const addImageMock = vi.fn();
const saveMock = vi.fn();
vi.mock('jspdf', () => ({
  jsPDF: class {
    internal = {
      pageSize: {
        getWidth: () => 210,
        getHeight: () => 297,
      },
    };
    addPage = addPageMock;
    addImage = addImageMock;
    save = saveMock;
  },
}));

import { downloadPdf } from '../shared/reportExport';

beforeEach(() => {
  toPngMock.mockReset();
  addPageMock.mockReset();
  addImageMock.mockReset();
  saveMock.mockReset();
  toPngMock.mockResolvedValue('data:image/png;base64,AAAA');
  // jsdom 无 Image 真实解码；构造一个带 naturalWidth/Height 的假对象供切片比例计算
  // @ts-expect-error 测试环境覆盖全局 Image
  globalThis.Image = class {
    naturalWidth = 1000;
    naturalHeight = 4000; // 长图：触发多页切片
    onload: (() => void) | null = null;
    onerror: (() => void) | null = null;
    set src(_v: string) {
      if (this.onload) this.onload();
    }
  };
  // jsdom 无 canvas；mock createElement('canvas') 返回带 getContext/toDataURL 的假对象
  const origCreate = document.createElement.bind(document);
  vi.spyOn(document, 'createElement').mockImplementation((tag: string) => {
    if (tag === 'canvas') {
      return {
        width: 0,
        height: 0,
        getContext: () => ({
          fillStyle: '',
          fillRect: () => {},
          drawImage: () => {},
        }),
        toDataURL: () => 'data:image/png;base64,SLICE',
      } as unknown as HTMLCanvasElement;
    }
    return origCreate(tag as any);
  });
});

function makeNode(): HTMLElement {
  const el = document.createElement('div');
  // 普通内容子节点
  const content = document.createElement('div');
  content.textContent = '报告正文';
  el.appendChild(content);
  // 应被排除：data-pdf-exclude
  const excludeExport = document.createElement('div');
  excludeExport.setAttribute('data-pdf-exclude', 'true');
  excludeExport.textContent = '导出按钮区';
  el.appendChild(excludeExport);
  // 应被排除：rp-no-print
  const noPrint = document.createElement('div');
  noPrint.className = 'rp-no-print';
  noPrint.textContent = '打印隐藏区';
  el.appendChild(noPrint);
  return el;
}

/** 从 toPng 调用参数里取 filter 函数（避免 vi.mock 工厂闭包无法捕获模块变量） */
function getFilter(): ((el: any) => boolean) | undefined {
  const opts = toPngMock.mock.calls[0]?.[1];
  return opts?.filter;
}

describe('reportExport.downloadPdf', () => {
  it('长报告应切成多页并调用 save（A4 比例 + canvas 切片）', async () => {
    const node = makeNode();
    await downloadPdf(node, 'report-x.pdf');

    // 1) toPng 被调用
    expect(toPngMock).toHaveBeenCalledTimes(1);
    // 2) 整图 1000×4000；imgW=194mm → pxPerMm≈5.155 → imgH≈776mm；contentH=281mm → 约 3 页
    expect(addImageMock).toHaveBeenCalled();
    expect(addPageMock.mock.calls.length).toBeGreaterThanOrEqual(1); // 多页（首頁不加 addPage）
    expect(saveMock).toHaveBeenCalledWith('report-x.pdf');
    // 每页 addImage 标准 5 参数：(dataUrl,'PNG',x,y,w,h)
    for (const c of addImageMock.mock.calls) {
      expect(c[0]).toBe('data:image/png;base64,SLICE');
      expect(c[1]).toBe('PNG');
      expect(c[2]).toBe(8); // margin x
      expect(typeof c[4]).toBe('number'); // w = imgW
      expect(typeof c[5]).toBe('number'); // h = sliceHmm
    }
  });

  it('filter 排除 data-pdf-exclude 与 rp-no-print 节点，保留普通内容', async () => {
    const node = makeNode();
    const content = node.children[0] as HTMLElement;
    const excludeExport = node.children[1] as HTMLElement;
    const noPrint = node.children[2] as HTMLElement;
    await downloadPdf(node, 'report-f.pdf');
    const filter = getFilter();
    expect(typeof filter).toBe('function');
    expect(filter!(content)).toBe(true);
    expect(filter!(excludeExport)).toBe(false);
    expect(filter!(noPrint)).toBe(false);
  });

  it('栅格化像素异常（0 宽）不崩，兜底单页后仍 save', async () => {
    // 让 Image 返回 0 像素 → pxPerMm=0 → imgH 兜底为 contentH，至少一页
    // @ts-expect-error 覆盖 Image 使 naturalWidth=0
    globalThis.Image = class {
      naturalWidth = 0;
      naturalHeight = 0;
      onload: (() => void) | null = null;
      set src(_v: string) {
        if (this.onload) this.onload();
      }
    };
    const node = makeNode();
    await downloadPdf(node, 'report-0.pdf');
    expect(saveMock).toHaveBeenCalled();
    expect(addImageMock).toHaveBeenCalledTimes(1); // 兜底单页
  });
});
