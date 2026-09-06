import { describe, it, expect, vi } from 'vitest';
import { tauriBridge } from '../shared/tauriBridge';

// Web 环境下的桥接行为（Tauri 环境由 window.__TAURI_INTERNALS__ 触发，jsdom 下不存在）
describe('tauriBridge', () => {
  it('Web 环境下 isTauri 为 false', () => {
    expect(tauriBridge.isTauri).toBe(false);
  });

  it('Web 环境下启停引擎为 no-op 且 resolve', async () => {
    await expect(tauriBridge.startEngine()).resolves.toBeUndefined();
    await expect(tauriBridge.stopEngine()).resolves.toBeUndefined();
  });

  it('Web 环境保存文件走浏览器下载分支（不抛错）', async () => {
    const createObjectURL = vi.fn(() => 'blob:mock');
    (globalThis as any).URL.createObjectURL = createObjectURL;
    (globalThis as any).URL.revokeObjectURL = vi.fn();
    const clickSpy = vi
      .spyOn(HTMLAnchorElement.prototype, 'click')
      .mockImplementation(() => undefined);

    await expect(
      tauriBridge.saveFile('report.json', '{"a":1}', 'application/json')
    ).resolves.toBeUndefined();

    expect(createObjectURL).toHaveBeenCalled();
    clickSpy.mockRestore();
  });

  it('Web 环境打开文本文件走隐藏 input + FileReader 分支并回传内容', async () => {
    const file = new File(['POST /a HTTP/1.1\r\nHost: h.com'], 'req.txt', {
      type: 'text/plain',
    });
    const realCreate = document.createElement.bind(document);
    const createSpy = vi
      .spyOn(document, 'createElement')
      .mockImplementation((tag: string) => {
        const el = realCreate(tag);
        if (tag === 'input') {
          // 拦截 click()：模拟用户选择文件后触发 onchange
          (el as HTMLInputElement).click = () => {
            Object.defineProperty(el, 'files', { value: [file] });
            el.onchange?.(new Event('change'));
          };
        }
        return el;
      });

    await expect(tauriBridge.openTextFile('.txt,.req')).resolves.toBe(
      'POST /a HTTP/1.1\r\nHost: h.com'
    );
    createSpy.mockRestore();
  });

  it('Web 环境取消选择（无文件）返回 null', async () => {
    const realCreate = document.createElement.bind(document);
    const createSpy = vi
      .spyOn(document, 'createElement')
      .mockImplementation((tag: string) => {
        const el = realCreate(tag);
        if (tag === 'input') {
          (el as HTMLInputElement).click = () => {
            Object.defineProperty(el, 'files', { value: [] });
            el.onchange?.(new Event('change'));
          };
        }
        return el;
      });

    await expect(tauriBridge.openTextFile()).resolves.toBeNull();
    createSpy.mockRestore();
  });
});
