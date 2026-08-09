import { describe, it, expect, vi, beforeEach } from 'vitest';
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
});
