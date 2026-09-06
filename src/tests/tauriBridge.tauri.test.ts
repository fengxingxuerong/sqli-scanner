import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest';

// 桌面版（__TAURI_INTERNALS__ 存在）的桥接行为：
// tauriAvailable 在模块加载时捕获，因此必须在 import 前挂好标记（vi.hoisted 先于所有 import 执行）。
// 全文件使用同一模块实例；plugin-dialog / plugin-fs 未安装，经 vitest.config.ts alias 指向 stubs/ 桩。
const h = vi.hoisted(() => {
  (window as any).__TAURI_INTERNALS__ = { postMessage: () => undefined };
  return {
    listen: vi.fn(),
    invoke: vi.fn(),
  };
});

vi.mock('@tauri-apps/api/event', () => ({ listen: h.listen }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: h.invoke }));

import { tauriBridge } from '../shared/tauriBridge';
import { save as dialogSave, open as dialogOpen } from './stubs/tauriPluginDialog';
import { writeTextFile, readTextFile } from './stubs/tauriPluginFs';

describe('tauriBridge 桌面分支（__TAURI_INTERNALS__）', () => {
  // 兜底：确保本文件内标记存在（vi.hoisted 已在最前挂载）
  beforeAll(() => {
    (window as any).__TAURI_INTERNALS__ = { postMessage: () => undefined };
  });

  // 本地 singleThread 模式下 jsdom window 在文件间共享，
  // 必须清理，否则污染后面 Web 分支测试（tauriBridge.test.ts 期望 isTauri=false）
  afterAll(() => {
    delete (window as any).__TAURI_INTERNALS__;
  });

  beforeEach(() => {
    h.listen.mockReset().mockResolvedValue(() => undefined);
    h.invoke.mockReset().mockResolvedValue(undefined);
    dialogSave.mockReset();
    dialogOpen.mockReset();
    writeTextFile.mockReset().mockResolvedValue(undefined);
    readTextFile.mockReset().mockResolvedValue('');
  });

  it('isTauri 为 true', () => {
    expect(tauriBridge.isTauri).toBe(true);
  });

  it('startEngine 调用 invoke("start_engine")，失败被吞掉不抛错', async () => {
    await expect(tauriBridge.startEngine()).resolves.toBeUndefined();
    expect(h.invoke).toHaveBeenCalledWith('start_engine');

    h.invoke.mockRejectedValueOnce(new Error('engine spawn failed'));
    await expect(tauriBridge.startEngine()).resolves.toBeUndefined();
  });

  it('stopEngine 调用 invoke("stop_engine")，失败被吞掉不抛错', async () => {
    await expect(tauriBridge.stopEngine()).resolves.toBeUndefined();
    expect(h.invoke).toHaveBeenCalledWith('stop_engine');

    h.invoke.mockRejectedValueOnce(new Error('engine stop failed'));
    await expect(tauriBridge.stopEngine()).resolves.toBeUndefined();
  });

  it('onEngineExit 注册 listen("engine-exit") 并把 payload 回传给 callback', async () => {
    const cb = vi.fn();
    const cancel = tauriBridge.onEngineExit(cb);
    expect(cancel).toBeTypeOf('function');

    await vi.waitFor(() => expect(h.listen).toHaveBeenCalled());
    expect(h.listen.mock.calls[0][0]).toBe('engine-exit');

    const handler = h.listen.mock.calls[0][1] as (e: { payload: unknown }) => void;
    handler({ payload: { code: 137, signal: 'SIGKILL' } });
    expect(cb).toHaveBeenCalledWith({ code: 137, signal: 'SIGKILL' });
  });

  it('onEngineExit 返回的取消函数调用 unlisten；listen 失败不抛错', async () => {
    const unlisten = vi.fn();
    h.listen.mockResolvedValue(unlisten);
    const cancel = tauriBridge.onEngineExit(vi.fn());
    await vi.waitFor(() => expect(h.listen).toHaveBeenCalled());
    cancel!();
    expect(unlisten).toHaveBeenCalledTimes(1);

    // listen 本身 reject：不抛错（内部 catch 吞掉）
    h.listen.mockRejectedValue(new Error('listen failed'));
    expect(() => tauriBridge.onEngineExit(vi.fn())).not.toThrow();
  });

  it('saveFile 走 dialog.save + fs.writeTextFile；用户取消（null）不写文件', async () => {
    dialogSave.mockResolvedValue('C:\\out\\report.json');
    await tauriBridge.saveFile('report.json', '{"a":1}', 'application/json');
    expect(dialogSave).toHaveBeenCalledWith({ defaultPath: 'report.json' });
    expect(writeTextFile).toHaveBeenCalledWith('C:\\out\\report.json', '{"a":1}');

    dialogSave.mockResolvedValue(null);
    await tauriBridge.saveFile('x.json', '{}', 'application/json');
    expect(writeTextFile).toHaveBeenCalledTimes(1); // 仍是上面那一次
  });

  it('openTextFile 走 dialog.open + fs.readTextFile；取消/非字符串路径返回 null', async () => {
    dialogOpen.mockResolvedValue('C:\\req.txt');
    readTextFile.mockResolvedValue('GET / HTTP/1.1');
    await expect(tauriBridge.openTextFile()).resolves.toBe('GET / HTTP/1.1');
    expect(dialogOpen).toHaveBeenCalledWith({
      multiple: false,
      filters: [{ name: 'HTTP Request', extensions: ['txt', 'req', 'http'] }],
    });
    expect(readTextFile).toHaveBeenCalledWith('C:\\req.txt');

    dialogOpen.mockResolvedValue(null);
    await expect(tauriBridge.openTextFile()).resolves.toBeNull();

    dialogOpen.mockResolvedValue(undefined);
    await expect(tauriBridge.openTextFile()).resolves.toBeNull();
  });
});

