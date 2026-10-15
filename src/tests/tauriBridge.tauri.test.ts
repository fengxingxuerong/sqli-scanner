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
import { getApiBase } from '../shared/apiClient';
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

describe('tauriBridge D81：引擎重启重连（restartEngineAndApply）', () => {
  // 与第一个 describe 同款的隔离：缺了它，spy 调用记录与 mockImplementation 会跨测试累积
  // （实测病征：not.toHaveBeenCalledWith('start_engine') 被上一个 describe 的历史调用误触红）。
  beforeEach(() => {
    h.listen.mockReset().mockResolvedValue(() => undefined);
    h.invoke.mockReset().mockResolvedValue(undefined);
  });

  it('isRestartingEngine：重启窗口内为 true、结束后回落 false（无限重启循环的破除点）', async () => {
    vi.useFakeTimers();
    try {
      h.invoke.mockImplementation((cmd: string) =>
        cmd === 'start_engine' ? Promise.resolve('ok') : Promise.resolve({ port: 0, token: '' }));
      const p = tauriBridge.restartEngineAndApply();
      // 首轮 500ms 轮询之前：重启窗口内（engine-exit 处理器据此跳过「再重启一次」）。
      // 推进 100ms < 500ms 首个轮询点，标志必为 true。
      await vi.advanceTimersByTimeAsync(100);
      expect(tauriBridge.isRestartingEngine()).toBe(true);
      await vi.advanceTimersByTimeAsync(15_000);
      await p;
      expect(tauriBridge.isRestartingEngine()).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  }, 20_000);


  // ── D81/D83：restartEngineAndApply（确保引擎在线 + 落地当前实连信息）────────
  // D83 改幂等后分两档：信息已就绪 ⇒ 零 invoke（旧实现每次开扫重启引擎、换 token，
  // 是 D81 两条 bug 的总源头）；未就绪 ⇒ start_engine 拉起 + 有界轮询等就绪。
  it('D83：引擎已在跑（信息就绪）⇒ 不 invoke 任何命令，直接落地返回', async () => {
    h.invoke.mockImplementation((cmd: string) =>
      Promise.resolve(cmd === 'start_engine' ? 'ok' : { port: 4567, token: 'tok' }));
    const info = await tauriBridge.restartEngineAndApply();
    expect(info).toEqual({ port: 4567, token: 'tok' });
    // 关键断言：根本不碰 start_engine —— 不开扫即重启，token 不变，D81 病征无从复发
    expect(h.invoke).not.toHaveBeenCalledWith('start_engine');
    expect(getApiBase()).toBe('http://127.0.0.1:4567/api');
  });

  it('D83：信息未就绪（port=0）⇒ 才 invoke start_engine，拿到新 port/token 后落地', async () => {
    let infoCalls = 0;
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === 'start_engine') return Promise.resolve('ok');
      infoCalls += 1;
      // 第 1 次（就绪探测）未就绪；重启后第 2 次拿到新实连信息
      return Promise.resolve(infoCalls < 2 ? { port: 0, token: '' } : { port: 5300, token: 't-new' });
    });
    const info = await tauriBridge.restartEngineAndApply();
    expect(info).toEqual({ port: 5300, token: 't-new' });
    expect(h.invoke).toHaveBeenCalledWith('start_engine');
    expect(getApiBase()).toBe('http://127.0.0.1:5300/api');
  });

  it('D81：token 未就绪（port=0）时继续轮询，不采用半就绪状态', async () => {
    let infoCalls = 0;
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === 'start_engine') return Promise.resolve('ok');
      infoCalls += 1;
      // 第 1 轮就绪探测 + 前两轮轮询均未就绪（Rust 侧 recv_timeout 5s），第 4 次拿到
      return Promise.resolve(infoCalls < 4 ? { port: 0, token: '' } : { port: 5300, token: 't2' });
    });
    const info = await tauriBridge.restartEngineAndApply();
    expect(info).toEqual({ port: 5300, token: 't2' });
    expect(infoCalls).toBeGreaterThanOrEqual(4);
  });

  it('D81：引擎始终不就绪 ⇒ 有界轮询后放弃返回 null（不无限等）', async () => {
    vi.useFakeTimers();
    try {
      h.invoke.mockImplementation((cmd: string) => Promise.resolve({ port: 0, token: '' }));
      const p = tauriBridge.restartEngineAndApply();
      await vi.advanceTimersByTimeAsync(15_000); // 24 轮 × 500ms = 12s 上界
      await expect(p).resolves.toBeNull();
    } finally {
      vi.useRealTimers();
    }
  }, 20_000);

  it('isRestartingEngine：重启窗口内为 true、结束后回落 false（无限重启循环的破除点）', async () => {
    vi.useFakeTimers();
    try {
      let calls = 0;
      h.invoke.mockImplementation((cmd: string) => {
        if (cmd === 'start_engine') return Promise.resolve('ok');
        calls += 1;
        return Promise.resolve(calls < 2 ? { port: 0, token: '' } : { port: 4567, token: 't' });
      });
      const p = tauriBridge.restartEngineAndApply();
      // 首轮 500ms 轮询之前：重启窗口内（engine-exit 处理器据此跳过「再重启一次」）。
      // 推进 100ms < 500ms 首个轮询点，标志必为 true。
      await vi.advanceTimersByTimeAsync(100);
      expect(tauriBridge.isRestartingEngine()).toBe(true);
      await vi.advanceTimersByTimeAsync(15_000);
      await p;
      expect(tauriBridge.isRestartingEngine()).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  }, 20_000);
});
