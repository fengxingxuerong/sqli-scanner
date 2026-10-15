// ============================================================================
// appMount.engineGate.test.tsx —— [D84] 桌面版渲染门禁：引擎就绪前不渲染路由
// ============================================================================
// 实测缺陷（报告页视觉核查时撞到）：引擎实连信息（端口 + 一次性 token）是**异步**
// 取得的（App 挂载时向 Rust 问 sidecar 实况）。旧实现下页面与它赛跑——冷启动
// 直达 /report/:id 时，ReportPage 的 fetch 比引擎信息先发出，用默认 base 打 404，
// 用户看到「未找到报告」，而引擎 API 明明好着（同 scanId 的 /api/scan/:id/report
// 返回 200、/api/scans 列单也有它）。
//
// D84 修法：App 挂载后先 `restartEngineAndApply()`（有界等待），**就绪后才渲染
// RouterProvider**；web/测试环境 isTauri=false，门禁初值即开，不受影响。
//
// 判据选 TopBar 的语言切换按钮（aria-label='Chinese'）：TopBar 只经路由渲染，
// 门禁未开时整个 RouterProvider 都不在——比匹配聚合文案稳。
// ============================================================================
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';

// [D84] 不抬高 cast 预算：给 Window 加一个**具名可选**的类型槽，而不是 `as any`
// （后者会把"这里到底该是什么类型"整个关掉，本仓 castBudget 守卫只许减不许增）。
// 可选（?）是必要的：赋值/删除之外还有 jsdom 没有该属性的运行时路径，且 delete 只作用于可选属性。
declare global {
  interface Window {
    __TAURI_INTERNALS__?: { postMessage: (msg: unknown) => void };
  }
}

// tauriAvailable 在模块加载时捕获窗口标记：必须在 import App 前挂好（vi.hoisted）
const h = vi.hoisted(() => {
  window.__TAURI_INTERNALS__ = { postMessage: () => undefined };
  return { invoke: vi.fn() };
});
vi.mock('@tauri-apps/api/core', () => ({ invoke: h.invoke }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn().mockResolvedValue(() => undefined) }));

import App from '../App';

const topBarRendered = () => screen.queryByRole('button', { name: 'Chinese' }) !== null;

describe('D84 桌面版引擎就绪渲染门禁', () => {
  beforeEach(() => {
    localStorage.clear();
    localStorage.setItem('sqli_disclaimer', '1'); // 绕过免责声明门，专测引擎门
    h.invoke.mockReset();
  });

  afterEach(() => {
    delete window.__TAURI_INTERNALS__;
  });

  it('桌面模式：引擎未就绪期间不渲染路由（就绪后放行）', async () => {
    let infoCalls = 0;
    h.invoke.mockImplementation((cmd: string) => {
      if (cmd === 'start_engine') return Promise.resolve('ok');
      infoCalls += 1;
      // 首轮就绪探测未就绪（port=0）⇒ 走重启+轮询路径（首轮轮询在 500ms 后）
      return Promise.resolve(infoCalls < 2 ? { port: 0, token: '' } : { port: 4567, token: 't' });
    });
    render(<App />);
    // 同步断言：门禁初关，路由不在（这正是旧实现会提前发请求的窗口）
    expect(topBarRendered()).toBe(false);
    // 轮询成功（~500ms+）后放行
    await waitFor(() => expect(topBarRendered()).toBe(true), { timeout: 5_000 });
  });

  it('桌面模式：引擎一开始就绪 ⇒ 门禁随即放行（restartEngineAndApply 零 invoke 快路径）', async () => {
    // 形参留空而不写 (cmd: string)：本例不按命令分支，写了就是未使用形参 ⇒ typecheck:tests 红
    h.invoke.mockImplementation(() => Promise.resolve({ port: 4567, token: 't' }));
    render(<App />);
    await waitFor(() => expect(topBarRendered()).toBe(true), { timeout: 5_000 });
    // 快路径：根本不碰 start_engine（D83 幂等语义）
    expect(h.invoke).not.toHaveBeenCalledWith('start_engine');
  });

  it('web 模式契约：门禁初值绑定 !isTauri（jsdom 无 Tauri 标记时同步渲染）', async () => {
    // 上两例已覆盖桌面两档；本用例锁定 web 初值不被改坏（源码字面契约）。
    const fs = await import('node:fs');
    const src = fs.readFileSync('src/App.tsx', 'utf8');
    expect(src).toMatch(/useState\(!tauriBridge\.isTauri\)/);
  });
});
