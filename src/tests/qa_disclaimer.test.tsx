// QA 独立验证：S19 首启一次性免责声明 Dialog。
// 通过真实渲染 <App/> 验证：
//  - localStorage['sqli_disclaimer'] 缺失 → 首启弹声明，未勾选时「进入应用」禁用、业务内容不渲染
//  - 勾选「已知晓」→ 可进入，写入 localStorage['sqli_disclaimer']='1'，声明关闭、应用正常渲染
//  - 已接受过声明 → 不再弹出，直接进入应用
//
// 懒加载适配：ScanPage 已改为 React.lazy（router.tsx 内 Suspense 承接），页面内容
// 需用 findBy* 异步等待；Dialog 退出过渡改由真实定时器驱动（waitFor 轮询），
// 不再依赖假定时器 + advanceTimersByTime。
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import App from '../App';

// jsdom 无 matchMedia，提供可控桩（AppThemeProvider 需要）
function mockMatchMedia() {
  const mql = {
    matches: false,
    media: '(prefers-color-scheme: dark)',
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => true,
  };
  vi.stubGlobal('matchMedia', vi.fn(() => mql));
}

beforeEach(() => {
  localStorage.clear();
  mockMatchMedia();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('S19 首启一次性免责声明', () => {
  it('未接受声明：Dialog 出现、未勾选时按钮禁用、业务内容不渲染', () => {
    render(<App />);
    expect(screen.getByText('安全使用须知')).toBeTruthy();
    // 关键合规文案
    expect(screen.getByText(/仅限在已获得授权的环境中使用/)).toBeTruthy();
    expect(screen.getByText(/我已阅读并知晓以上内容/)).toBeTruthy();
    // 未勾选 → 确认按钮禁用，无法进入
    const enterBtn = screen.getByRole('button', { name: '进入应用' }) as HTMLButtonElement;
    expect(enterBtn.disabled).toBe(true);
    // 业务内容（顶栏 / 扫描页）被拦截，未渲染
    expect(screen.queryByText('扫描')).toBeNull();
    expect(screen.queryByRole('button', { name: '开始扫描' })).toBeNull();
  });

  it('勾选「已知晓」后写入 localStorage，声明关闭、应用正常进入', async () => {
    render(<App />);
    fireEvent.click(screen.getByRole('checkbox'));
    const enterBtn = screen.getByRole('button', { name: '进入应用' }) as HTMLButtonElement;
    expect(enterBtn.disabled).toBe(false);
    fireEvent.click(enterBtn);
    // 持久化：之后不再弹出
    expect(localStorage.getItem('sqli_disclaimer')).toBe('1');
    // 应用正常渲染：顶栏（同步加载）即时可见；默认扫描页为懒加载，异步等待
    expect(screen.getByText('扫描')).toBeTruthy();
    expect(await screen.findByRole('button', { name: '开始扫描' })).toBeTruthy();
    // 等待 Dialog 退出过渡结束（默认退出时长 <225ms）后从 DOM 卸载
    await waitFor(() => expect(screen.queryByText('安全使用须知')).toBeNull());
  });

  it('已接受过声明：不再弹出，直接进入应用', async () => {
    localStorage.setItem('sqli_disclaimer', '1');
    render(<App />);
    expect(screen.queryByText('安全使用须知')).toBeNull();
    // 扫描页为懒加载，异步等待
    expect(await screen.findByRole('button', { name: '开始扫描' })).toBeTruthy();
  });
});
