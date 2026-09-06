// QA 独立验证（严过关）：F-18 暗色主题。
// 通过真实渲染 <App/>（含 AppThemeProvider + TopBar 三态切换）验证：
//  - localStorage['sqli_theme'] 缺失时回退默认 light 并持久化
//  - 写入后能读回（dark 被选中），点击可切回 light（写回）
//  - system 模式调用 matchMedia 且跟随系统暗色
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import App from '../App';

// jsdom 无 matchMedia，提供可控桩
function mockMatchMedia(matches: boolean) {
  const mql = {
    matches,
    media: '(prefers-color-scheme: dark)',
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => true,
  };
  const spy = vi.fn(() => mql);
  vi.stubGlobal('matchMedia', spy);
  return spy;
}

beforeEach(() => {
  localStorage.clear();
  // 已接受过首启免责声明（S19）：主题测试关注主题逻辑，应用需正常进入
  localStorage.setItem('sqli_disclaimer', '1');
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('F-18 暗色主题', () => {
  it('缺失 sqli_theme 时回退默认 light 并持久化到 localStorage', () => {
    mockMatchMedia(false);
    render(<App />);
    // 挂载后持久化默认 light
    expect(localStorage.getItem('sqli_theme')).toBe('light');
    // 浅色按钮被选中
    expect(screen.getByRole('button', { name: 'Light theme' }).getAttribute('aria-pressed')).toBe('true');
    // 非暗色：body 不应有暗色背景（MUI 的 emotion 全局样式常驻 head，检查 body 样式更可靠）
    expect(getComputedStyle(document.body).backgroundColor).not.toBe('rgb(15, 23, 42)');
  });

  it('写入 dark 后能读回，点击可切回 light（写回 localStorage）', () => {
    localStorage.setItem('sqli_theme', 'dark');
    mockMatchMedia(false);
    render(<App />);
    // 读回：dark 按钮被选中
    expect(screen.getByRole('button', { name: 'Dark theme' }).getAttribute('aria-pressed')).toBe('true');
    // 暗色主题应用到站点（head 含 #0f172a 暗色背景）
    expect(document.head.innerHTML.toLowerCase()).toContain('0f172a');
    // 点击浅色 → 切回 light 并写回
    act(() => {
      fireEvent.click(screen.getByRole('button', { name: 'Light theme' }));
    });
    expect(localStorage.getItem('sqli_theme')).toBe('light');
    expect(screen.getByRole('button', { name: 'Light theme' }).getAttribute('aria-pressed')).toBe('true');
  });

  it('system 模式调用 matchMedia 且跟随系统暗色', () => {
    localStorage.setItem('sqli_theme', 'system');
    const spy = mockMatchMedia(true); // 模拟系统为暗色
    render(<App />);
    // system 模式确实查询了系统配色
    expect(spy).toHaveBeenCalledWith('(prefers-color-scheme: dark)');
    expect(screen.getByRole('button', { name: 'System theme' }).getAttribute('aria-pressed')).toBe('true');
    // 系统暗色 → 实际渲染暗色主题
    expect(document.head.innerHTML.toLowerCase()).toContain('0f172a');
  });
});
