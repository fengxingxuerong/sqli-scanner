import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import App from '../App';

/**
 * 挂载级冒烟测试 —— 防「整页白屏」回归护栏。
 *
 * 历史教训：P2 阶段曾把 TopBar 放在 RouterProvider 之外，而 TopBar 内部调用
 * useLocation()，导致挂载即抛 "useLocation() may be used only in the context of a
 * <Router>"，整棵 <App/> 无法渲染（扫描/历史/报告三页全白屏）。该 Bug 在组件级
 * 单测中无法暴露（编译期不报错、孤立组件不涉及 Router 上下文），只有真正挂载
 * <App/> 才会触发。
 *
 * 本测试挂载完整 <App/>：若 TopBar 被再次移出 Router 上下文，render 将抛错，
 * 测试失败，从而把此类接线 Bug 挡在 CI 之前。
 */
describe('App 挂载冒烟（防整页白屏回归）', () => {
  it('挂载 <App/> 不抛错，顶栏(依赖 useLocation)与默认扫描页均正常渲染', () => {
    // render 本身即护栏：TopBar 在 Router 外时此处会抛错
    render(<App />);

    // 顶栏导航依赖 useLocation，能渲染即证明 TopBar 处于 Router 上下文内
    expect(screen.getByText('新建扫描')).toBeTruthy();
    expect(screen.getByText('历史')).toBeTruthy();

    // 主题切换三态按钮（证明 TopBar 完整渲染）
    expect(screen.getByRole('button', { name: '浅色' })).toBeTruthy();
    expect(screen.getByRole('button', { name: '跟随系统' })).toBeTruthy();
    expect(screen.getByRole('button', { name: '暗色' })).toBeTruthy();

    // 默认路由 "/" 渲染 ScanPage
    expect(screen.getByRole('button', { name: '开始扫描' })).toBeTruthy();
  });
});
