import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import ErrorBoundary from '../components/ErrorBoundary';

// 故意抛错的子组件（模拟渲染期异常）
function Bomb({ message }: { message?: string }) {
  throw new Error(message ?? 'boom-render');
}

// React 会把组件树渲染异常打到 console.error，测试中静音避免噪音
let errSpy: ReturnType<typeof vi.spyOn>;

afterEach(() => {
  errSpy?.mockRestore();
});

describe('ErrorBoundary 全局错误边界', () => {
  it('无异常时直接渲染 children（不拦截）', () => {
    render(
      <ErrorBoundary>
        <div>content-ok</div>
      </ErrorBoundary>
    );
    expect(screen.getByText('content-ok')).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('子组件抛错时渲染降级 UI（错误信息 + 刷新按钮），不白屏', () => {
    errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(
      <ErrorBoundary>
        <Bomb message=" boom-render " />
      </ErrorBoundary>
    );
    expect(screen.getByText(/boom-render/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /刷新页面/ })).toBeInTheDocument();
    // 错误信息渲染在 Alert 内
    expect(screen.getByText(/boom-render/).closest('.MuiAlert-root')).not.toBeNull();
  });

  it('componentDidCatch 记录错误（console.error 携带 error 与 errorInfo）', () => {
    errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    render(
      <ErrorBoundary>
        <Bomb message="logged-error" />
      </ErrorBoundary>
    );
    expect(errSpy).toHaveBeenCalled();
    const logged = errSpy.mock.calls.flat().map(String).join(' ');
    expect(logged).toContain('logged-error');
  });

  it('点击「刷新页面」重置错误状态（hasError 复位 → children 恢复渲染）', () => {
    errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    // 子组件可控抛错：点击刷新后停止抛错，若 handleReload 未重置 hasError，
    // 边界不会重新渲染 children，'recovered' 就不会出现
    let shouldThrow = true;
    function MaybeBomb(): JSX.Element {
      if (shouldThrow) throw new Error('toggle-boom');
      return <div>recovered</div>;
    }
    render(
      <ErrorBoundary>
        <MaybeBomb />
      </ErrorBoundary>
    );
    expect(screen.getByText(/toggle-boom/)).toBeInTheDocument();

    shouldThrow = false;
    fireEvent.click(screen.getByRole('button', { name: /刷新页面/ }));
    // hasError 已重置 → children 重新渲染成功
    expect(screen.getByText('recovered')).toBeInTheDocument();
    expect(screen.queryByText(/toggle-boom/)).not.toBeInTheDocument();
  });

  it('error.message 为空时降级 UI 回退到通用错误标题', () => {
    errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    // 模拟一个没有 message 的错误对象
    function EmptyError(): never {
      throw Object.assign(new Error(), { message: '' });
    }
    render(
      <ErrorBoundary>
        <EmptyError />
      </ErrorBoundary>
    );
    // common.pageErrorTitle = 「页面渲染异常」
    expect(screen.getByText('页面渲染异常')).toBeInTheDocument();
  });
});
