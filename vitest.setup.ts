import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';

// 每个用例结束后清理渲染到 document.body 的组件，避免 DOM 累积导致 getByText 命中多个元素
afterEach(() => {
  cleanup();
});

// React Flow (@xyflow/react) 渲染依赖 ResizeObserver，jsdom 未实现，需 polyfill 以免用例报错
if (typeof (globalThis as any).ResizeObserver === 'undefined') {
  class ResizeObserverStub {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
  (globalThis as any).ResizeObserver = ResizeObserverStub;
}
