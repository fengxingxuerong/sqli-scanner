import '@testing-library/jest-dom/vitest';
import { afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';
import './src/i18n/index';

// 每个用例结束后清理渲染到 document.body 的组件，避免 DOM 累积导致 getByText 命中多个元素
afterEach(() => {
  cleanup();
});
