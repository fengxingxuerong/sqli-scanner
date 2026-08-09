import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// 前端单元测试配置：jsdom 环境 + React 插件
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: false,
    setupFiles: ['./vitest.setup.ts'],
    include: ['src/tests/**/*.{test,spec}.{ts,tsx}'],
    coverage: {
      provider: 'v8',
    },
  },
});
