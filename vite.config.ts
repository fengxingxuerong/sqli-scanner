import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';

// Vite 配置：开发期将 /api 代理到本地检测引擎（端口 4567）
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:4567',
        changeOrigin: true,
      },
    },
  },
  // Tauri 构建时通过 .env.tauri 注入 VITE_API_BASE=http://127.0.0.1:4567
  envPrefix: ['VITE_'],
});
