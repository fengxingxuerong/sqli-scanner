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
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          // React 核心
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          // MUI 核心（icons 独立 chunk：体积大但变更少，独立缓存避免应用代码更新使其失效）
          'mui-vendor': ['@mui/material', '@emotion/react', '@emotion/styled'],
          'mui-icons': ['@mui/icons-material'],
          // i18n
          'i18n-vendor': ['i18next', 'react-i18next'],
          // 状态管理
          'state-vendor': ['zustand'],
        },
      },
    },
    // 压缩提示
    minify: 'esbuild',
    sourcemap: false,
  },
});