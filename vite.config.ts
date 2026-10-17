import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath, URL } from 'node:url';
import { version } from './package.json';

// Vite 配置：开发期将 /api 代理到本地检测引擎（端口 4567）
export default defineConfig({
  plugins: [react()],
  // [D85] 版本号构建期注入：单一来源是 package.json（与 version:check 门禁同源），
  // 前端 TopBar 版本角标消费 __APP_VERSION__（类型声明见 src/vite-env.d.ts）。
  define: {
    __APP_VERSION__: JSON.stringify(version),
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    port: 5173,
    // [D86 修白屏] 本机 localhost 优先解析 IPv6（::1），vite 默认只听 ::1 ⇒ Tauri
    // 桌面端 devUrl（http://localhost:5173）的 WebView2 走 IPv4 连不上 ⇒ 纯白板。
    // 显式绑 127.0.0.1：IPv4/IPv6 回环客户端都能连（::1 客户端会 fallback 到 v4），
    // 且不开 0.0.0.0（不暴露局域网）。strictPort 防端口被占时静默漂移。
    host: '127.0.0.1',
    strictPort: true,
    // Tauri 桌面开发（tauri dev）：cargo 会持续写 src-tauri/target/debug/deps/*.dll，
    // vite 的文件监视与它对撞 ⇒ Windows 上 EBUSY（-4082）直接崩掉 beforeDevCommand，
    // 表现为「tauri dev 起不来、\`The beforeDevCommand terminated with a non-zero status code\`」。
    // 排除后 watcher 不再碰构建产物目录（只影响 dev 期热更新监听，不影响代理与构建）。
    watch: {
      ignored: ['**/src-tauri/target/**', '**/node_modules/**', '**/dist/**'],
    },
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