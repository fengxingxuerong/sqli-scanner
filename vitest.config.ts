import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// 前端单元测试配置：jsdom 环境 + React 插件
// [P0-FIX] 并行策略按环境区分：CI（GITHUB_ACTIONS=1）恢复文件级并行提速；
// 本地默认保持串行（规避本机 jsdom 偶发挂起/worker 意外退出的历史问题）。
const IS_CI = process.env.GITHUB_ACTIONS === 'true' || process.env.CI === 'true';
export default defineConfig({
  plugins: [react()],
  // Tauri 插件（plugin-dialog / plugin-fs）未在本地安装，桌面分支单测经
  // alias 指向测试桩（stubs/），Web 构建不受影响（此配置仅在 vitest 生效）。
  resolve: {
    alias: {
      '@tauri-apps/plugin-dialog': path.resolve(
        __dirname,
        'src/tests/stubs/tauriPluginDialog.ts'
      ),
      '@tauri-apps/plugin-fs': path.resolve(
        __dirname,
        'src/tests/stubs/tauriPluginFs.ts'
      ),
    },
  },
  test: {
    environment: 'jsdom',
    globals: false,
    setupFiles: ['./vitest.setup.ts'],
    include: ['src/tests/**/*.{test,spec}.{ts,tsx}'],
    // 单文件串行执行：本机 jsdom + 多个测试文件并行时偶发挂起（进程不退），
    // 关闭文件级并行避免挂起；单文件内部用例仍按默认并行运行。
    // CI 环境恢复并行以缩短流水线耗时（需排除偶发挂起已解决的环境）。
    fileParallelism: IS_CI,
    // 线程池单线程：默认 forks 池在本机偶发 worker 子进程意外退出（tinypool
    // "Worker exited unexpectedly"）导致整轮崩溃；threads+singleThread 稳定通过。
    // CI 使用默认 forks 池（多 worker 并行），本地保持单线程稳定。
    pool: IS_CI ? 'forks' : 'threads',
    poolOptions: IS_CI
      ? {}
      : {
          threads: { singleThread: true },
        },
    coverage: {
      provider: 'v8',
      // 只统计前端业务源码，排除测试/配置/类型声明（v8 provider 默认已忽略 node_modules）
      include: ['src/**/*.{ts,tsx}'],
      exclude: [
        'src/tests/**',
        '**/*.d.ts',
        // main.tsx 为应用引导（createRoot + 挂载），已由 appMount.smoke 覆盖行为，不计入门禁
        'src/main.tsx',
      ],
      reporter: ['text', 'json', 'html'],
      reportsDirectory: './coverage',
      thresholds: {
        // 2026-09-03 补测（ErrorBoundary/tauriBridge 桌面分支/apiClient 错误体系/
        // progressUtils/StatCardGroup/ScanConfigPanel 认证区/i18n 一致性）后收紧
        // （实测 stmts 93.4 / branch 80.5 / func 72.0）：阈值留 ~3pt 余量防回退
        statements: 90,
        branches: 77,
        functions: 69,
        lines: 90,
      },
    },
  },
});

