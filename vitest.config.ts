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
    // [audit-FIX 2026-09-13] NODE_ENV=test 强制注入：本机裸跑 `npm test` 时 vitest worker 未带
    // NODE_ENV，jsdom 内 React 被解析为 production build → `act(...) is not supported in
    // production builds` 导致 246/263 用例批量假失败（NODE_ENV=test 时 263/263 全过，实测）。
    // CI（GITHUB_ACTIONS）环境 vitest 自带 NODE_ENV=test，此行无副作用。
    env: { NODE_ENV: 'test' },
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
        // [2026-09-18 数据刷新] 实测：stmts 91.11 / branch 80.01 / func 72.01 / lines 91.11。
        // 阈值仍按「实测 − 约 3pt」留余量，防止前端任何一处小改动就让 CI 假红。
        //
        // 【为什么 func 阈值刻意不跟涨 —— 别按 stmts 的规则去"修"它】
        // 本轮把 func 从 70.64 提到 72.01（+1.37pt）只用了 4 个函数（21 条用例），
        // 按 293 个函数折算恰好是 4/293 = 1.37pt，即**覆盖面每一处都落在真逻辑上**。
        // 但同期统计：剩余 82 个未覆盖函数里 **69 个是 JSX 内联事件处理器**
        // （onChange/onClick/onClose 之类，见 src/components/SqlmapOptions.tsx 单文件 21 个），
        // 真正带分支逻辑的仅剩约 13 个。
        // 结论：func% 这个指标在本项目里**主要反映"组件里写了多少内联箭头函数"**，
        // 而不是逻辑质量 —— 每新增一个组件它就会自然下跌。把它按 stmts 的 −3pt 规则跟着涨，
        // 等于要求为 JSX 样板写测试（负收益），且会持续制造假红。
        // 故：func 保持宽松余量；想验真实逻辑盲区请看 stmts/branch/lines。
        statements: 88,
        branches: 77,
        functions: 67,
        lines: 88,
      },
    },
  },
});

