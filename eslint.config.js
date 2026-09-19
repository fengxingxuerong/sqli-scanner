// ESLint flat config（eslint v9+/v10 原生格式）
// 规则策略：克制。error 级只保留「真正有价值的」——未使用变量、明显 bug 类规则、
// react-hooks 钩子规则；exhaustive-deps 等启发式规则降为 warn，避免过度阻塞。
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';

// 各类文件的全局环境：
//  - 前端 src/ 与 vite/vitest 配置：浏览器全局（含 vitest 测试全局）
//  - server/ 引擎、e2e、根级 mjs 脚本：Node 全局
const browserEnv = { ...globals.browser, ...globals.es2021 };
const nodeEnv = { ...globals.node, ...globals.es2021 };
const testEnv = { ...globals.vitest };

export default [
  // 1) 全局忽略：构建产物、依赖、日志、Tauri 壳、编辑器/OS 噪音
  {
    ignores: [
      'node_modules/**',
      'server/node_modules/**',
      'dist/**',
      'server/dist/**',
      'server/dist-engine/**',
      'src-tauri/**',
      '**/*.d.ts',
      '**/.trash/**',
      // 一次性排障脚本目录（e2e/diag）：不入库也不参与 lint
      'e2e/diag/**',
      // [LINT-FIX 2026-09-19] 原先这里另有 9 条目录/文件级 ignore（multi-engine-lab / ntlm-lab /
      // oob-real-lab / redteam-lab / retest-lab / waf-real / acceptance.mjs / l46-fp-stage /
      // verify-tamper-breakage），理由是「子代理引入的 unused import 不阻塞主 CI」。
      // 问题不在理由，在于**挡住的正是门禁自己**：`e2e/acceptance.mjs` 是全方位验收总控，
      // 被整文件 ignore 后它的语法/未定义变量错误没人检查 —— 门禁脚本裸奔。
      // 本批全部纳回并逐条清零（子代理 18 条 + 本批 7 条 no-unused-vars），目录级豁免只剩上面
      // 那条 e2e/diag。**今后 lint 报错要修，不要再加 ignore**；真要豁免请精确到单个文件并写明理由。
      'fix-eslint.mjs',
      'logs/**',
      'server/logs/**',
      '*.log',
      '*.timestamp-*.mjs',
      // scratch / 调试脚本（不入库，gitignore 已排除，无需 lint）
      'debug-target.mjs',
      'live-scan-demo.mjs',
    ],
  },

  // 2) 全量基础：对 JS/TS 统一开启的核心 bug 类规则
  {
    files: ['**/*.{js,mjs,cjs,ts,tsx}'],
    rules: {
      // 明显 bug 类（error）
      'no-const-assign': 'error', // 给 const 重新赋值
      'no-dupe-args': 'error', // 函数重复参数名
      'no-dupe-class-members': 'error', // 类成员重复定义
      'no-dupe-keys': 'error', // 对象字面量重复键
      'no-obj-calls': 'error', // 把 Math/JSON 当函数调用
      'no-cond-assign': 'error', // 条件中赋值
      'no-duplicate-case': 'error', // switch 重复 case
      'no-func-assign': 'error', // 对函数名赋值
      'no-unreachable': 'error', // 不可达代码
      // 未使用变量（error，新代码必须干净；存量问题单独清）
      'no-unused-vars': 'off', // JS 与 TS 各自单独开启，见下
    },
  },

  // 3) 纯 JS 文件（server 引擎 + 根级脚本 + e2e + 配置）：Node 环境
  {
    files: ['**/*.{js,mjs,cjs}', 'server/**/*.js', 'e2e/**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: nodeEnv,
    },
    rules: {
      'no-undef': 'error',
      // 未用变量保持 error（真正有价值）；未用参数不检查——
      // 策略类接口（如 tamper 插件 transform(payload, ctx)）的占位参数是常态。
      // ignoreRestSiblings —— 与 TS 侧一致：允许 { auth, proxy, ...rest } = obj
      // 这类「剥离敏感字段后再落盘」的 rest 排除模式（P1-1 脱敏用），避免误报。
      'no-unused-vars': ['error', { args: 'none', caughtErrors: 'none', ignoreRestSiblings: true }],
    },
  },

  // 4) server 测试（node:test）：补充 vitest 无关，纯 Node，已含在上一条

  // 5) TypeScript / TSX（前端 src/ + vite/vitest 配置）：
  //    typescript-eslint 负责类型层面规则，no-undef 交给 TS 编译器兜底（避免误报）
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: { sourceType: 'module' },
      globals: { ...browserEnv, ...testEnv },
    },
    plugins: {
      '@typescript-eslint': tseslint.plugin,
      'react-hooks': reactHooks,
    },
    rules: {
      ...tseslint.configs.recommended.rules,
      'no-undef': 'off', // TS 内置检查更强，避免误报
      'no-unused-vars': 'off', // 由 TS 专用规则接管
      '@typescript-eslint/no-unused-vars': [
        'error',
        // args: 'none' —— 同上，策略类接口占位参数不检查；caughtErrors 同理
        // ignoreRestSiblings —— 允许 const { auth, proxy, ...rest } = obj 这类
        // 「剥离敏感字段后再落盘」的 rest 排除模式（P1-U8 脱敏用），避免误报
        { args: 'none', caughtErrors: 'none', ignoreRestSiblings: true },
      ],
      // 去掉 recommended 里偏严格/低价值的规则
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-empty-object-type': 'off',
      '@typescript-eslint/no-require-imports': 'off',
      '@typescript-eslint/no-unused-expressions': 'warn',
      // React Hooks：钩子调用顺序为 error，依赖数组为 warn
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
    },
  },

  // 6) 测试文件（前端 vitest + server node:test）：测试里常有未用桩变量/占位变量，
  //    降为 warn 避免阻塞；bug 类规则仍保留 error
  {
    files: ['src/tests/**/*.{ts,tsx}'],
    plugins: {
      '@typescript-eslint': tseslint.plugin,
    },
    rules: {
      '@typescript-eslint/no-unused-vars': 'warn',
    },
  },
  {
    files: ['server/tests/**/*.js'],
    rules: {
      'no-unused-vars': 'warn',
    },
  },
];
