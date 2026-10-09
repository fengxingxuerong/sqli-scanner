// ESLint flat config（eslint v9+/v10 原生格式）
// 规则策略（2026-10-09 D25 改版）：**基线 = eslint:recommended 全集**，只对本仓实测证明
// 「会产出噪音而不是缺陷」的规则逐条开例外并写明理由；例外必须是少数、可核、带实测数字。
// 改版前这里是「手挑 12 条 bug 规则」，实测差距：recommended 全集在本仓只暴 8 个族 229 处，
// 其中 6 个族是合法惯用法（见下例外），2 个族（no-sparse-arrays / preserve-caught-error）
// 是真该修的 ⇒ 修 7 处，换来约 45 条规则的后续保护（含 no-dupe-else-if —— 批次 D21 那个
// `--random-agent` 重复分支缺陷，正是这条规则要抓的形状）。
import js from '@eslint/js';
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
      // [D25 2026-10-09] **lint 的作用域必须等于仓库**。实测改版前 `eslint .` 处理 1128 个文件，
      // 其中 **35 个根本没入库**：`.box-agent-scratch/**`（上一次拆分的旧副本，里面躺着
      // ScanManager.orig.js 与几份 `*.new.js`）、`.workbuddy/tmp/**`（Exploiter.bak.js 等备份）、
      // `.mock/**`、`.acl-recovery/**`、`kanban-check-*/**`。后果不是"多扫了不相干的文件"这么轻：
      // 门禁的红绿会取决于**本机磁盘上恰好躺着哪些排障现场**，而 recommended 全集一开，
      // 这些旧副本立刻暴出 5 处违规 —— 那既不是仓库的问题，也不该由仓库修。
      // 上面 29–35 行的历史教训是「不要为了躲报错而加 ignore」；这里相反：
      // 被 ignore 的都不是入库文件，且新增一条就有 `server/tests/lintScope.guard.test.js`
      // 反向钉住「任何入库代码文件都不许被 ignore 吞掉」。
      '.box-agent-scratch/**',
      '.workbuddy/**',
      '.mock/**',
      '.acl-recovery/**',
      'kanban-check-*/**',
      '.tmp-chk/**',
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
      // [2026-10-05] 排障/注入验证用的临时脚本统一用 .tmp-* 前缀（.gitignore 已覆盖，
      // 不会被提交）。此前是逐个文件名加 ignore（fix-eslint.mjs / debug-target.mjs 等），
      // 那种做法必然漏：每写一个新临时脚本就会让 `npm run lint` 假红，而这类假红很
      // 容易被误当成"代码有问题"，或被加 ignore 绕过 —— 与第 29-35 行记录的历史教训同型。
      // 故改成通配符覆盖整个临时文件族。
      '.tmp-*',
      '**/.tmp-*',
    ],
  },

  // 2) 全量基础：recommended 全集 + 本仓实测例外（例外逐条带理由与数字）
  {
    files: ['**/*.{js,mjs,cjs,ts,tsx}'],
    rules: {
      ...js.configs.recommended.rules,
      // 明显 bug 类（error）—— 保留显式声明，recommended 之后仍可逐条覆盖
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

      // ── 例外（每条都是"实测过它在本仓产出的是噪音而不是缺陷"）──────────────────
      'no-useless-assignment': 'off',
      // 实测 98 处、65 处在 server/src：全是 `let x = 初值; try { x = await … } catch { x = 兜底 }`
      // 这种两条分支都赋值的形状。改掉不修任何缺陷，只制造 98 处无意义改动，
      // 而且改错一处就是把兜底路径丢掉。
      'no-irregular-whitespace': 'off',
      // 实测 86 处全是 U+3000 全角空格，用在报告文案的排版分隔。另跑了一次定向探针：
      // 1093 个入库代码文件里 **0 处**全角空格落进比较/匹配语句 ⇒ 它现在不掩盖任何断言，
      // 开这条只会逼人把中文排版改成半角。
      'no-control-regex': 'off',
      // 实测 11 处：WAF/tamper 与协议解析**刻意**构造控制字节（本仓的被测对象之一就是
      // 带 \x00 的请求），报的全是设计。
      'no-regex-spaces': 'off',
      // 实测 4 处里 3 处**就是要匹配两个空格**：`tamper.tokenBoundary` 的"不叠出双空格"判据、
      // `ciNightlyEngine` 的 YAML 缩进锚点。这条规则在这里是反语义的。
      'no-fallthrough': 'off',
      // 实测唯一命中在 `DialectSqlBuilder.escCols`：分支全部以 return 收尾，只是 case 之间夹了
      // 长取证注释。已用最小复现证明 eslint 把"只有注释的 case"当作有语句而报（见 CHANGELOG D25）
      // ⇒ 开它等于逼人把取证注释搬走，那是反收益。
      'no-useless-escape': 'off',
      // 实测 13 处里 7 处在 `[^:\[\]]` / 反引号双引号方括号 这类字符类里 —— 转义多余但更好读
      // （含 scopeGuard 的主机端口解析，动它的正则本身才是风险）。
      // ⚠️ 但本批**真缺陷**正是这条规则报出来的：3 个 tamper 插件把 Python 的 `\Z`（串尾）
      // 抄进 JS 正则，JS 里它是字面字母 Z ⇒ 句尾关键词永不变形。规则没开，缺陷已修，
      // 并由 `server/tests/pythonRegexEscapes.guard.test.js` 独立钉住这一族。
      'no-empty': ['error', { allowEmptyCatch: true }],
      // 实测 9 处全是 catch 空块惯用法（URL 解析失败退回 params/body、健康探测失败继续轮询、
      // unlink 尽力而为）⇒ 放行空 catch，仍拦住空的 if/块/循环。
    },
  },

  // 3) 纯 JS 文件（server 引擎 + 根级脚本 + e2e + 配置）：Node 环境
  {
    files: ['**/*.{js,mjs,cjs}', 'server/**/*.js', 'e2e/**/*.js'],
    languageOptions: {
      // [E5-2 2026-09-23] 2022 → 2025：`payloads/registry.json` 用 import attributes 加载
      // （`import data from './x.json' with { type: 'json' }`）。espree 在 2022/2024 下都报
      // `Parsing error: Unexpected token with`（实测 espree 11.2.0），2025 起支持。
      // 运行时（Node 22/24）与 tsc（module: NodeNext）均已实测可用。
      ecmaVersion: 2025,
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
