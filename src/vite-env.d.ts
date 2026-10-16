/// <reference types="vite/client" />

// 声明 VITE_API_BASE 环境变量类型
interface ImportMetaEnv {
  readonly VITE_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

// [D85] 版本号构建期常量（vite.config.ts define 注入，单一来源 package.json）
declare const __APP_VERSION__: string;
