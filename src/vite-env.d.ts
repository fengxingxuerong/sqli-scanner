/// <reference types="vite/client" />

// 声明 VITE_API_BASE 环境变量类型
interface ImportMetaEnv {
  readonly VITE_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
