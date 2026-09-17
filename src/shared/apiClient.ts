import axios from 'axios';
import type { ApiResponse, ExploitTarget, ExploitResult, ExploitCapabilities, TamperInfo } from './types';

/**
 * 携带后端错误码的异常类。
 * 替代直接抛 `new Error(message)`，确保 ApiResponse.code 在拦截器中不丢失，
 * 前端 catch 块可通过 `e.code` 判断错误类型以决定行为（重试 vs 提示 vs 跳转）。
 */
export class ApiError extends Error {
  code: number;
  constructor(code: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
  }
}

// 前端 API base：Web 版为 /api（同源代理），Tauri 版为 http://127.0.0.1:4567。
// [A3 2026-09-17] 运行期可覆盖：桌面版由 Rust sidecar 告知实际端口（4567 被占时随机端口），
// 前端启动时经 tauriBridge.getEngineInfo() 调 setApiBase()，不再依赖编译期常量。
export const API_BASE: string =
  (import.meta.env.VITE_API_BASE as string | undefined) ?? '/api';
let runtimeBase: string | null = null;
export function setApiBase(base: string): void {
  runtimeBase = base;
}
export function getApiBase(): string {
  return runtimeBase || API_BASE;
}

// Token 来源优先级：运行期注入（Tauri sidecar 一次性 token）→ 编译期 env → localStorage。
// 后端设置 SCAN_API_TOKEN 后，前端需携带此 token 否则全 401。
let runtimeToken: string | null = null;
export function setApiToken(token: string): void {
  const v = String(token || '').trim();
  runtimeToken = v || null;
  try {
    if (v) localStorage.setItem('scanApiToken', v);
    else localStorage.removeItem('scanApiToken');
  } catch { /* localStorage 不可用（隐私模式）时仅内存生效 */ }
}
export function getApiToken(): string {
  const envToken = import.meta.env.VITE_SCAN_API_TOKEN as string | undefined;
  if (envToken) return envToken;
  if (runtimeToken) return runtimeToken;
  try {
    return localStorage.getItem('scanApiToken') || '';
  } catch {
    return '';
  }
}

// axios 实例：统一超时与响应解包
const http = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

// 请求拦截：注入 API Token（对标后端 SCAN_API_TOKEN 中间件）+ 运行期 baseURL
http.interceptors.request.use((config) => {
  config.baseURL = getApiBase();
  const token = getApiToken();
  if (token) {
    config.headers = config.headers || {};
    config.headers['x-api-token'] = token;
  }
  return config;
});

// 响应拦截：统一解包 {code,data,message}，非 0 抛 ApiError（保留 code 供前端决策）
http.interceptors.response.use(
  (response) => {
    const body = response.data as ApiResponse<unknown>;
    if (body && typeof body.code === 'number' && body.code !== 0) {
      return Promise.reject(new ApiError(body.code, body.message || '请求失败'));
    }
    return response;
  },
  (error) => {
    // [A2 2026-09-17] 401 引导：引擎启用鉴权（非回环部署会强制启用）而前端还没 token 时，
    // 弹一次输入并原样重放该请求——否则用户看到的是一串无上下文的 401。
    // 仅在真实浏览器、且当前确实没有 token、且未提示过该请求时触发（防无限循环）。
    const status = error?.response?.status;
    const cfg = error?.config;
    const canPrompt =
      typeof window !== 'undefined' &&
      typeof (window as any).prompt === 'function' &&
      import.meta.env.MODE !== 'test';
    if (status === 401 && cfg && !cfg.__tokenPrompted && !getApiToken() && canPrompt) {
      cfg.__tokenPrompted = true;
      const input = (window as any).prompt(
        '引擎已启用 API 鉴权，请输入 SCAN_API_TOKEN（将保存在本机 localStorage）'
      );
      if (input && String(input).trim()) {
        setApiToken(String(input).trim());
        cfg.baseURL = getApiBase();
        cfg.headers = cfg.headers || {};
        cfg.headers['x-api-token'] = getApiToken();
        return http.request(cfg);
      }
    }
    // 优先从响应体提取 code + message（后端统一 { code, data, message } 包装）
    const body = error?.response?.data;
    if (body && typeof body.code === 'number') {
      return Promise.reject(new ApiError(body.code, body.message || '请求失败'));
    }
    // 网络层错误（无响应体）—— code=-1 表示非业务错误码
    const msg = body?.message || error?.message || '网络错误';
    return Promise.reject(new ApiError(-1, msg));
  }
);

// 业务封装：自动解包 data
export const apiClient = {
  async get<T>(url: string, config?: object): Promise<T> {
    const res = await http.get<ApiResponse<T>>(url, config);
    return res.data.data as T;
  },
  async post<T>(url: string, data?: object, config?: object): Promise<T> {
    const res = await http.post<ApiResponse<T>>(url, data, config);
    return res.data.data as T;
  },
  // tamper 清单（GET /api/tampers，单一事实源，与 TamperRegistry.list() 一致）
  tampers: () => apiClient.get<TamperInfo[]>('/tampers'),
  // AI 报告生成
  report: {
    /** 生成 AI 漏洞分析报告（POST /api/scan/:id/report/ai） */
    ai: (scanId: string, config?: { keyIndex?: number; modelIndex?: number }) =>
      apiClient.post<{ success: boolean; model: string; content: string; usage?: object }>(
        `/scan/${scanId}/report/ai`, config || {}),
    /** 列出可用 AI 模型组合（GET /api/scan/:id/report/ai/configs） */
    aiConfigs: (scanId: string) =>
      apiClient.get<{ keyIndex: number; modelIndex: number; label: string; model: string }[]>(
        `/scan/${scanId}/report/ai/configs`),
  },
};

// 利用端点客户端（sql-shell / file-read / file-write / os-shell / capabilities）
export const exploitClient = {
  capabilities: () => apiClient.get<ExploitCapabilities>('/exploit/capabilities'),
  sqlShell: (req: ExploitTarget & { sql: string }) =>
    apiClient.post<ExploitResult>('/exploit/sql', req),
  fileRead: (req: ExploitTarget & { path: string }) =>
    apiClient.post<ExploitResult>('/exploit/file-read', req),
  fileWrite: (req: ExploitTarget & { content: string; remotePath: string }) =>
    apiClient.post<ExploitResult>('/exploit/file-write', req),
  osShell: (req: ExploitTarget & { cmd: string }) =>
    apiClient.post<ExploitResult>('/exploit/os-shell', req),
};

// sqlmap 高级模式客户端（P1-U1：status 预检）
export interface SqlmapStatus {
  available: boolean;
  maxConcurrent: number;
}
export const sqlmapClient = {
  status: () => apiClient.get<SqlmapStatus>('/sqlmap/status'),
};

export default apiClient;
