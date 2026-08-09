import axios from 'axios';
import type { ApiResponse, ExploitTarget, ExploitResult, ExploitCapabilities, TamperInfo } from './types';

// 前端 API base：Web 版为 /api（同源代理），Tauri 版为 http://127.0.0.1:4567
export const API_BASE: string =
  (import.meta.env.VITE_API_BASE as string | undefined) ?? '/api';

// axios 实例：统一超时与响应解包
const http = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
});

// 响应拦截：统一解包 {code,data,message}，非 0 抛错
http.interceptors.response.use(
  (response) => {
    const body = response.data as ApiResponse<unknown>;
    if (body && typeof body.code === 'number' && body.code !== 0) {
      return Promise.reject(new Error(body.message || '请求失败'));
    }
    return response;
  },
  (error) => {
    const msg =
      error?.response?.data?.message || error?.message || '网络错误';
    return Promise.reject(new Error(msg));
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

export default apiClient;
