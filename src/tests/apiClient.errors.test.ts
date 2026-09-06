import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as axios from 'axios';
import {
  ApiError,
  apiClient,
  exploitClient,
  sqlmapClient,
} from '../shared/apiClient';

// 与 apiClient.test.ts 相同的桩策略：替换 axios.create 返回的实例，
// 并暴露拦截器处理器供错误路径断言
vi.mock('axios', () => {
  const reqHandlers: any[] = [];
  const resHandlers: any[] = [];
  const instance = {
    interceptors: {
      request: { use: (fn: any) => reqHandlers.push(fn) },
      response: { use: (onOk: any, onErr: any) => { resHandlers.push(onOk, onErr); } },
    },
    get: vi.fn(),
    post: vi.fn(),
  };
  return {
    default: { create: () => instance },
    __instance: instance,
    __resHandlers: resHandlers,
    __reqHandlers: reqHandlers,
  };
});

const mocked = axios as any;

// resHandlers 布局: [成功拦截器, 错误拦截器]
const onOk = () => mocked.__resHandlers[0];
const onErr = () => mocked.__resHandlers[1];

describe('apiClient 错误体系与端点封装', () => {
  beforeEach(() => {
    mocked.__instance.get = vi.fn();
    mocked.__instance.post = vi.fn();
    localStorage.clear();
    vi.unstubAllEnvs();
  });

  it('ApiError 携带业务 code，name 为 ApiError', () => {
    const e = new ApiError(2003, '参数非法');
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe('ApiError');
    expect(e.code).toBe(2003);
    expect(e.message).toBe('参数非法');
  });

  it('HTTP 错误响应体含 code 时抛 ApiError(code, message)', async () => {
    const rejected = onErr()({
      response: { data: { code: 4031, message: 'token 无效' } },
    });
    await expect(rejected).rejects.toMatchObject({ code: 4031, message: 'token 无效' });
  });

  it('HTTP 错误响应体含 code 但无 message 时使用默认文案', async () => {
    const rejected = onErr()({ response: { data: { code: 5000 } } });
    await expect(rejected).rejects.toMatchObject({ code: 5000, message: '请求失败' });
  });

  it('网络层错误（无响应体）抛 ApiError(-1, error.message)', async () => {
    const rejected = onErr()({ message: 'timeout of 30000ms exceeded' });
    await expect(rejected).rejects.toMatchObject({
      code: -1,
      message: 'timeout of 30000ms exceeded',
    });
  });

  it('网络层错误且无 error.message 时回退「网络错误」', async () => {
    const rejected = onErr()({});
    await expect(rejected).rejects.toMatchObject({ code: -1, message: '网络错误' });
  });

  it('响应体非 {code:number} 结构时不误判（code 缺失走透传）', async () => {
    const res = { data: { foo: 'bar' } };
    // 成功拦截器同步返回原响应对象
    expect(onOk()(res)).toBe(res);
  });

  it('请求拦截器：env token 优先于 localStorage token', () => {
    vi.stubEnv('VITE_SCAN_API_TOKEN', 'env-token');
    localStorage.setItem('scanApiToken', 'ls-token');
    const result = mocked.__reqHandlers[0]({ headers: {} });
    expect(result.headers['x-api-token']).toBe('env-token');
  });

  it('请求拦截器：无任何 token 时不注入 header', () => {
    const result = mocked.__reqHandlers[0]({ headers: {} });
    expect(result.headers['x-api-token']).toBeUndefined();
  });

  it('请求拦截器：config.headers 为空对象时安全注入', () => {
    localStorage.setItem('scanApiToken', 'ls-token');
    const result = mocked.__reqHandlers[0]({} as any);
    expect(result.headers['x-api-token']).toBe('ls-token');
  });

  it('exploitClient 五个端点映射到正确 URL', async () => {
    mocked.__instance.get.mockResolvedValue({ data: { code: 0, data: { osShell: true }, message: 'ok' } });
    mocked.__instance.post.mockResolvedValue({ data: { code: 0, data: { success: true }, message: 'ok' } });

    await exploitClient.capabilities();
    expect(mocked.__instance.get).toHaveBeenCalledWith('/exploit/capabilities', undefined);

    await exploitClient.sqlShell({ sql: 'SELECT 1' } as any);
    expect(mocked.__instance.post).toHaveBeenCalledWith('/exploit/sql', { sql: 'SELECT 1' }, undefined);

    await exploitClient.fileRead({ path: '/etc/passwd' } as any);
    expect(mocked.__instance.post).toHaveBeenCalledWith('/exploit/file-read', { path: '/etc/passwd' }, undefined);

    await exploitClient.fileWrite({ content: 'x', remotePath: '/tmp/x' } as any);
    expect(mocked.__instance.post).toHaveBeenCalledWith(
      '/exploit/file-write',
      { content: 'x', remotePath: '/tmp/x' },
      undefined
    );

    await exploitClient.osShell({ cmd: 'id' } as any);
    expect(mocked.__instance.post).toHaveBeenCalledWith('/exploit/os-shell', { cmd: 'id' }, undefined);
  });

  it('sqlmapClient.status / apiClient.tampers 端点正确', async () => {
    mocked.__instance.get.mockResolvedValue({ data: { code: 0, data: [], message: 'ok' } });
    await sqlmapClient.status();
    expect(mocked.__instance.get).toHaveBeenCalledWith('/sqlmap/status', undefined);
    await apiClient.tampers();
    expect(mocked.__instance.get).toHaveBeenCalledWith('/tampers', undefined);
  });

  it('report.ai / report.aiConfigs 端点与默认空 config', async () => {
    mocked.__instance.post.mockResolvedValue({
      data: { code: 0, data: { success: true, model: 'm', content: 'c' }, message: 'ok' },
    });
    mocked.__instance.get.mockResolvedValue({ data: { code: 0, data: [], message: 'ok' } });

    await apiClient.report.ai('scan-9');
    expect(mocked.__instance.post).toHaveBeenCalledWith('/scan/scan-9/report/ai', {}, undefined);

    await apiClient.report.ai('scan-9', { keyIndex: 1, modelIndex: 2 });
    expect(mocked.__instance.post).toHaveBeenCalledWith(
      '/scan/scan-9/report/ai',
      { keyIndex: 1, modelIndex: 2 },
      undefined
    );

    await apiClient.report.aiConfigs('scan-9');
    expect(mocked.__instance.get).toHaveBeenCalledWith('/scan/scan-9/report/ai/configs', undefined);
  });
});
