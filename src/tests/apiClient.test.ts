import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as axios from 'axios';
import { apiClient } from '../shared/apiClient';

// 用桩替换 axios：create 返回固定实例，并暴露实例与响应拦截处理器供断言
vi.mock('axios', () => {
  const handlers: any[] = [];
  const instance = {
    interceptors: { response: { use: (fn: any) => handlers.push(fn) } },
    get: vi.fn(),
    post: vi.fn(),
  };
  return { default: { create: () => instance }, __instance: instance, __handlers: handlers };
});

const mocked = axios as any;

describe('apiClient 响应解包与拦截', () => {
  beforeEach(() => {
    mocked.__instance.get = vi.fn();
    mocked.__instance.post = vi.fn();
  });

  it('成功响应(code===0)解包到 data', async () => {
    mocked.__instance.get.mockResolvedValue({ data: { code: 0, data: { id: '1' }, message: 'ok' } });
    const r = await apiClient.get('/scan/1');
    expect(mocked.__instance.get).toHaveBeenCalledWith('/scan/1', undefined);
    expect(r).toEqual({ id: '1' });
  });

  it('post 成功解包 data', async () => {
    mocked.__instance.post.mockResolvedValue({ data: { code: 0, data: 'ok', message: 'ok' } });
    const r = await apiClient.post('/scan/start', { url: 'x' });
    expect(mocked.__instance.post).toHaveBeenCalledWith('/scan/start', { url: 'x' }, undefined);
    expect(r).toBe('ok');
  });

  it('拦截器对 code!==0 抛错（统一错误体系）', async () => {
    const fake = { data: { code: 2001, data: null, message: '未找到' } };
    await expect(mocked.__handlers[0](fake)).rejects.toThrow('未找到');
  });

  it('拦截器对 code===0 透传响应', async () => {
    const fake = { data: { code: 0, data: 'D', message: 'ok' } };
    const res = await mocked.__handlers[0](fake);
    expect(res).toBe(fake);
  });
});
