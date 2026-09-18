// apiClient.runtime.test.ts —— 运行期 API base / Token 覆盖的行为契约
//
// 存在理由（为什么单独立一个文件）：`apiClient.test.ts` 已覆盖「localStorage 里有 token」
// 这条静态路径，但**运行期注入**这条路径此前 0 覆盖，而它恰恰是桌面版的命门
// （见 src/shared/apiClient.ts 顶部注释 A3 2026-09-17）：
//   · 桌面版 Rust sidecar 端口不固定（4567 被占时随机端口）→ 前端启动时经
//     tauriBridge.getEngineInfo() 调 setApiBase() 告知真实端口；
//   · sidecar 一次性 token 经 setApiToken() 注入，后端设 SCAN_API_TOKEN 后
//     不带此 token 全部 401。
// 即：setApiBase / setApiToken 若行为不对，桌面版是「连不上」或「全 401」，
// 而这两种故障在 Web 版都复现不出来。故对它们断言「请求最终发出的 baseURL 与请求头」，
// 而不是只看内部变量 —— 落点必须是外部可观测的请求形态。
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as axios from 'axios';
import {
  setApiBase,
  getApiBase,
  setApiToken,
  getApiToken,
} from '../shared/apiClient';

// 与 apiClient.test.ts 相同的桩策略：替换 axios.create 返回的实例，
// 并暴露请求拦截器处理器，从而断言「真实发出的 config」
vi.mock('axios', () => {
  const reqHandlers: any[] = [];
  const instance = {
    interceptors: {
      request: { use: (fn: any) => reqHandlers.push(fn) },
      response: { use: () => undefined },
    },
    get: vi.fn(),
    post: vi.fn(),
  };
  return { default: { create: () => instance }, __instance: instance, __reqHandlers: reqHandlers };
});

const mocked = axios as any;

/** 走一遍请求拦截器，返回它最终决定的 baseURL 与请求头 */
function runRequestInterceptor(config: Record<string, any> = { headers: {} }) {
  return mocked.__reqHandlers[0](config);
}

describe('apiClient 运行期 base 覆盖（桌面版 sidecar 随机端口）', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.unstubAllEnvs();
    setApiToken(''); // 清掉上一用例遗留的运行期 token
    setApiBase(''); // 清掉上一用例遗留的运行期 base
  });

  afterEach(() => {
    setApiBase('');
    setApiToken('');
    localStorage.clear();
  });

  it('未调用 setApiBase 时，请求走编译期默认 base（/api）', () => {
    expect(getApiBase()).toBe('/api');
    expect(runRequestInterceptor().baseURL).toBe('/api');
  });

  it('setApiBase 后，拦截器把 baseURL 覆盖为运行期值', () => {
    setApiBase('http://127.0.0.1:54321');
    expect(getApiBase()).toBe('http://127.0.0.1:54321');
    expect(runRequestInterceptor().baseURL).toBe('http://127.0.0.1:54321');
  });
});

describe('apiClient 运行期 token（sidecar 一次性 token）', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.unstubAllEnvs();
    setApiToken('');
    setApiBase('');
  });

  afterEach(() => {
    setApiToken('');
    localStorage.clear();
  });

  it('setApiToken 去除首尾空白后生效，并注入 x-api-token 头', () => {
    setApiToken('  tok-abc  ');
    expect(getApiToken()).toBe('tok-abc');
    expect(runRequestInterceptor().headers['x-api-token']).toBe('tok-abc');
  });

  it('setApiToken 将 token 持久化到 localStorage（刷新后仍可用）', () => {
    setApiToken('persist-me');
    expect(localStorage.getItem('scanApiToken')).toBe('persist-me');
  });

  it('setApiToken("") 清空运行期 token 并移除持久化值；请求不再带 x-api-token', () => {
    setApiToken('to-be-cleared');
    expect(runRequestInterceptor().headers['x-api-token']).toBe('to-be-cleared');

    setApiToken('');
    expect(getApiToken()).toBe('');
    expect(localStorage.getItem('scanApiToken')).toBeNull();
    // 关键断言：不是「带空值头」，而是**压根没有这个头**
    expect(runRequestInterceptor().headers['x-api-token']).toBeUndefined();
  });

  it('空白字符串（非空但无内容）等价于清空，不写入 localStorage', () => {
    setApiToken('   ');
    expect(getApiToken()).toBe('');
    expect(localStorage.getItem('scanApiToken')).toBeNull();
  });

  it('运行期 token 优先于 localStorage 里的旧值', () => {
    localStorage.setItem('scanApiToken', 'stale-from-disk');
    setApiToken('fresh-from-sidecar');
    expect(runRequestInterceptor().headers['x-api-token']).toBe('fresh-from-sidecar');
  });

  it('无运行期 token 时回落到 localStorage 的值（Web 版路径不回退）', () => {
    localStorage.setItem('scanApiToken', 'from-localstorage');
    expect(getApiToken()).toBe('from-localstorage');
    expect(runRequestInterceptor().headers['x-api-token']).toBe('from-localstorage');
  });

  it('localStorage 不可用（隐私模式）时不抛错，内存里仍生效', () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceededError / private mode');
    });
    expect(() => setApiToken('in-memory-only')).not.toThrow();
    expect(getApiToken()).toBe('in-memory-only');
    setItem.mockRestore();
  });
});
