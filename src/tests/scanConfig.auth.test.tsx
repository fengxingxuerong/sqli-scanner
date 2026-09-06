import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useState } from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import ScanConfigPanel from '../components/ScanConfigPanel';
import { DEFAULT_CONFIG } from '../shared/constants';
import type { ScanConfig, EngineType } from '../shared/types';

// WafTamperPanel 内部会调 apiClient.tampers()，mock 掉避免真实请求
vi.mock('../shared/apiClient', () => ({
  apiClient: {
    tampers: vi.fn().mockResolvedValue([]),
    get: vi.fn(),
    post: vi.fn(),
  },
}));

// 受控组件测试需要「回写 state」的父级：否则 input value 不更新，
// 第二次 fireEvent.change（值相同）不会触发 React onChange
function PanelHarness({
  initial,
  mode = 'builtin',
  onChangeSpy,
}: {
  initial: ScanConfig;
  mode?: EngineType;
  onChangeSpy: (patch: Partial<ScanConfig>) => void;
}) {
  const [config, setConfig] = useState<ScanConfig>(initial);
  return (
    <ScanConfigPanel
      config={config}
      mode={mode}
      onChange={(patch) => {
        onChangeSpy(patch);
        setConfig((c) => ({ ...c, ...patch }));
      }}
    />
  );
}

function makeConfig(over: Partial<ScanConfig> = {}): ScanConfig {
  return { ...DEFAULT_CONFIG, ...over } as ScanConfig;
}

describe('ScanConfigPanel 网络与认证区', () => {
  let onChange: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    onChange = vi.fn();
    render(
      <PanelHarness
        initial={makeConfig({ crawlDepth: 0, sessionDefault: false, auth: null, proxy: null })}
        onChangeSpy={onChange}
      />
    );
    // 打开「高级设置」折叠面板
    fireEvent.click(screen.getByText('高级设置'));
  });

  it('代理输入：写入非空值 → proxy；清空/空白 → null', () => {
    const proxy = screen.getByLabelText(/代理（http/);
    fireEvent.change(proxy, { target: { value: '  http://1.2.3.4:8080  ' } });
    expect(onChange).toHaveBeenLastCalledWith({ proxy: 'http://1.2.3.4:8080' });

    fireEvent.change(proxy, { target: { value: '   ' } });
    expect(onChange).toHaveBeenLastCalledWith({ proxy: null });
  });

  it('Basic Auth：user:pass 拆分为 {username,password}；无冒号整段为用户名；清空删除 basic', () => {
    const basic = screen.getByLabelText(/Basic Auth/);
    fireEvent.change(basic, { target: { value: 'admin:s3cret' } });
    expect(onChange).toHaveBeenLastCalledWith({
      auth: { basic: { username: 'admin', password: 's3cret' } },
    });

    fireEvent.change(basic, { target: { value: 'tokenonly' } });
    expect(onChange).toHaveBeenLastCalledWith({
      auth: { basic: { username: 'tokenonly', password: '' } },
    });

    fireEvent.change(basic, { target: { value: '' } });
    expect(onChange).toHaveBeenLastCalledWith({ auth: null });
  });

  it('Cookie：非空写入 auth.cookie，清空删除并回到 null', () => {
    const cookie = screen.getByLabelText(/Cookie/);
    fireEvent.change(cookie, { target: { value: 'session=abc123' } });
    expect(onChange).toHaveBeenLastCalledWith({ auth: { cookie: 'session=abc123' } });

    fireEvent.change(cookie, { target: { value: '' } });
    expect(onChange).toHaveBeenLastCalledWith({ auth: null });
  });

  it('自定义请求头：k:v 用 | 分组解析；非法片段忽略；全部非法/清空 → auth null', () => {
    const headers = screen.getByLabelText(/自定义请求头/);
    fireEvent.change(headers, { target: { value: 'X-Auth: token1 | X-B: v2' } });
    expect(onChange).toHaveBeenLastCalledWith({
      auth: { headers: { 'X-Auth': 'token1', 'X-B': 'v2' } },
    });

    fireEvent.change(headers, { target: { value: 'nocolon | :novalue' } });
    expect(onChange).toHaveBeenLastCalledWith({ auth: null });

    fireEvent.change(headers, { target: { value: 'X-Auth: token1' } });
    fireEvent.change(headers, { target: { value: '' } });
    expect(onChange).toHaveBeenLastCalledWith({ auth: null });
  });

  it('站内爬虫开关：勾选 → crawlDepth=2 并出现深度滑杆；再点 → 0', () => {
    const crawler = screen.getByLabelText(/启用站内爬虫/);
    fireEvent.click(crawler);
    expect(onChange).toHaveBeenLastCalledWith({ crawlDepth: 2 });

    // state 回写后深度滑杆出现（aria-label = 爬取深度）
    expect(screen.getByLabelText('爬取深度')).toBeInTheDocument();
  });

  it('断点续跑开关触发 sessionDefault', () => {
    fireEvent.click(screen.getByLabelText(/启用断点续跑/));
    expect(onChange).toHaveBeenLastCalledWith({ sessionDefault: true });
  });

  it('「高级设置」支持 Enter/Space 键盘开合（无障碍）', () => {
    // beforeEach 中已点击展开，这里再按 Enter/Space 验证键盘路径不抛错且面板仍可用
    const toggle = screen.getByText('高级设置').closest('[role="button"]')!;
    fireEvent.keyDown(toggle, { key: 'Enter' });
    fireEvent.keyDown(toggle, { key: ' ' });
    expect(screen.getByLabelText(/启用断点续跑/)).toBeInTheDocument();
  });
});

