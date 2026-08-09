import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import ScanConfigPanel from '../components/ScanConfigPanel';
import { DEFAULT_CONFIG } from '../shared/constants';
import type { ScanConfig } from '../shared/types';

const BASE_PROPS = {
  config: { ...DEFAULT_CONFIG } as ScanConfig,
  onChange: () => undefined,
};

describe('高级检测选项（对标 sqlmap）UI 接入', () => {
  it('builtin 模式渲染全部新开关', () => {
    render(<ScanConfigPanel {...BASE_PROPS} mode="builtin" />);
    expect(screen.getByText('高级检测选项（对标 sqlmap）')).toBeTruthy();
    // MUI outlined TextField 的 label 同时出现在 <label> 与 notched <legend>，
    // 故用 getByLabelText（精确关联 input）而非 getByText（会命中多个）。
    expect(screen.getByLabelText('检测等级 level')).toBeTruthy();
    expect(screen.getByLabelText('风险等级 risk')).toBeTruthy();
    expect(screen.getByLabelText('时间盲注 SLEEP (s)')).toBeTruthy();
    expect(screen.getByLabelText('固定延时 (ms)')).toBeTruthy();
    expect(screen.getByLabelText('真响应含此串')).toBeTruthy();
    expect(screen.getByLabelText('安全 URL（可逗号分隔多 URL 随机轮询）')).toBeTruthy();
    expect(screen.getByLabelText(/HTTP 参数污染/)).toBeTruthy();
    expect(screen.getByLabelText(/连接复用/)).toBeTruthy();
  });

  it('sqlmap 模式不渲染 builtin 高级检测选项', () => {
    render(<ScanConfigPanel {...BASE_PROPS} mode="sqlmap" />);
    expect(screen.queryByText('高级检测选项（对标 sqlmap）')).toBeNull();
  });

  it('hpp 开关 → onChange 写入 hpp:true', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel {...BASE_PROPS} mode="builtin" onChange={onChange} />);
    const sw = screen.getByLabelText(/HTTP 参数污染/) as HTMLInputElement;
    fireEvent.click(sw);
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ hpp: true }));
  });

  it('keepAlive 默认开，关闭 → onChange 写入 keepAlive:false', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel {...BASE_PROPS} mode="builtin" onChange={onChange} />);
    const sw = screen.getByLabelText(/连接复用/) as HTMLInputElement;
    expect(sw.checked).toBe(true);
    fireEvent.click(sw);
    expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ keepAlive: false }));
  });

  it('detectMatch string 输入 → onChange 写入 detectMatch.string', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel {...BASE_PROPS} mode="builtin" onChange={onChange} />);
    const input = screen.getByLabelText('真响应含此串') as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'welcome' } });
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ detectMatch: expect.objectContaining({ string: 'welcome' }) })
    );
  });

  it('safeProbe url 输入 → onChange 写入 safeProbe.url（逗号分隔多 URL）', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel {...BASE_PROPS} mode="builtin" onChange={onChange} />);
    const input = screen.getByLabelText(/安全 URL/) as HTMLInputElement;
    fireEvent.change(input, { target: { value: 'http://h/,http://h2/' } });
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ safeProbe: expect.objectContaining({ url: 'http://h/,http://h2/' }) })
    );
  });

  it('level 下拉存在（builtin 模式渲染）', () => {
    render(<ScanConfigPanel {...BASE_PROPS} mode="builtin" />);
    expect(screen.getByLabelText('检测等级 level')).toBeTruthy();
  });
});
