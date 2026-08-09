import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import ScanConfigPanel from '../components/ScanConfigPanel';
import { DEFAULT_CONFIG, SCAN_PRESETS, SCAN_DEFAULTS } from '../shared/constants';
import type { ScanConfig } from '../shared/types';

// 桩掉真实网络：WafTamperPanel 会拉取 tamper 清单，测试环境不发真实 XHR（避免 jsdom virtualConsole 噪声导致进程退出码非零）
vi.mock('../shared/apiClient', () => ({
  apiClient: { tampers: vi.fn().mockResolvedValue([]) },
}));

const baseConfig = { ...DEFAULT_CONFIG } as ScanConfig;

describe('ScanConfigPanel 并发滑杆', () => {
  it('builtin 模式下渲染「并发数」滑块并反映当前值', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    const slider = screen.getByRole('slider', { name: '并发数' }) as HTMLInputElement;
    expect(slider).toBeTruthy();
    expect(Number(slider.value)).toBe(baseConfig.concurrency);
  });

  it('拖动并发滑块触发 onChange({ concurrency })', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    const slider = screen.getByRole('slider', { name: '并发数' }) as HTMLInputElement;
    fireEvent.change(slider, { target: { value: 12 } });
    expect(onChange).toHaveBeenCalledWith({ concurrency: 12 });
  });

  it('sqlmap 模式不渲染自带引擎的并发滑块', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="sqlmap" onChange={onChange} />);
    expect(screen.queryByRole('slider', { name: '并发数' })).toBeNull();
  });
});

describe('ScanConfigPanel 预设档位', () => {
  it('builtin 模式渲染预设档位按钮（快速/标准/激进）', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    expect(screen.getByRole('button', { name: '快速' })).toBeTruthy();
    expect(screen.getByRole('button', { name: '标准' })).toBeTruthy();
    expect(screen.getByRole('button', { name: '激进' })).toBeTruthy();
  });

  it('点击「激进」预设触发 onChange(SCAN_PRESETS.aggressive)', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    fireEvent.click(screen.getByRole('button', { name: '激进' }));
    expect(onChange).toHaveBeenCalledWith(SCAN_PRESETS.aggressive);
  });

  it('点击「标准」预设触发 onChange(SCAN_PRESETS.standard)', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    fireEvent.click(screen.getByRole('button', { name: '标准' }));
    expect(onChange).toHaveBeenCalledWith(SCAN_PRESETS.standard);
  });

  it('sqlmap 模式不渲染预设档位按钮', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="sqlmap" onChange={onChange} />);
    expect(screen.queryByRole('button', { name: '激进' })).toBeNull();
  });

  it('builtin 模式渲染「恢复默认」按钮', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    expect(screen.getByRole('button', { name: '恢复默认' })).toBeTruthy();
  });

  it('点击「恢复默认」触发 onChange(SCAN_DEFAULTS)', () => {
    const onChange = vi.fn();
    render(
      <ScanConfigPanel
        config={{ ...baseConfig, concurrency: 12, level: 5 }}
        mode="builtin"
        onChange={onChange}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: '恢复默认' }));
    expect(onChange).toHaveBeenCalledWith(SCAN_DEFAULTS);
  });

  it('sqlmap 模式不渲染「恢复默认」按钮', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="sqlmap" onChange={onChange} />);
    expect(screen.queryByRole('button', { name: '恢复默认' })).toBeNull();
  });

  it('config 性能字段匹配 standard 时「标准」档位高亮(aria-pressed=true)', () => {
    const onChange = vi.fn();
    // standard 与 defaults 仅 level 不同（2 vs 1），其余 6 个性能字段一致
    render(<ScanConfigPanel config={{ ...baseConfig, level: 2 }} mode="builtin" onChange={onChange} />);
    expect(screen.getByRole('button', { name: '标准' }).getAttribute('aria-pressed')).toBe('true');
  });

  it('config 偏离所有预设时三档均不高亮(aria-pressed 非 true)', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    expect(screen.getByRole('button', { name: '快速' }).getAttribute('aria-pressed')).not.toBe('true');
    expect(screen.getByRole('button', { name: '标准' }).getAttribute('aria-pressed')).not.toBe('true');
    expect(screen.getByRole('button', { name: '激进' }).getAttribute('aria-pressed')).not.toBe('true');
  });
});

describe('ScanConfigPanel 预设联动高亮（手动改滑杆/选择后消高亮）', () => {
  const standardConfig = { ...baseConfig, ...SCAN_PRESETS.standard } as ScanConfig;
  const aggressiveConfig = { ...baseConfig, ...SCAN_PRESETS.aggressive } as ScanConfig;

  it('套用「标准」后「标准」高亮；手动拖并发滑杆偏离后高亮消失（双向联动）', () => {
    const onChange = vi.fn();
    const { rerender } = render(
      <ScanConfigPanel config={standardConfig} mode="builtin" onChange={onChange} />,
    );
    // 套用预设后处于高亮态
    expect(screen.getByRole('button', { name: '标准' }).getAttribute('aria-pressed')).toBe('true');
    // 用户拖动并发滑杆（标准预设 concurrency=4，拖到 5 即偏离）
    const slider = screen.getByRole('slider', { name: '并发数' }) as HTMLInputElement;
    fireEvent.change(slider, { target: { value: 5 } });
    expect(onChange).toHaveBeenCalledWith({ concurrency: 5 });
    // 父级合并后 config 偏离预设 → 受控重渲 → 三档高亮应全部消失
    rerender(
      <ScanConfigPanel config={{ ...standardConfig, concurrency: 5 }} mode="builtin" onChange={onChange} />,
    );
    expect(screen.getByRole('button', { name: '标准' }).getAttribute('aria-pressed')).not.toBe('true');
    expect(screen.getByRole('button', { name: '快速' }).getAttribute('aria-pressed')).not.toBe('true');
    expect(screen.getByRole('button', { name: '激进' }).getAttribute('aria-pressed')).not.toBe('true');
  });

  it('套用「激进」后「激进」高亮；手动改 risk 选择偏离后高亮消失', () => {
    const onChange = vi.fn();
    const { rerender } = render(
      <ScanConfigPanel config={aggressiveConfig} mode="builtin" onChange={onChange} />,
    );
    expect(screen.getByRole('button', { name: '激进' }).getAttribute('aria-pressed')).toBe('true');
    // risk 属 7 个性能比对字段之一，手动改为 1 即偏离激进预设
    rerender(
      <ScanConfigPanel config={{ ...aggressiveConfig, risk: 1 }} mode="builtin" onChange={onChange} />,
    );
    expect(screen.getByRole('button', { name: '激进' }).getAttribute('aria-pressed')).not.toBe('true');
  });

  it('点击预设按钮套用的是仅含性能字段的 Partial（父级合并不会清空 techniques/auth/wafEvasion）', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    fireEvent.click(screen.getByRole('button', { name: '标准' }));
    const patch = onChange.mock.calls[onChange.mock.calls.length - 1][0] as Record<string, unknown>;
    const keys = Object.keys(patch).sort();
    // 仅 7 个性能字段，绝不触碰检测技术 / 认证 / WAF 规避 / 二阶 / OOB
    expect(keys).toEqual(
      ['concurrency', 'level', 'ratePerSec', 'retry', 'risk', 'timeoutMs', 'timeThresholdMs'].sort(),
    );
    expect(keys).not.toContain('techniques');
    expect(keys).not.toContain('auth');
    expect(keys).not.toContain('wafEvasion');
  });
});

describe('ScanConfigPanel 数字项滑杆', () => {
  it('渲染主配置区各数字项滑块并反映当前值', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    expect(screen.getByRole('slider', { name: '超时 (ms)' })).toBeTruthy();
    expect(screen.getByRole('slider', { name: '重试次数' })).toBeTruthy();
    expect(screen.getByRole('slider', { name: '时间盲注阈值 (ms)' })).toBeTruthy();
    expect(screen.getByRole('slider', { name: '限速 (req/s)' })).toBeTruthy();
  });

  it('拖动超时滑块触发 onChange({ timeoutMs })', () => {
    const onChange = vi.fn();
    const cfg = { ...baseConfig, timeoutMs: 2000 };
    render(<ScanConfigPanel config={cfg} mode="builtin" onChange={onChange} />);
    const slider = screen.getByRole('slider', { name: '超时 (ms)' }) as HTMLInputElement;
    fireEvent.change(slider, { target: { value: 30000 } });
    expect(onChange).toHaveBeenCalledWith({ timeoutMs: 30000 });
  });

  it('拖动重试滑块触发 onChange({ retry })', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    const slider = screen.getByRole('slider', { name: '重试次数' }) as HTMLInputElement;
    fireEvent.change(slider, { target: { value: 3 } });
    expect(onChange).toHaveBeenCalledWith({ retry: 3 });
  });

  it('拖动限速滑块触发 onChange({ ratePerSec })', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    const slider = screen.getByRole('slider', { name: '限速 (req/s)' }) as HTMLInputElement;
    fireEvent.change(slider, { target: { value: 20 } });
    expect(onChange).toHaveBeenCalledWith({ ratePerSec: 20 });
  });

  it('渲染高级检测项滑块（SLEEP / 固定延时）', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    expect(screen.getByRole('slider', { name: '时间盲注 SLEEP (s)' })).toBeTruthy();
    expect(screen.getByRole('slider', { name: '固定延时 (ms)' })).toBeTruthy();
  });

  it('拖动固定延时滑块触发 onChange({ requestDelayMs })', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    const slider = screen.getByRole('slider', { name: '固定延时 (ms)' }) as HTMLInputElement;
    fireEvent.change(slider, { target: { value: 500 } });
    expect(onChange).toHaveBeenCalledWith({ requestDelayMs: 500 });
  });

  it('拖动 WAF 抖动滑块触发 updateWaf({ jitterMs })', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel config={baseConfig} mode="builtin" onChange={onChange} />);
    const slider = screen.getByRole('slider', { name: '请求间随机延时 (ms)' }) as HTMLInputElement;
    fireEvent.change(slider, { target: { value: 500 } });
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ wafEvasion: expect.objectContaining({ jitterMs: 500 }) }),
    );
  });
});
