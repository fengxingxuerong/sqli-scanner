import { useState } from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { describe, test, expect, vi } from 'vitest';
import ScanConfigPanel from '../components/ScanConfigPanel';
import { DEFAULT_CONFIG } from '../shared/constants';

function Wrapper({ initial }: { initial?: Record<string, unknown> }) {
  const [cfg, setCfg] = useState({ ...DEFAULT_CONFIG, ...initial } as any);
  return (
    <ScanConfigPanel
      config={cfg}
      mode="builtin"
      onChange={(p: any) => setCfg({ ...cfg, ...p })}
    />
  );
}

describe('ScanConfigPanel OOB 带外开关', () => {
  test('渲染授权警示 + 启用开关（默认未启用）', () => {
    render(<Wrapper />);
    expect(screen.getByText(/OOB 带外注入/)).toBeTruthy();
    const sw = screen.getByLabelText(/启用 OOB 带外接收端/) as HTMLInputElement;
    expect(sw.checked).toBe(false);
  });

  test('默认文本框 disabled', () => {
    render(<Wrapper />);
    const cb = screen.getByLabelText(/接收端地址 callbackBase/) as HTMLInputElement;
    expect(cb.disabled).toBe(true);
  });

  test('启用后文本框可编辑', () => {
    render(<Wrapper />);
    const sw = screen.getByLabelText(/启用 OOB 带外接收端/) as HTMLInputElement;
    fireEvent.click(sw);
    const cb = screen.getByLabelText(/接收端地址 callbackBase/) as HTMLInputElement;
    expect(cb.disabled).toBe(false);
  });

  test('sqlmap 模式不显示 OOB 区块', () => {
    render(<ScanConfigPanel config={{ ...DEFAULT_CONFIG } as any} mode="sqlmap" onChange={() => {}} />);
    expect(screen.queryByText(/OOB 带外注入/)).toBeNull();
  });

  test('勾选 oob 技术但未启用接收端 → 显示 info 前置提示', () => {
    render(
      <ScanConfigPanel
        config={{
          ...DEFAULT_CONFIG,
          techniques: ['union', 'oob'],
          oob: { enabled: false, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 5000 },
        } as any}
        mode="builtin"
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByText(/已勾选「带外注入\(OOB\)」技术，但接收端未启用/)).toBeTruthy();
  });

  test('启用接收端但 risk<3 → 显示 warning 风险门控提示', () => {
    render(
      <ScanConfigPanel
        config={{
          ...DEFAULT_CONFIG,
          techniques: ['union', 'oob'],
          risk: 1,
          oob: { enabled: true, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 5000 },
        } as any}
        mode="builtin"
        onChange={vi.fn()}
      />,
    );
    expect(screen.getByText(/OOB 带外需风险等级 risk≥3/)).toBeTruthy();
  });

  test('勾选 oob + 启用接收端 + risk≥3 → 不显示任何前置提示', () => {
    render(
      <ScanConfigPanel
        config={{
          ...DEFAULT_CONFIG,
          techniques: ['union', 'oob'],
          risk: 3,
          oob: { enabled: true, callbackBase: '127.0.0.1:8899', httpPort: 8899, timeoutMs: 5000 },
        } as any}
        mode="builtin"
        onChange={vi.fn()}
      />,
    );
    expect(screen.queryByText(/已勾选「带外注入\(OOB\)」技术，但接收端未启用/)).toBeNull();
    expect(screen.queryByText(/OOB 带外需风险等级 risk≥3/)).toBeNull();
  });
});
