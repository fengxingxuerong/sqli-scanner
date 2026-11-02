// [P1-SAFE/P0-SEC 2026-11-02] 授权与安全护栏分组新增两个开关：
//   confirmFormWrites（默认 false：表单 POST 不投放）
//   pocRedactAuth（默认 true：PoC 凭据脱敏）
// 断言 UI 真能把两个键发进 patch（而不是只有文案没有接线）。
import { describe, it, expect, vi } from 'vitest';
import { useState } from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import ScanConfigPanel from '../components/ScanConfigPanel';
import { DEFAULT_CONFIG } from '../shared/constants';
import type { ScanConfig } from '../shared/types';

vi.mock('../shared/apiClient', () => ({
  apiClient: {
    tampers: vi.fn().mockResolvedValue([]),
    get: vi.fn(),
    post: vi.fn(),
  },
}));

function Harness({ initial, onPatch }: { initial: ScanConfig; onPatch: (p: Partial<ScanConfig>) => void }) {
  const [config, setConfig] = useState(initial);
  return (
    <ScanConfigPanel
      config={config}
      mode="builtin"
      onChange={(patch) => {
        onPatch(patch);
        setConfig((c) => ({ ...c, ...patch }));
      }}
    />
  );
}

describe('ScanConfigPanel 授权与安全护栏新增开关', () => {
  it('confirmFormWrites 默认关闭；打开 → patch.confirmFormWrites=true 且出现写数据告警', () => {
    const onPatch = vi.fn();
    render(<Harness initial={{ ...DEFAULT_CONFIG }} onPatch={onPatch} />);
    const label = screen.getByText('允许自动发现的表单 POST（会写数据）');
    expect(label).toBeTruthy();
    const control = label.closest('label')?.querySelector('input[type="checkbox"]');
    expect(control).toBeTruthy();
    fireEvent.click(control!);
    expect(onPatch).toHaveBeenCalledWith({ confirmFormWrites: true });
    expect(screen.getByText(/表单写请求已放行/)).toBeTruthy();
  });

  it('pocRedactAuth 默认开启；关闭 → patch.pocRedactAuth=false 且出现明文告警', () => {
    const onPatch = vi.fn();
    render(<Harness initial={{ ...DEFAULT_CONFIG }} onPatch={onPatch} />);
    const label = screen.getByText('报告中脱敏 PoC 凭据');
    const control = label.closest('label')?.querySelector('input[type="checkbox"]');
    expect(control).toBeTruthy();
    fireEvent.click(control!);
    expect(onPatch).toHaveBeenCalledWith({ pocRedactAuth: false });
    expect(screen.getByText(/PoC 凭据脱敏已关闭/)).toBeTruthy();
  });
});
