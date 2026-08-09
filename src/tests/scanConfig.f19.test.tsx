import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import ScanConfigPanel from '../components/ScanConfigPanel';
import { DEFAULT_CONFIG, TECHNIQUE_LABEL } from '../shared/constants';
import type { ScanConfig } from '../shared/types';

const BASE_PROPS = {
  config: { ...DEFAULT_CONFIG } as ScanConfig,
  onChange: () => undefined,
};

describe('F-19 ScanConfigPanel 检测技术多选', () => {
  it('默认态 4 项勾选、堆叠未勾选', () => {
    render(<ScanConfigPanel {...BASE_PROPS} />);
    // 默认 4 类（联合/报错/布尔/时间）勾选，堆叠未勾选
    expect(screen.getByRole('checkbox', { name: TECHNIQUE_LABEL.union }).checked).toBe(true);
    expect(screen.getByRole('checkbox', { name: TECHNIQUE_LABEL.error }).checked).toBe(true);
    expect(screen.getByRole('checkbox', { name: TECHNIQUE_LABEL.boolean }).checked).toBe(true);
    expect(screen.getByRole('checkbox', { name: TECHNIQUE_LABEL.time }).checked).toBe(true);
    expect(screen.getByRole('checkbox', { name: TECHNIQUE_LABEL.stacked }).checked).toBe(false);
  });

  it('勾选堆叠 → onChange 写入 techniques 含 stacked', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel {...BASE_PROPS} onChange={onChange} />);
    const stacked = screen.getByRole('checkbox', { name: TECHNIQUE_LABEL.stacked });
    fireEvent.click(stacked);
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ techniques: ['union', 'error', 'boolean', 'time', 'stacked'] })
    );
  });

  it('取消勾选某经典技术 → techniques 不含该项', () => {
    const onChange = vi.fn();
    render(<ScanConfigPanel {...BASE_PROPS} onChange={onChange} />);
    const union = screen.getByRole('checkbox', { name: TECHNIQUE_LABEL.union });
    fireEvent.click(union);
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ techniques: ['error', 'boolean', 'time'] })
    );
  });

  it('全不选 → techniques 传空数组 []', () => {
    const onChange = vi.fn();
    const allUnchecked = { ...DEFAULT_CONFIG, techniques: [] as ScanConfig['techniques'] } as ScanConfig;
    render(<ScanConfigPanel {...BASE_PROPS} config={allUnchecked} onChange={onChange} />);
    const union = screen.getByRole('checkbox', { name: TECHNIQUE_LABEL.union });
    fireEvent.click(union); // 空数组点 union → 仅含 union
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ techniques: ['union'] })
    );
  });

  it('config.techniques 缺失时回落 DEFAULT_CONFIG（堆叠未勾选）', () => {
    const noTech = { ...DEFAULT_CONFIG } as ScanConfig;
    delete (noTech as Partial<ScanConfig>).techniques;
    render(<ScanConfigPanel {...BASE_PROPS} config={noTech} />);
    expect(screen.getByRole('checkbox', { name: TECHNIQUE_LABEL.stacked }).checked).toBe(false);
    expect(screen.getByRole('checkbox', { name: TECHNIQUE_LABEL.union }).checked).toBe(true);
  });
});
