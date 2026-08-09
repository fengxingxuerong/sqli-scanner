import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import SqlmapOptions from '../components/SqlmapOptions';
import type { SqlmapConfig } from '../shared/types';

const baseConfig: SqlmapConfig = {
  threads: 1,
  techniques: [],
  tamper: [],
  dump: false,
  osShell: false,
  fileRead: undefined,
  level: 1,
  risk: 1,
  dbms: '',
};

describe('SqlmapOptions 线程滑杆', () => {
  it('渲染「线程数 threads」滑块并反映当前值', () => {
    const onChange = vi.fn();
    render(<SqlmapOptions config={baseConfig} onChange={onChange} />);
    const slider = screen.getByRole('slider', { name: '线程数 threads' }) as HTMLInputElement;
    expect(slider).toBeTruthy();
    expect(Number(slider.value)).toBe(1);
  });

  it('拖动线程滑块触发 onChange({ threads })', () => {
    const onChange = vi.fn();
    render(<SqlmapOptions config={baseConfig} onChange={onChange} />);
    const slider = screen.getByRole('slider', { name: '线程数 threads' }) as HTMLInputElement;
    fireEvent.change(slider, { target: { value: 5 } });
    expect(onChange).toHaveBeenCalledWith({ threads: 5 });
  });
});
